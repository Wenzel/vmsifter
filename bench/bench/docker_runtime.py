"""Docker-backed runtime for vmsifter-bench backends."""

from __future__ import annotations

import json
import logging
import queue
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import docker
from docker.errors import BuildError
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from bench.progress import decode_progress_line

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTAINERS_DIR = PROJECT_ROOT / "containers"
IMAGE_PREFIX = "vmsifter-bench"
PROGRESS_MOUNT_DIR = Path("/progress")
PROGRESS_SOCKET_NAME = "progress.sock"


class BackendNotFoundError(ValueError):
    """Raised when a backend does not have a container definition."""


def _input_size_bytes(input_path: Path) -> int:
    """Return the input file size in bytes for the host-side progress bar."""
    return input_path.stat().st_size


def _should_render_progress() -> bool:
    """Return True when the host can render an interactive Rich progress bar."""
    return sys.stderr.isatty()


def _format_byte_count(value: int) -> str:
    """Render a byte count with compact decimal suffixes."""
    if value < 1000:
        return f"{value}B"

    suffixes = ("KB", "MB", "GB", "TB", "PB", "EB")
    scaled = float(value)
    for suffix in suffixes:
        scaled /= 1000.0
        if scaled < 1000.0:
            return f"{scaled:.1f}{suffix}"

    return f"{scaled:.1f}{suffix}"


class CompactByteCountColumn(ProgressColumn):
    """Render current / total byte counts with compact decimal suffixes."""

    def render(self, task) -> str:
        total = task.total
        if isinstance(total, (int, float)) and not isinstance(total, bool):
            return f"{_format_byte_count(int(task.completed))}/{_format_byte_count(int(total))}"
        return _format_byte_count(int(task.completed))


class DockerProgressChannel:
    """Host-side Unix socket listener for container progress updates."""

    def __init__(self, input_path: Path, subcommand: str) -> None:
        self.input_path = input_path
        self.subcommand = subcommand
        self.total_bytes = _input_size_bytes(input_path)
        self.mount_dir: Path | None = None
        self.container_socket_path = PROGRESS_MOUNT_DIR / PROGRESS_SOCKET_NAME
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._server: socket.socket | None = None
        self._updates: queue.Queue[dict[str, object]] = queue.Queue()
        self._stop_event = threading.Event()
        self._reader_thread: threading.Thread | None = None

    def __enter__(self) -> "DockerProgressChannel":
        self._tmpdir = tempfile.TemporaryDirectory(prefix="vmsifter-progress-")
        self.mount_dir = Path(self._tmpdir.name)
        socket_path = self.mount_dir / PROGRESS_SOCKET_NAME
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)
        server.settimeout(0.1)
        self._server = server
        self._reader_thread = threading.Thread(target=self._serve, daemon=True)
        self._reader_thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop_event.set()
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=1)
            self._reader_thread = None
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
        self.mount_dir = None

    def _serve(self) -> None:
        if self._server is None:
            return

        while not self._stop_event.is_set():
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop_event.is_set():
                    return
                logger.debug("Progress socket accept failed", exc_info=True)
                return

            with conn:
                with conn.makefile("r", encoding="utf-8") as stream:
                    for line in stream:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            self._updates.put(decode_progress_line(line))
                        except (json.JSONDecodeError, TypeError, ValueError):
                            logger.debug("Ignoring malformed progress payload %r", line, exc_info=True)
                return

    def track_container(self, container, backend_name: str) -> int:
        """Stream logs, render host-side Rich progress, and return the exit code."""
        wait_result: dict[str, int] = {}
        wait_errors: list[BaseException] = []
        log_errors: list[BaseException] = []

        def wait_for_container() -> None:
            try:
                wait_result.update(container.wait())
            except BaseException as exc:  # pragma: no cover - defensive
                wait_errors.append(exc)

        def stream_logs() -> None:
            try:
                for chunk in container.logs(stream=True, follow=True):
                    line = chunk.decode(errors="replace").rstrip()
                    if line:
                        logger.info("[%s] %s", backend_name, line)
            except BaseException as exc:  # pragma: no cover - defensive
                log_errors.append(exc)

        wait_thread = threading.Thread(target=wait_for_container, daemon=True)
        log_thread = threading.Thread(target=stream_logs, daemon=True)
        wait_thread.start()
        log_thread.start()

        if _should_render_progress():
            self._render_progress(wait_thread, backend_name)

        wait_thread.join()
        log_thread.join()

        if log_errors:
            raise log_errors[0]
        if wait_errors:
            raise wait_errors[0]
        return wait_result["StatusCode"]

    def _render_progress(self, wait_thread: threading.Thread, backend_name: str) -> None:
        completed = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            CompactByteCountColumn(),
            TimeElapsedColumn(),
            TextColumn("eta"),
            TimeRemainingColumn(compact=True, elapsed_when_finished=True),
            transient=True,
        ) as progress:
            task_id = progress.add_task(
                f"{backend_name} {self.subcommand}",
                total=self.total_bytes,
            )
            while wait_thread.is_alive():
                completed = self._drain_updates(progress, task_id, completed)
                time.sleep(0.05)
            self._drain_updates(progress, task_id, completed)

    def _drain_updates(self, progress: Progress, task_id: TaskID, completed: int) -> int:
        latest = completed
        while True:
            try:
                payload = self._updates.get_nowait()
            except queue.Empty:
                return latest

            current = payload.get("current")
            if isinstance(current, bool) or not isinstance(current, int):
                continue
            latest = current
            progress.update(task_id, completed=latest)


def list_backends(containers_dir: Path = CONTAINERS_DIR) -> list[str]:
    """Return sorted backend names discovered from containers/<backend>/Dockerfile."""
    if not containers_dir.exists():
        return []
    return sorted(
        entry.name
        for entry in containers_dir.iterdir()
        if entry.is_dir() and (entry / "Dockerfile").is_file()
    )


def dockerfile_for_backend(backend_name: str, containers_dir: Path = CONTAINERS_DIR) -> Path:
    """Return the Dockerfile path for a backend, or raise if it is unknown."""
    dockerfile = containers_dir / backend_name / "Dockerfile"
    if not dockerfile.is_file():
        available = ", ".join(list_backends(containers_dir)) or "(none)"
        raise BackendNotFoundError(f"Unknown backend {backend_name!r}. Available: {available}")
    return dockerfile


def image_name_for_backend(backend_name: str) -> str:
    """Return the image tag used for the backend."""
    return f"{IMAGE_PREFIX}/{backend_name}:dev"


def build_backend_image(
    backend_name: str,
    *,
    client=None,
    project_root: Path = PROJECT_ROOT,
    containers_dir: Path = CONTAINERS_DIR,
) -> str:
    """Always invoke docker build and rely on Docker layer caching."""
    dockerfile = dockerfile_for_backend(backend_name, containers_dir)
    image = image_name_for_backend(backend_name)
    client = client or docker.from_env()
    logger.info("Building backend image %s from %s", image, dockerfile)
    build_kwargs = {
        "path": str(project_root),
        "dockerfile": str(dockerfile.relative_to(project_root)),
        "tag": image,
        "rm": True,
    }
    if logger.isEnabledFor(logging.DEBUG):
        _stream_build_logs(client, backend_name, build_kwargs)
    else:
        client.images.build(**build_kwargs)
    return image


def _stream_build_logs(client, backend_name: str, build_kwargs: dict[str, object]) -> None:
    """Stream docker build output in debug mode."""
    for event in client.api.build(decode=True, **build_kwargs):
        if "error" in event:
            raise BuildError(event["error"], build_log=[event])

        stream = event.get("stream")
        if stream:
            for line in str(stream).splitlines():
                if line:
                    logger.debug("[build:%s] %s", backend_name, line)
            continue

        status = event.get("status")
        if status:
            detail = status
            progress = event.get("progress")
            identifier = event.get("id")
            if identifier:
                detail = f"{identifier}: {detail}"
            if progress:
                detail = f"{detail} {progress}"
            logger.debug("[build:%s] %s", backend_name, detail)


def run_backend_container(
    backend_name: str,
    input_path: Path,
    exec_mode: int,
    output_path: Path,
    *,
    client=None,
    progress_channel_factory=DockerProgressChannel,
) -> None:
    """Run a built backend container to completion."""
    _run_backend_container(
        backend_name,
        exec_mode=exec_mode,
        subcommand="run",
        input_path=input_path,
        output_path=output_path,
        client=client,
        progress_channel_factory=progress_channel_factory,
    )


def validate_backend_container(
    backend_name: str,
    input_path: Path,
    exec_mode: int,
    output_path: Path | None = None,
    *,
    client=None,
    progress_channel_factory=DockerProgressChannel,
) -> None:
    """Run backend validation inside a container."""
    _run_backend_container(
        backend_name,
        exec_mode=exec_mode,
        subcommand="validate",
        input_path=input_path,
        output_path=output_path,
        client=client,
        progress_channel_factory=progress_channel_factory,
    )


def _run_backend_container(
    backend_name: str,
    exec_mode: int,
    subcommand: str,
    input_path: Path,
    output_path: Path | None,
    *,
    client=None,
    progress_channel_factory=DockerProgressChannel,
) -> None:
    """Run a built backend container to completion."""
    client = client or docker.from_env()
    image = image_name_for_backend(backend_name)
    input_path = input_path.resolve()
    if output_path is not None:
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path is not None and input_path.parent == output_path.parent:
        mount_host = input_path.parent
        volumes = {
            str(mount_host): {"bind": "/work", "mode": "rw"},
        }
        input_arg = Path("/work") / input_path.name
        output_arg = Path("/work") / output_path.name
    elif output_path is None:
        volumes = {
            str(input_path.parent): {"bind": "/input", "mode": "ro"},
        }
        input_arg = Path("/input") / input_path.name
        output_arg = None
    else:
        volumes = {
            str(input_path.parent): {"bind": "/input", "mode": "ro"},
            str(output_path.parent): {"bind": "/output", "mode": "rw"},
        }
        input_arg = Path("/input") / input_path.name
        output_arg = Path("/output") / output_path.name

    with progress_channel_factory(input_path, subcommand) as progress_channel:
        if progress_channel.mount_dir is None:
            raise RuntimeError("Progress channel did not expose a mount directory")
        volumes[str(progress_channel.mount_dir)] = {"bind": str(PROGRESS_MOUNT_DIR), "mode": "rw"}

        logger.info("Running backend container %s", image)
        command = [
            subcommand,
            "--input",
            str(input_arg),
            "--backend",
            backend_name,
            "--exec-mode",
            str(exec_mode),
        ]
        if output_arg is not None:
            command.extend([
                "--output",
                str(output_arg),
            ])
        command.extend([
            "--progress-socket",
            str(progress_channel.container_socket_path),
        ])
        container = client.containers.run(
            image=image,
            command=command,
            volumes=volumes,
            detach=True,
            remove=False,
        )

        try:
            status_code = progress_channel.track_container(container, backend_name)
            if status_code != 0:
                raise RuntimeError(f"Backend {backend_name!r} exited with code {status_code}")
        finally:
            container.remove(force=True)


def run_backend_in_docker(
    input_path: Path,
    backend_name: str,
    exec_mode: int,
    output_path: Path,
) -> None:
    """Build and run a backend container."""
    client = docker.from_env()
    build_backend_image(backend_name, client=client)
    run_backend_container(backend_name, input_path, exec_mode, output_path, client=client)


def validate_backend_in_docker(
    input_path: Path,
    backend_name: str,
    exec_mode: int,
    output_path: Path | None = None,
) -> None:
    """Build and run backend validation inside a container."""
    client = docker.from_env()
    build_backend_image(backend_name, client=client)
    validate_backend_container(backend_name, input_path, exec_mode, output_path=output_path, client=client)
