"""Docker-backed runtime for vmsifter-bench backends."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import logging
import queue
import socket
import sys
import tempfile
import threading
import time
from contextlib import nullcontext
from pathlib import Path

import docker
from docker.errors import BuildError, NotFound
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

    def track_container(
        self,
        container,
        backend_name: str,
        *,
        progress: Progress | None = None,
        task_id: TaskID | None = None,
        progress_lock: threading.Lock | None = None,
        log_label: str | None = None,
    ) -> int:
        """Stream logs, render host-side Rich progress, and return the exit code."""
        wait_result: dict[str, int] = {}
        wait_errors: list[BaseException] = []
        log_errors: list[BaseException] = []
        label = backend_name if log_label is None else log_label

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
                        logger.info("[%s] %s", label, line)
            except BaseException as exc:  # pragma: no cover - defensive
                log_errors.append(exc)

        wait_thread = threading.Thread(target=wait_for_container, daemon=True)
        log_thread = threading.Thread(target=stream_logs, daemon=True)
        wait_thread.start()
        log_thread.start()

        if progress is not None and task_id is not None:
            self._render_into_existing_task(wait_thread, progress, task_id, progress_lock)
        elif _should_render_progress():
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
        with _create_progress(transient=True) as progress:
            task_id = progress.add_task(
                f"{backend_name} {self.subcommand}",
                total=self.total_bytes,
            )
            while wait_thread.is_alive():
                completed = self._drain_updates(progress, task_id, completed)
                time.sleep(0.05)
            self._drain_updates(progress, task_id, completed)

    def _render_into_existing_task(
        self,
        wait_thread: threading.Thread,
        progress: Progress,
        task_id: TaskID,
        progress_lock: threading.Lock | None,
    ) -> None:
        completed = 0
        while wait_thread.is_alive():
            completed = self._drain_updates(progress, task_id, completed, progress_lock=progress_lock)
            time.sleep(0.05)
        self._drain_updates(progress, task_id, completed, progress_lock=progress_lock)

    def _drain_updates(
        self,
        progress: Progress,
        task_id: TaskID,
        completed: int,
        *,
        progress_lock: threading.Lock | None = None,
    ) -> int:
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
            if progress_lock is None:
                progress.update(task_id, completed=latest)
            else:
                with progress_lock:
                    progress.update(task_id, completed=latest)


class ContainerCleanupRegistry:
    """Track started containers and force-remove leftovers on scope exit."""

    def __init__(self) -> None:
        self._containers: list[object] = []
        self._lock = threading.Lock()

    def __enter__(self) -> "ContainerCleanupRegistry":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()

    def track(self, container) -> None:
        with self._lock:
            self._containers.append(container)

    def forget(self, container) -> None:
        with self._lock:
            try:
                self._containers.remove(container)
            except ValueError:
                pass

    def cleanup(self) -> None:
        with self._lock:
            pending = list(self._containers)
            self._containers.clear()

        for container in pending:
            _force_remove_container(container)


def _create_progress(*, transient: bool) -> Progress:
    """Build the standard Rich progress renderer used for container execution."""
    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        CompactByteCountColumn(),
        TimeElapsedColumn(),
        TextColumn("eta"),
        TimeRemainingColumn(compact=True, elapsed_when_finished=True),
        transient=transient,
    )


def _csv_data_offset(input_path: Path) -> int:
    """Return the byte offset of the first data row after the CSV header."""
    with open(input_path, "rb") as stream:
        stream.readline()
        return stream.tell()


def _align_to_row_start(stream, offset: int, data_start: int, file_size: int) -> int:
    """Advance an offset to the next CSV row boundary without scanning the file."""
    if offset <= data_start:
        return data_start
    if offset >= file_size:
        return file_size

    stream.seek(offset - 1)
    if stream.read(1) == b"\n":
        return offset

    stream.seek(offset)
    stream.readline()
    return min(stream.tell(), file_size)


def plan_worker_ranges(input_path: Path, workers: int) -> list[tuple[int, int]]:
    """Split the CSV body into byte ranges aligned on row boundaries."""
    if workers < 1:
        raise ValueError("workers must be >= 1")

    file_size = input_path.stat().st_size
    data_start = _csv_data_offset(input_path)
    if data_start >= file_size:
        return [(data_start, data_start)]

    boundaries = [data_start]
    with open(input_path, "rb") as stream:
        span = file_size - data_start
        for worker_index in range(1, workers):
            raw_offset = data_start + (span * worker_index) // workers
            boundaries.append(_align_to_row_start(stream, raw_offset, data_start, file_size))
    boundaries.append(file_size)

    ranges: list[tuple[int, int]] = []
    for start, end in zip(boundaries, boundaries[1:]):
        if start < end:
            ranges.append((start, end))

    return ranges or [(data_start, data_start)]


def _part_output_path(tmpdir: Path, output_path: Path, worker_index: int) -> Path:
    """Return a stable per-worker output filename."""
    return tmpdir / f"{output_path.stem}.part{worker_index:03d}{output_path.suffix}"


def _merge_csv_parts(part_paths: list[Path], output_path: Path) -> None:
    """Merge per-worker CSV outputs into a single output file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrote_header = False
    with open(output_path, "w", newline="") as merged:
        for part_path in part_paths:
            with open(part_path, "r", newline="") as part:
                for line_number, line in enumerate(part):
                    if line_number == 0:
                        if wrote_header:
                            continue
                        wrote_header = True
                    merged.write(line)


def _merge_json_arrays(part_paths: list[Path], output_path: Path) -> None:
    """Merge per-worker JSON array outputs into one JSON array."""
    merged: list[object] = []
    for part_path in part_paths:
        with open(part_path, "r", encoding="utf-8") as part:
            payload = json.load(part)
        if not isinstance(payload, list):
            raise ValueError(f"Validation output {part_path} did not contain a JSON array")
        merged.extend(payload)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as merged_file:
        json.dump(merged, merged_file, indent=2)


def _force_remove_container(container) -> None:
    """Best-effort forced removal used during interrupt/error cleanup."""
    try:
        container.remove(force=True)
    except NotFound:
        return
    except BaseException:  # pragma: no cover - defensive cleanup
        logger.warning("Failed to remove container during cleanup", exc_info=True)


def _tracked_container(container, *, registry: ContainerCleanupRegistry | None):
    """Context-manage a started container and unregister it after forced cleanup."""
    return _TrackedContainer(container, registry=registry)


class _TrackedContainer:
    """Internal context manager for a started Docker container."""

    def __init__(self, container, *, registry: ContainerCleanupRegistry | None) -> None:
        self.container = container
        self.registry = registry

    def __enter__(self):
        if self.registry is not None:
            self.registry.track(self.container)
        return self.container

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.registry is not None:
            self.registry.forget(self.container)
        _force_remove_container(self.container)


def _run_parallel_futures(
    submit_worker,
    *,
    worker_count: int,
) -> None:
    """Run submitted worker futures and cleanup started containers on interruption."""
    executor = ThreadPoolExecutor(max_workers=worker_count)
    futures = []
    try:
        futures = submit_worker(executor)
        for future in futures:
            future.result()
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)


def run_backend_containers_parallel(
    backend_name: str,
    input_path: Path,
    exec_mode: int,
    output_path: Path,
    *,
    workers: int,
    client=None,
    progress_channel_factory=DockerProgressChannel,
) -> None:
    """Run one backend container per byte range and merge partial results."""
    ranges = plan_worker_ranges(input_path, workers)
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    progress_lock = threading.Lock()
    progress_context = _create_progress(transient=True) if _should_render_progress() else nullcontext(None)

    with (
        ContainerCleanupRegistry() as container_registry,
        tempfile.TemporaryDirectory(prefix=f"{output_path.stem}.parts.", dir=output_path.parent) as tmpdir_name,
        progress_context as progress,
    ):
        tmpdir = Path(tmpdir_name)
        part_paths = [_part_output_path(tmpdir, output_path, index) for index in range(len(ranges))]
        task_ids: list[TaskID | None] = []
        if progress is not None:
            for index, (start, end) in enumerate(ranges):
                task_ids.append(
                    progress.add_task(
                        f"{backend_name} worker {index + 1}/{len(ranges)}",
                        total=end - start,
                    )
                )
        else:
            task_ids = [None] * len(ranges)

        def submit_workers(executor: ThreadPoolExecutor):
            futures = []
            for index, ((start, end), part_path, task_id) in enumerate(zip(ranges, part_paths, task_ids), start=1):
                futures.append(executor.submit(
                    run_backend_container,
                    backend_name,
                    input_path,
                    exec_mode,
                    part_path,
                    client=client,
                    progress_channel_factory=progress_channel_factory,
                    byte_start=start,
                    byte_end=end,
                    progress=progress,
                    task_id=task_id,
                    progress_lock=progress_lock,
                    worker_label=f"{backend_name} worker {index}/{len(ranges)}",
                    container_registry=container_registry,
                ))
            return futures

        _run_parallel_futures(
            submit_workers,
            worker_count=len(ranges),
        )
        _merge_csv_parts(part_paths, output_path)


def validate_backend_containers_parallel(
    backend_name: str,
    input_path: Path,
    exec_mode: int,
    output_path: Path | None = None,
    *,
    workers: int,
    client=None,
    progress_channel_factory=DockerProgressChannel,
) -> None:
    """Run one validation container per byte range and merge discrepancy outputs."""
    ranges = plan_worker_ranges(input_path, workers)
    if output_path is not None:
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

    progress_lock = threading.Lock()
    progress_context = _create_progress(transient=True) if _should_render_progress() else nullcontext(None)

    with (
        ContainerCleanupRegistry() as container_registry,
        tempfile.TemporaryDirectory(
            prefix=f"{backend_name}.validate.parts.",
            dir=(output_path.parent if output_path is not None else None),
        ) as tmpdir_name,
        progress_context as progress,
    ):
        tmpdir = Path(tmpdir_name)
        part_paths = [_part_output_path(tmpdir, Path("failures.json"), index) for index in range(len(ranges))]
        task_ids: list[TaskID | None] = []
        if progress is not None:
            for index, (start, end) in enumerate(ranges):
                task_ids.append(
                    progress.add_task(
                        f"{backend_name} validate {index + 1}/{len(ranges)}",
                        total=end - start,
                    )
                )
        else:
            task_ids = [None] * len(ranges)

        def submit_workers(executor: ThreadPoolExecutor):
            futures = []
            for index, ((start, end), part_path, task_id) in enumerate(zip(ranges, part_paths, task_ids), start=1):
                futures.append(executor.submit(
                    validate_backend_container,
                    backend_name,
                    input_path,
                    exec_mode,
                    output_path=part_path,
                    client=client,
                    progress_channel_factory=progress_channel_factory,
                    byte_start=start,
                    byte_end=end,
                    progress=progress,
                    task_id=task_id,
                    progress_lock=progress_lock,
                    worker_label=f"{backend_name} validate {index}/{len(ranges)}",
                    allow_discrepancies=True,
                    container_registry=container_registry,
                ))
            return futures

        results: list[int] = []

        def submit_and_collect(executor: ThreadPoolExecutor):
            submitted = list(zip(submit_workers(executor), part_paths))

            class _CollectingFuture:
                def __init__(self, future, part_path: Path) -> None:
                    self.future = future
                    self.part_path = part_path

                def result(self):
                    status_code = self.future.result()
                    results.append(status_code)
                    if output_path is None or self.part_path.exists():
                        return
                    if status_code == 0:
                        self.part_path.write_text("[]", encoding="utf-8")
                        return
                    raise RuntimeError(
                        f"Validation worker reported discrepancies but did not write {self.part_path}"
                    )

            return [_CollectingFuture(future, part_path) for future, part_path in submitted]

        _run_parallel_futures(
            submit_and_collect,
            worker_count=len(ranges),
        )

        if output_path is not None:
            _merge_json_arrays(part_paths, output_path)

        if any(status_code == 1 for status_code in results):
            raise RuntimeError("Validation found discrepancies")


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
    byte_start: int | None = None,
    byte_end: int | None = None,
    progress: Progress | None = None,
    task_id: TaskID | None = None,
    progress_lock: threading.Lock | None = None,
    worker_label: str | None = None,
    container_registry: ContainerCleanupRegistry | None = None,
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
        byte_start=byte_start,
        byte_end=byte_end,
        progress=progress,
        task_id=task_id,
        progress_lock=progress_lock,
        worker_label=worker_label,
        container_registry=container_registry,
    )


def validate_backend_container(
    backend_name: str,
    input_path: Path,
    exec_mode: int,
    output_path: Path | None = None,
    *,
    client=None,
    progress_channel_factory=DockerProgressChannel,
    byte_start: int | None = None,
    byte_end: int | None = None,
    progress: Progress | None = None,
    task_id: TaskID | None = None,
    progress_lock: threading.Lock | None = None,
    worker_label: str | None = None,
    allow_discrepancies: bool = False,
    container_registry: ContainerCleanupRegistry | None = None,
) -> int:
    """Run backend validation inside a container."""
    return _run_backend_container(
        backend_name,
        exec_mode=exec_mode,
        subcommand="validate",
        input_path=input_path,
        output_path=output_path,
        client=client,
        progress_channel_factory=progress_channel_factory,
        byte_start=byte_start,
        byte_end=byte_end,
        progress=progress,
        task_id=task_id,
        progress_lock=progress_lock,
        worker_label=worker_label,
        allow_discrepancies=allow_discrepancies,
        container_registry=container_registry,
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
    byte_start: int | None = None,
    byte_end: int | None = None,
    progress: Progress | None = None,
    task_id: TaskID | None = None,
    progress_lock: threading.Lock | None = None,
    worker_label: str | None = None,
    allow_discrepancies: bool = False,
    container_registry: ContainerCleanupRegistry | None = None,
) -> int:
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
        if byte_start is not None or byte_end is not None:
            start = 0 if byte_start is None else byte_start
            end = input_path.stat().st_size if byte_end is None else byte_end
            progress_channel.total_bytes = max(0, end - start)
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
        if byte_start is not None:
            command.extend([
                "--byte-start",
                str(byte_start),
            ])
        if byte_end is not None:
            command.extend([
                "--byte-end",
                str(byte_end),
            ])
        command.extend([
            "--progress-socket",
            str(progress_channel.container_socket_path),
        ])
        with _tracked_container(
            client.containers.run(
                image=image,
                command=command,
                volumes=volumes,
                detach=True,
                remove=False,
            ),
            registry=container_registry,
        ) as container:
            status_code = progress_channel.track_container(
                container,
                backend_name,
                progress=progress,
                task_id=task_id,
                progress_lock=progress_lock,
                log_label=worker_label,
            )
            if subcommand == "validate" and status_code == 1 and allow_discrepancies:
                return status_code
            if status_code != 0:
                label = backend_name if worker_label is None else worker_label
                if subcommand == "validate" and status_code == 1:
                    raise RuntimeError("Validation found discrepancies")
                raise RuntimeError(f"Backend {label!r} exited with code {status_code}")
            return status_code


def run_backend_in_docker(
    input_path: Path,
    backend_name: str,
    exec_mode: int,
    output_path: Path,
    workers: int = 1,
) -> None:
    """Build and run a backend container."""
    client = docker.from_env()
    build_backend_image(backend_name, client=client)
    if workers == 1:
        run_backend_container(backend_name, input_path, exec_mode, output_path, client=client)
        return

    run_backend_containers_parallel(
        backend_name,
        input_path,
        exec_mode,
        output_path,
        workers=workers,
        client=client,
    )


def validate_backend_in_docker(
    input_path: Path,
    backend_name: str,
    exec_mode: int,
    output_path: Path | None = None,
    workers: int = 1,
) -> None:
    """Build and run backend validation inside a container."""
    client = docker.from_env()
    build_backend_image(backend_name, client=client)
    if workers == 1:
        validate_backend_container(backend_name, input_path, exec_mode, output_path=output_path, client=client)
        return

    validate_backend_containers_parallel(
        backend_name,
        input_path,
        exec_mode,
        output_path=output_path,
        workers=workers,
        client=client,
    )
