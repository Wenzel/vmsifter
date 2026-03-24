"""Docker-backed runtime for vmsifter-bench backends."""

from __future__ import annotations

import logging
from pathlib import Path

import docker
from docker.errors import BuildError

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTAINERS_DIR = PROJECT_ROOT / "containers"
IMAGE_PREFIX = "vmsifter-bench"


class BackendNotFoundError(ValueError):
    """Raised when a backend does not have a container definition."""


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
) -> None:
    """Run a built backend container to completion."""
    _run_backend_container(
        backend_name,
        exec_mode=exec_mode,
        subcommand="run",
        input_path=input_path,
        output_path=output_path,
        client=client,
    )


def validate_backend_container(
    backend_name: str,
    input_path: Path,
    exec_mode: int,
    output_path: Path | None = None,
    *,
    client=None,
) -> None:
    """Run backend validation inside a container."""
    _run_backend_container(
        backend_name,
        exec_mode=exec_mode,
        subcommand="validate",
        input_path=input_path,
        output_path=output_path,
        client=client,
    )


def _run_backend_container(
    backend_name: str,
    exec_mode: int,
    subcommand: str,
    input_path: Path,
    output_path: Path | None,
    *,
    client=None,
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
    container = client.containers.run(
        image=image,
        command=command,
        volumes=volumes,
        detach=True,
        remove=False,
    )

    try:
        for chunk in container.logs(stream=True, follow=True):
            line = chunk.decode(errors="replace").rstrip()
            if line:
                logger.info("[%s] %s", backend_name, line)

        result = container.wait()
        status_code = result["StatusCode"]
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
