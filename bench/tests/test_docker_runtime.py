"""Tests for Docker runtime helpers."""

import logging
from pathlib import Path

from bench.docker_runtime import (
    build_backend_image,
    dockerfile_for_backend,
    image_name_for_backend,
    list_backends,
    run_backend_container,
    validate_backend_container,
)


class FakeImages:
    def __init__(self) -> None:
        self.calls = []

    def build(self, **kwargs) -> None:
        self.calls.append(kwargs)


class FakeAPI:
    def __init__(self) -> None:
        self.calls = []

    def build(self, **kwargs):
        self.calls.append(kwargs)
        yield {"stream": "Step 1/2 : FROM scratch\n"}
        yield {"status": "Building", "id": "layer0", "progress": "[==========>]"}


class FakeContainer:
    def __init__(self) -> None:
        self.removed = []

    def logs(self, stream: bool, follow: bool):
        assert stream is True
        assert follow is True
        yield b"processing\n"

    def wait(self):
        return {"StatusCode": 0}

    def remove(self, force: bool) -> None:
        self.removed.append(force)


class FakeContainers:
    def __init__(self) -> None:
        self.calls = []
        self.last_container = FakeContainer()

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return self.last_container


class FakeClient:
    def __init__(self) -> None:
        self.images = FakeImages()
        self.api = FakeAPI()
        self.containers = FakeContainers()


def test_list_backends_discovers_container_directories(tmp_path: Path):
    (tmp_path / "xed").mkdir()
    (tmp_path / "xed" / "Dockerfile").write_text("FROM scratch\n", encoding="ascii")
    (tmp_path / "unicorn").mkdir()
    (tmp_path / "unicorn" / "Dockerfile").write_text("FROM scratch\n", encoding="ascii")
    (tmp_path / "notes").mkdir()

    assert list_backends(tmp_path) == ["unicorn", "xed"]


def test_dockerfile_for_backend_uses_container_convention(tmp_path: Path):
    dockerfile = tmp_path / "capstone" / "Dockerfile"
    dockerfile.parent.mkdir()
    dockerfile.write_text("FROM scratch\n", encoding="ascii")

    assert dockerfile_for_backend("capstone", tmp_path) == dockerfile


def test_build_backend_image_uses_project_root_and_relative_dockerfile(tmp_path: Path):
    project_root = tmp_path
    containers_dir = project_root / "containers"
    dockerfile = containers_dir / "xed" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n", encoding="ascii")
    client = FakeClient()

    image = build_backend_image("xed", client=client, project_root=project_root, containers_dir=containers_dir)

    assert image == image_name_for_backend("xed")
    assert client.images.calls == [{
        "path": str(project_root),
        "dockerfile": "containers/xed/Dockerfile",
        "tag": "vmsifter-bench/xed:dev",
        "rm": True,
    }]


def test_build_backend_image_streams_debug_logs_when_debug_enabled(tmp_path: Path, caplog):
    project_root = tmp_path
    containers_dir = project_root / "containers"
    dockerfile = containers_dir / "xed" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n", encoding="ascii")
    client = FakeClient()

    caplog.set_level(logging.DEBUG, logger="bench.docker_runtime")
    build_backend_image("xed", client=client, project_root=project_root, containers_dir=containers_dir)

    assert client.images.calls == []
    assert client.api.calls == [{
        "path": str(project_root),
        "dockerfile": "containers/xed/Dockerfile",
        "tag": "vmsifter-bench/xed:dev",
        "rm": True,
        "decode": True,
    }]
    assert "[build:xed] Step 1/2 : FROM scratch" in caplog.text
    assert "[build:xed] layer0: Building [==========>]" in caplog.text


def test_run_backend_container_mounts_shared_directory_once(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results_xed.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    run_backend_container("xed", input_path, 64, output_path, client=client)

    assert client.containers.calls == [{
        "image": "vmsifter-bench/xed:dev",
        "command": [
            "run",
            "--input",
            "/work/catalog.csv",
            "--backend",
            "xed",
            "--exec-mode",
            "64",
            "--output",
            "/work/results_xed.csv",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/work", "mode": "rw"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]


def test_validate_backend_container_mounts_input_only(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    validate_backend_container("xed", input_path, 64, client=client)

    assert client.containers.calls == [{
        "image": "vmsifter-bench/xed:dev",
        "command": [
            "validate",
            "--input",
            "/input/catalog.csv",
            "--backend",
            "xed",
            "--exec-mode",
            "64",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/input", "mode": "ro"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]
