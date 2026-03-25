"""Tests for Docker runtime helpers."""

import logging
from pathlib import Path

import bench.docker_runtime as docker_runtime_module
from rich.progress import TimeRemainingColumn

from bench.docker_runtime import (
    CompactByteCountColumn,
    DockerProgressChannel,
    _format_byte_count,
    build_backend_image,
    dockerfile_for_backend,
    image_name_for_backend,
    list_backends,
    run_backend_container,
    run_backend_containers_parallel,
    run_backend_in_docker,
    plan_worker_ranges,
    validate_backend_container,
    validate_backend_containers_parallel,
    validate_backend_in_docker,
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


class FakeProgressChannel:
    def __init__(self, input_path: Path, subcommand: str) -> None:
        self.input_path = input_path
        self.subcommand = subcommand
        self.mount_dir = Path("/tmp/fake-progress")
        self.container_socket_path = Path("/progress/progress.sock")

    def __enter__(self) -> "FakeProgressChannel":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def track_container(
        self,
        container,
        backend_name: str,
        *,
        progress=None,
        task_id=None,
        progress_lock=None,
        log_label: str | None = None,
    ) -> int:
        return 0


class InterruptingFuture:
    def __init__(self, *, raises: bool) -> None:
        self.raises = raises

    def result(self):
        if self.raises:
            raise KeyboardInterrupt()
        return None


class FakeExecutor:
    instances = []

    def __init__(self, max_workers: int) -> None:
        self.max_workers = max_workers
        self.shutdown_calls = []
        self._submit_count = 0
        type(self).instances.append(self)

    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)
        future = InterruptingFuture(raises=self._submit_count == 0)
        self._submit_count += 1
        return future

    def shutdown(self, wait: bool, cancel_futures: bool = False) -> None:
        self.shutdown_calls.append((wait, cancel_futures))


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


def test_format_byte_count_uses_compact_decimal_suffixes():
    assert _format_byte_count(999) == "999B"
    assert _format_byte_count(1_000) == "1.0KB"
    assert _format_byte_count(23_778_600) == "23.8MB"
    assert _format_byte_count(1_263_225_561) == "1.3GB"


def test_compact_byte_count_column_renders_current_and_total_bytes():
    class FakeTask:
        completed = 23_778_600
        total = 126_322_561

    assert CompactByteCountColumn().render(FakeTask()) == "23.8MB/126.3MB"


def test_render_progress_adds_eta_column(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")
    channel = DockerProgressChannel(input_path, "validate")
    captured = {}

    class FakeProgress:
        def __init__(self, *columns, transient: bool) -> None:
            captured["columns"] = columns
            captured["transient"] = transient

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def add_task(self, description: str, total: int):
            captured["description"] = description
            captured["total"] = total
            return 1

        def update(self, task_id, completed: int) -> None:
            captured["completed"] = completed

    class DeadThread:
        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(docker_runtime_module, "Progress", FakeProgress)

    channel._render_progress(DeadThread(), "xed")

    assert captured["transient"] is True
    assert captured["description"] == "xed validate"
    assert captured["total"] == input_path.stat().st_size
    assert any(isinstance(column, TimeRemainingColumn) for column in captured["columns"])


def test_plan_worker_ranges_aligns_on_row_boundaries(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n0f0b\ncc\n", encoding="ascii")

    ranges = plan_worker_ranges(input_path, 3)

    assert ranges == [(5, 8), (8, 13), (13, 16)]


def test_run_backend_container_mounts_shared_directory_once(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results_xed.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    run_backend_container(
        "xed",
        input_path,
        64,
        output_path,
        client=client,
        progress_channel_factory=FakeProgressChannel,
    )

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
            "--progress-socket",
            "/progress/progress.sock",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/work", "mode": "rw"},
            "/tmp/fake-progress": {"bind": "/progress", "mode": "rw"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]


def test_run_backend_container_passes_byte_range_arguments(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results_xed.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    run_backend_container(
        "xed",
        input_path,
        64,
        output_path,
        client=client,
        progress_channel_factory=FakeProgressChannel,
        byte_start=5,
        byte_end=8,
        worker_label="xed worker 1/2",
    )

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
            "--byte-start",
            "5",
            "--byte-end",
            "8",
            "--progress-socket",
            "/progress/progress.sock",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/work", "mode": "rw"},
            "/tmp/fake-progress": {"bind": "/progress", "mode": "rw"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]


def test_validate_backend_container_mounts_input_only(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    validate_backend_container(
        "xed",
        input_path,
        64,
        client=client,
        progress_channel_factory=FakeProgressChannel,
    )

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
            "--progress-socket",
            "/progress/progress.sock",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/input", "mode": "ro"},
            "/tmp/fake-progress": {"bind": "/progress", "mode": "rw"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]


def test_validate_backend_container_with_output_mounts_shared_directory(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text("insn\n90\n", encoding="ascii")

    validate_backend_container(
        "xed",
        input_path,
        64,
        output_path=output_path,
        client=client,
        progress_channel_factory=FakeProgressChannel,
    )

    assert client.containers.calls == [{
        "image": "vmsifter-bench/xed:dev",
        "command": [
            "validate",
            "--input",
            "/work/catalog.csv",
            "--backend",
            "xed",
            "--exec-mode",
            "64",
            "--output",
            "/work/failures.json",
            "--progress-socket",
            "/progress/progress.sock",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/work", "mode": "rw"},
            "/tmp/fake-progress": {"bind": "/progress", "mode": "rw"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]


def test_validate_backend_container_passes_byte_range_arguments(tmp_path: Path):
    client = FakeClient()
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text("insn\n90\n", encoding="ascii")

    validate_backend_container(
        "xed",
        input_path,
        64,
        output_path=output_path,
        client=client,
        progress_channel_factory=FakeProgressChannel,
        byte_start=5,
        byte_end=8,
        worker_label="xed validate 1/2",
    )

    assert client.containers.calls == [{
        "image": "vmsifter-bench/xed:dev",
        "command": [
            "validate",
            "--input",
            "/work/catalog.csv",
            "--backend",
            "xed",
            "--exec-mode",
            "64",
            "--output",
            "/work/failures.json",
            "--byte-start",
            "5",
            "--byte-end",
            "8",
            "--progress-socket",
            "/progress/progress.sock",
        ],
        "volumes": {
            str(tmp_path.resolve()): {"bind": "/work", "mode": "rw"},
            "/tmp/fake-progress": {"bind": "/progress", "mode": "rw"},
        },
        "detach": True,
        "remove": False,
    }]
    assert client.containers.last_container.removed == [True]


def test_run_backend_containers_parallel_merges_partial_outputs(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results_xed.csv"
    input_path.write_text("insn\n90\ncc\n", encoding="ascii")

    calls = []

    def fake_run_backend_container(
        backend_name: str,
        input_file: Path,
        exec_mode: int,
        part_output: Path,
        *,
        client=None,
        progress_channel_factory=DockerProgressChannel,
        byte_start: int | None = None,
        byte_end: int | None = None,
        progress=None,
        task_id=None,
        progress_lock=None,
        worker_label: str | None = None,
        container_registry=None,
    ) -> None:
        calls.append((backend_name, input_file, exec_mode, byte_start, byte_end, worker_label))
        part_output.write_text(
            "insn,valid,length,exit_type,reg_delta,backend,exec_mode,misc\n"
            f"{byte_start}-{byte_end},True,1,valid,,{backend_name},{exec_mode},\n",
            encoding="ascii",
        )

    monkeypatch.setattr(docker_runtime_module, "run_backend_container", fake_run_backend_container)
    monkeypatch.setattr(docker_runtime_module, "_should_render_progress", lambda: False)

    run_backend_containers_parallel("xed", input_path, 64, output_path, workers=2, client=object())

    assert len(calls) == 2
    assert output_path.read_text(encoding="ascii") == (
        "insn,valid,length,exit_type,reg_delta,backend,exec_mode,misc\n"
        "5-8,True,1,valid,,xed,64,\n"
        "8-11,True,1,valid,,xed,64,\n"
    )


def test_run_backend_in_docker_uses_parallel_path_when_workers_gt_one(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results_xed.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    client = object()
    build_calls = []
    parallel_calls = []

    monkeypatch.setattr(docker_runtime_module.docker, "from_env", lambda: client)
    monkeypatch.setattr(
        docker_runtime_module,
        "build_backend_image",
        lambda backend_name, *, client=None: build_calls.append((backend_name, client)),
    )
    monkeypatch.setattr(
        docker_runtime_module,
        "run_backend_containers_parallel",
        lambda backend_name, input_file, exec_mode, output_file, *, workers, client=None, progress_channel_factory=DockerProgressChannel:
        parallel_calls.append((backend_name, input_file, exec_mode, output_file, workers, client)),
    )

    run_backend_in_docker(input_path, "xed", 64, output_path, workers=3)

    assert build_calls == [("xed", client)]
    assert parallel_calls == [("xed", input_path, 64, output_path, 3, client)]


def test_parallel_run_cleans_up_started_containers_on_interrupt(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results_xed.csv"
    input_path.write_text("insn\n90\ncc\n", encoding="ascii")
    started = []

    def fake_run_backend_container(
        backend_name: str,
        input_file: Path,
        exec_mode: int,
        part_output: Path,
        *,
        client=None,
        progress_channel_factory=DockerProgressChannel,
        byte_start: int | None = None,
        byte_end: int | None = None,
        progress=None,
        task_id=None,
        progress_lock=None,
        worker_label: str | None = None,
        container_registry=None,
    ) -> None:
        container = FakeContainer()
        started.append(container)
        if container_registry is not None:
            container_registry.track(container)

    FakeExecutor.instances.clear()
    monkeypatch.setattr(docker_runtime_module, "run_backend_container", fake_run_backend_container)
    monkeypatch.setattr(docker_runtime_module, "_should_render_progress", lambda: False)
    monkeypatch.setattr(docker_runtime_module, "ThreadPoolExecutor", FakeExecutor)

    try:
        run_backend_containers_parallel("xed", input_path, 64, output_path, workers=2, client=object())
    except KeyboardInterrupt:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected KeyboardInterrupt")

    assert len(started) == 2
    assert [container.removed for container in started] == [[True], [True]]
    assert FakeExecutor.instances[0].shutdown_calls == [(False, True)]


def test_validate_backend_containers_parallel_merges_json_outputs(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text("insn\n90\ncc\n", encoding="ascii")

    calls = []

    def fake_validate_backend_container(
        backend_name: str,
        input_file: Path,
        exec_mode: int,
        output_path: Path | None = None,
        *,
        client=None,
        progress_channel_factory=DockerProgressChannel,
        byte_start: int | None = None,
        byte_end: int | None = None,
        progress=None,
        task_id=None,
        progress_lock=None,
        worker_label: str | None = None,
        allow_discrepancies: bool = False,
        container_registry=None,
    ) -> int:
        calls.append((backend_name, input_file, exec_mode, byte_start, byte_end, worker_label, allow_discrepancies))
        assert output_path is not None
        output_path.write_text(f'[{{"start": {byte_start}, "end": {byte_end}}}]', encoding="utf-8")
        return 1 if byte_start == 5 else 0

    monkeypatch.setattr(docker_runtime_module, "validate_backend_container", fake_validate_backend_container)
    monkeypatch.setattr(docker_runtime_module, "_should_render_progress", lambda: False)

    try:
        validate_backend_containers_parallel("xed", input_path, 64, output_path=output_path, workers=2, client=object())
    except RuntimeError as exc:
        assert str(exc) == "Validation found discrepancies"
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected validation discrepancies to raise")

    assert len(calls) == 2
    assert all(call[-1] is True for call in calls)
    assert output_path.read_text(encoding="utf-8") == '[\n  {\n    "start": 5,\n    "end": 8\n  },\n  {\n    "start": 8,\n    "end": 11\n  }\n]'


def test_validate_backend_containers_parallel_treats_missing_clean_outputs_as_empty_arrays(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text("insn\n90\ncc\n", encoding="ascii")

    def fake_validate_backend_container(
        backend_name: str,
        input_file: Path,
        exec_mode: int,
        output_path: Path | None = None,
        *,
        client=None,
        progress_channel_factory=DockerProgressChannel,
        byte_start: int | None = None,
        byte_end: int | None = None,
        progress=None,
        task_id=None,
        progress_lock=None,
        worker_label: str | None = None,
        allow_discrepancies: bool = False,
        container_registry=None,
    ) -> int:
        assert output_path is not None
        if byte_start == 5:
            output_path.write_text(f'[{{"start": {byte_start}, "end": {byte_end}}}]', encoding="utf-8")
            return 1
        return 0

    monkeypatch.setattr(docker_runtime_module, "validate_backend_container", fake_validate_backend_container)
    monkeypatch.setattr(docker_runtime_module, "_should_render_progress", lambda: False)

    try:
        validate_backend_containers_parallel("xed", input_path, 64, output_path=output_path, workers=2, client=object())
    except RuntimeError as exc:
        assert str(exc) == "Validation found discrepancies"
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected validation discrepancies to raise")

    assert output_path.read_text(encoding="utf-8") == '[\n  {\n    "start": 5,\n    "end": 8\n  }\n]'


def test_validate_backend_in_docker_uses_parallel_path_when_workers_gt_one(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text("insn\n90\n", encoding="ascii")

    client = object()
    build_calls = []
    parallel_calls = []

    monkeypatch.setattr(docker_runtime_module.docker, "from_env", lambda: client)
    monkeypatch.setattr(
        docker_runtime_module,
        "build_backend_image",
        lambda backend_name, *, client=None: build_calls.append((backend_name, client)),
    )
    monkeypatch.setattr(
        docker_runtime_module,
        "validate_backend_containers_parallel",
        lambda backend_name, input_file, exec_mode, output_path=None, *, workers, client=None, progress_channel_factory=DockerProgressChannel:
        parallel_calls.append((backend_name, input_file, exec_mode, output_path, workers, client)),
    )

    validate_backend_in_docker(input_path, "xed", 64, output_path=output_path, workers=3)

    assert build_calls == [("xed", client)]
    assert parallel_calls == [("xed", input_path, 64, output_path, 3, client)]
