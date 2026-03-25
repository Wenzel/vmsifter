"""Tests for in-container argument plumbing."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from bench import container_entrypoint


class FakeBackendContext:
    def __init__(self, backend) -> None:
        self.backend = backend

    def __enter__(self):
        return self.backend

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_main_passes_progress_socket_to_runner(monkeypatch):
    calls = []
    backend = object()
    progress_socket = Path("/progress/progress.sock")

    monkeypatch.setattr(
        container_entrypoint,
        "parse_args",
        lambda: Namespace(
            command="run",
            input_path=Path("/input/catalog.csv"),
            output_path=Path("/output/results.csv"),
            backend_name="xed",
            exec_mode=64,
            progress_socket=progress_socket,
            byte_start=123,
            byte_end=456,
        ),
    )
    monkeypatch.setattr(container_entrypoint, "get_backend", lambda *args, **kwargs: FakeBackendContext(backend))
    monkeypatch.setattr(container_entrypoint, "run_backend", lambda *args, **kwargs: calls.append((args, kwargs)))

    container_entrypoint.main()

    assert calls == [(
        (Path("/input/catalog.csv"), backend, 64, Path("/output/results.csv")),
        {"progress_socket": progress_socket, "byte_start": 123, "byte_end": 456},
    )]


def test_main_passes_progress_socket_to_validator(monkeypatch):
    calls = []
    backend = object()
    progress_socket = Path("/progress/progress.sock")

    monkeypatch.setattr(
        container_entrypoint,
        "parse_args",
        lambda: Namespace(
            command="validate",
            input_path=Path("/input/catalog.csv"),
            output_path=Path("/output/failures.json"),
            backend_name="xed",
            exec_mode=64,
            progress_socket=progress_socket,
            byte_start=123,
            byte_end=456,
        ),
    )
    monkeypatch.setattr(container_entrypoint, "get_backend", lambda *args, **kwargs: FakeBackendContext(backend))
    monkeypatch.setattr(
        container_entrypoint,
        "validate_backend",
        lambda *args, **kwargs: calls.append((args, kwargs)) or Namespace(discrepant_rows=0),
    )

    container_entrypoint.main()

    assert calls == [(
        (Path("/input/catalog.csv"), backend, Path("/output/failures.json")),
        {"progress_socket": progress_socket, "byte_start": 123, "byte_end": 456},
    )]
