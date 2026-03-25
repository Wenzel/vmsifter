"""Tests for runner behavior."""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

from bench import runner as runner_module
from bench.schema import Backend, BackendResult


class FakeBackend(Backend):
    name = "fake"
    kind = "decoder"

    def __init__(self, exec_mode: int) -> None:
        self.exec_mode = exec_mode

    def process(self, insn_bytes: bytes) -> BackendResult:
        return BackendResult(valid=True, length=len(insn_bytes), exit_type="valid")


def test_runner_reports_progress_over_unix_socket(tmp_path: Path, monkeypatch):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results.csv"
    socket_path = tmp_path / "progress.sock"
    input_path.write_text("insn\n90\n0f0b\n", encoding="ascii")
    messages: list[dict[str, object]] = []

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)

    def read_messages() -> None:
        conn, _ = server.accept()
        with conn, conn.makefile("r", encoding="utf-8") as stream:
            for line in stream:
                messages.append(json.loads(line))

    reader = threading.Thread(target=read_messages, daemon=True)
    reader.start()
    monkeypatch.setattr(
        runner_module.rich.progress,
        "open",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("rich.progress.open should not be used")),
    )

    runner_module.run(
        input_path,
        FakeBackend(exec_mode=64),
        64,
        output_path,
        progress_socket=socket_path,
    )

    reader.join(timeout=1)
    server.close()

    assert messages[0]["current"] == 0
    assert messages[-1]["current"] == input_path.stat().st_size
    assert messages[-1]["done"] is True
