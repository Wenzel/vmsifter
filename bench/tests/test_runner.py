"""Tests for runner behavior."""

from __future__ import annotations

import csv
import json
import socket
import threading
from pathlib import Path

import pytest

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


def test_runner_processes_only_the_assigned_byte_range(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results.csv"
    input_path.write_text("insn\n90\n0f0b\ncc\n", encoding="ascii")

    with open(input_path, "rb") as stream:
        stream.readline()
        first_start = stream.tell()
        stream.readline()
        second_start = stream.tell()
        stream.readline()
        third_start = stream.tell()

    runner_module.run(
        input_path,
        FakeBackend(exec_mode=64),
        64,
        output_path,
        byte_start=second_start,
        byte_end=third_start,
    )

    with open(output_path, newline="") as result_file:
        rows = list(csv.DictReader(result_file))

    assert [row["insn"] for row in rows] == ["0f0b"]
    assert first_start < second_start < third_start


def test_runner_logs_invalid_insn_hex_with_row_context(tmp_path: Path, caplog):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "results.csv"
    input_path.write_text("insn\nzz\n", encoding="ascii")

    with pytest.raises(SystemExit):
        runner_module.run(input_path, FakeBackend(exec_mode=64), 64, output_path)

    assert "CSV row 2" in caplog.text
    assert "insn='zz'" in caplog.text
