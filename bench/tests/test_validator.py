"""Tests for validation runner behavior."""

import json
import socket
import threading
from pathlib import Path

import pytest

from bench.schema import Backend, BackendResult, ReferenceRow, ValidationIssue, ValidationReport
from bench.validator import validate


class FakeBackend(Backend):
    name = "fake"
    kind = "decoder"

    def __init__(self, exec_mode: int) -> None:
        self.exec_mode = exec_mode

    def process(self, insn_bytes: bytes) -> BackendResult:
        return BackendResult(valid=True, length=len(insn_bytes), exit_type="valid")

    def validate(self, reference: ReferenceRow, result: BackendResult) -> ValidationReport:
        if reference.is_xed_comparable():
            if result.length != reference.length:
                return ValidationReport(
                    comparable=True,
                    issues=(ValidationIssue(
                        field="length",
                        expected=reference.length,
                        actual=result.length,
                        message="length mismatch",
                    ),),
                )
            return ValidationReport(comparable=True)
        return ValidationReport.skip()


def test_validate_counts_only_comparable_rows(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    input_path.write_text(
        "\n".join([
            "insn,length,exit-type,misc,reg-delta",
            "90,1,vmexit:37,,",
            "0f0b,2,vmexit:0 interrupt_type:hw_exc interrupt_vector:invalid_opcode,,",
        ]) + "\n",
        encoding="ascii",
    )

    summary = validate(input_path, FakeBackend(exec_mode=64))

    assert summary.total_rows == 2
    assert summary.comparable_rows == 1
    assert summary.discrepant_rows == 0
    assert summary.issue_count == 0


def test_validate_reports_discrepancies(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    input_path.write_text(
        "\n".join([
            "insn,length,exit-type,misc,reg-delta",
            "0f1f00,2,vmexit:37,,",
        ]) + "\n",
        encoding="ascii",
    )

    summary = validate(input_path, FakeBackend(exec_mode=64))

    assert summary.total_rows == 1
    assert summary.comparable_rows == 1
    assert summary.discrepant_rows == 1
    assert summary.issue_count == 1


def test_validate_writes_failures_as_json_array(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text(
        "\n".join([
            "insn,length,exit-type,misc,reg-delta",
            "0f1f00,2,vmexit:37,,",
        ]) + "\n",
        encoding="ascii",
    )

    summary = validate(input_path, FakeBackend(exec_mode=64), output_path=output_path)

    assert summary.discrepant_rows == 1
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["reference"]["insn"] == "0f1f00"
    assert payload[0]["report"]["comparable"] is True
    assert payload[0]["report"]["issues"][0]["field"] == "length"


def test_validate_reports_byte_progress_over_unix_socket(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    socket_path = tmp_path / "progress.sock"
    input_path.write_text(
        "\n".join([
            "insn,length,exit-type,misc,reg-delta",
            "90,1,vmexit:37,,",
            "0f0b,2,vmexit:0 interrupt_type:hw_exc interrupt_vector:invalid_opcode,,",
        ]) + "\n",
        encoding="ascii",
    )
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

    validate(input_path, FakeBackend(exec_mode=64), progress_socket=socket_path)

    reader.join(timeout=1)
    server.close()

    assert messages[0]["current"] == 0
    assert messages[-1]["current"] == input_path.stat().st_size
    assert messages[-1]["done"] is True


def test_validate_processes_only_the_assigned_byte_range(tmp_path: Path):
    input_path = tmp_path / "catalog.csv"
    output_path = tmp_path / "failures.json"
    input_path.write_text(
        "\n".join([
            "insn,length,exit-type,misc,reg-delta",
            "90,1,vmexit:37,,",
            "0f1f00,2,vmexit:37,,",
        ]) + "\n",
        encoding="ascii",
    )

    with open(input_path, "rb") as stream:
        stream.readline()
        stream.readline()
        second_start = stream.tell()

    summary = validate(
        input_path,
        FakeBackend(exec_mode=64),
        output_path=output_path,
        byte_start=second_start,
    )

    assert summary.total_rows == 1
    assert summary.discrepant_rows == 1
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [entry["reference"]["insn"] for entry in payload] == ["0f1f00"]


def test_validate_logs_invalid_insn_hex_with_row_context(tmp_path: Path, caplog):
    input_path = tmp_path / "catalog.csv"
    input_path.write_text(
        "\n".join([
            "insn,length,exit-type,misc,reg-delta",
            "zz,1,vmexit:37,,",
        ]) + "\n",
        encoding="ascii",
    )

    with pytest.raises(SystemExit):
        validate(input_path, FakeBackend(exec_mode=64))

    assert "CSV row 2" in caplog.text
    assert "insn='zz'" in caplog.text
