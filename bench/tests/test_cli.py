"""Tests for CLI orchestration behavior."""

import csv
from pathlib import Path

from click.testing import CliRunner

from bench import cli


def test_backends_command_lists_container_backends(monkeypatch):
    monkeypatch.setattr(cli, "list_backends", lambda: ["unicorn", "xed"])

    result = CliRunner().invoke(cli.main, ["backends"])

    assert result.exit_code == 0
    assert result.output == "  unicorn\n  xed\n"


def test_run_command_uses_docker_runtime(tmp_path: Path, monkeypatch):
    calls = []

    def fake_run_backend_in_docker(
        input_path: Path,
        backend_name: str,
        exec_mode: int,
        output_path: Path,
        *,
        workers: int,
    ) -> None:
        calls.append((input_path, backend_name, exec_mode, output_path, workers))

    monkeypatch.setattr(cli, "run_backend_in_docker", fake_run_backend_in_docker)
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    result = CliRunner().invoke(
        cli.main,
        ["run", "--input", str(input_path), "--backend", "xed", "--exec-mode", "64"],
    )

    assert result.exit_code == 0
    assert calls == [(input_path, "xed", 64, Path("results_xed.csv"), 1)]


def test_run_command_passes_worker_count(tmp_path: Path, monkeypatch):
    calls = []

    def fake_run_backend_in_docker(
        input_path: Path,
        backend_name: str,
        exec_mode: int,
        output_path: Path,
        *,
        workers: int,
    ) -> None:
        calls.append((input_path, backend_name, exec_mode, output_path, workers))

    monkeypatch.setattr(cli, "run_backend_in_docker", fake_run_backend_in_docker)
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    result = CliRunner().invoke(
        cli.main,
        ["run", "--input", str(input_path), "--backend", "xed", "--workers", "4"],
    )

    assert result.exit_code == 0
    assert calls == [(input_path, "xed", 64, Path("results_xed.csv"), 4)]


def test_validate_command_uses_docker_runtime(tmp_path: Path, monkeypatch):
    calls = []

    def fake_validate_backend_in_docker(
        input_path: Path,
        backend_name: str,
        exec_mode: int,
        output_path: Path | None = None,
        *,
        workers: int,
    ) -> None:
        calls.append((input_path, backend_name, exec_mode, output_path, workers))

    monkeypatch.setattr(cli, "validate_backend_in_docker", fake_validate_backend_in_docker)
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")
    output_path = tmp_path / "failures.json"

    result = CliRunner().invoke(
        cli.main,
        [
            "validate",
            "--input",
            str(input_path),
            "--backend",
            "xed",
            "--exec-mode",
            "64",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert calls == [(input_path, "xed", 64, output_path, 1)]


def test_validate_command_passes_worker_count(tmp_path: Path, monkeypatch):
    calls = []

    def fake_validate_backend_in_docker(
        input_path: Path,
        backend_name: str,
        exec_mode: int,
        output_path: Path | None = None,
        *,
        workers: int,
    ) -> None:
        calls.append((input_path, backend_name, exec_mode, output_path, workers))

    monkeypatch.setattr(cli, "validate_backend_in_docker", fake_validate_backend_in_docker)
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    result = CliRunner().invoke(
        cli.main,
        [
            "validate",
            "--input",
            str(input_path),
            "--backend",
            "xed",
            "--workers",
            "3",
        ],
    )

    assert result.exit_code == 0
    assert calls == [(input_path, "xed", 64, None, 3)]


def test_normalize_command_merges_sharded_campaign_csvs(tmp_path: Path):
    header = ["insn", "length", "exit-type"]
    for name, rows in {
        "results_2.csv": [["0f0b", "2", "invalid-opcode"]],
        "results_10.csv": [["cc", "1", "interrupt"]],
        "results_1.csv": [["90", "1", "vmexit"]],
        "invalid_instructions_2.csv": [["0f0b", "2", "invalid-opcode"]],
        "invalid_instructions_1.csv": [["0f3f", "2", "invalid-opcode"]],
    }.items():
        with (tmp_path / name).open("w", newline="", encoding="ascii") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)

    result = CliRunner().invoke(cli.main, ["normalize", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / "results.csv").exists()
    assert (tmp_path / "invalid_instructions.csv").exists()
    assert not (tmp_path / "results_1.csv").exists()
    assert not (tmp_path / "results_2.csv").exists()
    assert not (tmp_path / "results_10.csv").exists()
    assert not (tmp_path / "invalid_instructions_1.csv").exists()
    assert not (tmp_path / "invalid_instructions_2.csv").exists()

    with (tmp_path / "results.csv").open("r", newline="", encoding="ascii") as handle:
        rows = list(csv.reader(handle))
    assert rows == [
        header,
        ["90", "1", "vmexit"],
        ["0f0b", "2", "invalid-opcode"],
        ["cc", "1", "interrupt"],
    ]

    with (tmp_path / "invalid_instructions.csv").open("r", newline="", encoding="ascii") as handle:
        rows = list(csv.reader(handle))
    assert rows == [
        header,
        ["0f3f", "2", "invalid-opcode"],
        ["0f0b", "2", "invalid-opcode"],
    ]


def test_normalize_command_fails_when_campaign_has_no_matching_shards(tmp_path: Path):
    result = CliRunner().invoke(cli.main, ["normalize", str(tmp_path)])

    assert result.exit_code != 0
    assert "No shard files found" in result.output


def test_normalize_command_refuses_existing_unified_outputs(tmp_path: Path):
    (tmp_path / "results_1.csv").write_text("insn,length,exit-type\n90,1,vmexit\n", encoding="ascii")
    (tmp_path / "invalid_instructions_1.csv").write_text(
        "insn,length,exit-type\n0f0b,2,invalid-opcode\n",
        encoding="ascii",
    )
    (tmp_path / "results.csv").write_text("existing\n", encoding="ascii")

    result = CliRunner().invoke(cli.main, ["normalize", str(tmp_path)])

    assert result.exit_code != 0
    assert "Refusing to overwrite existing normalized file" in result.output
    assert (tmp_path / "results_1.csv").exists()
    assert (tmp_path / "invalid_instructions_1.csv").exists()


def test_normalize_command_merges_only_remaining_shard_family(tmp_path: Path):
    (tmp_path / "results.csv").write_text("insn,length,exit-type\n90,1,vmexit\n", encoding="ascii")
    (tmp_path / "invalid_instructions_1.csv").write_text(
        "insn,length,exit-type\n0f3f,2,invalid-opcode\n",
        encoding="ascii",
    )
    (tmp_path / "invalid_instructions_2.csv").write_text(
        "insn,length,exit-type\n0f0b,2,invalid-opcode\n",
        encoding="ascii",
    )

    result = CliRunner().invoke(cli.main, ["normalize", str(tmp_path)])

    assert result.exit_code == 0
    assert result.output == f"Normalized: {tmp_path / 'invalid_instructions.csv'}\n"
    assert (tmp_path / "results.csv").read_text(encoding="ascii") == "insn,length,exit-type\n90,1,vmexit\n"
    assert (tmp_path / "invalid_instructions.csv").read_text(encoding="ascii") == (
        "insn,length,exit-type\n"
        "0f3f,2,invalid-opcode\n"
        "0f0b,2,invalid-opcode\n"
    )
    assert not (tmp_path / "invalid_instructions_1.csv").exists()
    assert not (tmp_path / "invalid_instructions_2.csv").exists()
