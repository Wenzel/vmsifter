"""Tests for CLI orchestration behavior."""

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

    def fake_run_backend_in_docker(input_path: Path, backend_name: str, exec_mode: int, output_path: Path) -> None:
        calls.append((input_path, backend_name, exec_mode, output_path))

    monkeypatch.setattr(cli, "run_backend_in_docker", fake_run_backend_in_docker)
    input_path = tmp_path / "catalog.csv"
    input_path.write_text("insn\n90\n", encoding="ascii")

    result = CliRunner().invoke(
        cli.main,
        ["run", "--input", str(input_path), "--backend", "xed", "--exec-mode", "64"],
    )

    assert result.exit_code == 0
    assert calls == [(input_path, "xed", 64, Path("results_xed.csv"))]


def test_validate_command_uses_docker_runtime(tmp_path: Path, monkeypatch):
    calls = []

    def fake_validate_backend_in_docker(
        input_path: Path,
        backend_name: str,
        exec_mode: int,
        output_path: Path | None = None,
    ) -> None:
        calls.append((input_path, backend_name, exec_mode, output_path))

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
    assert calls == [(input_path, "xed", 64, output_path)]
