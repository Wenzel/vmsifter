"""Tests for shard normalization helpers."""

import csv
from pathlib import Path

from bench.normalize import normalize_campaign_dir


def test_normalize_campaign_dir_reports_byte_progress(tmp_path: Path):
    header = ["insn", "length", "exit-type"]
    files = {
        "results_1.csv": [["90", "1", "vmexit"]],
        "results_2.csv": [["cc", "1", "interrupt"]],
        "invalid_instructions_1.csv": [["0f0b", "2", "invalid-opcode"]],
    }
    expected_totals: dict[str, int] = {}

    for name, rows in files.items():
        path = tmp_path / name
        with path.open("w", newline="", encoding="ascii") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
        family = "results" if name.startswith("results_") else "invalid_instructions"
        expected_totals[family] = expected_totals.get(family, 0) + path.stat().st_size

    updates: list[tuple[str, int, int]] = []

    def record_update(name: str, current: int, total: int) -> None:
        updates.append((name, current, total))

    outputs = normalize_campaign_dir(tmp_path, progress_callback=record_update)

    assert outputs == {
        "results": tmp_path / "results.csv",
        "invalid_instructions": tmp_path / "invalid_instructions.csv",
    }

    first_updates: dict[str, tuple[str, int, int]] = {}
    final_updates: dict[str, tuple[str, int, int]] = {}
    for update in updates:
        first_updates.setdefault(update[0], update)
        final_updates[update[0]] = update

    assert first_updates == {
        "results": ("results", 0, expected_totals["results"]),
        "invalid_instructions": ("invalid_instructions", 0, expected_totals["invalid_instructions"]),
    }
    assert final_updates == {
        "results": ("results", expected_totals["results"], expected_totals["results"]),
        "invalid_instructions": (
            "invalid_instructions",
            expected_totals["invalid_instructions"],
            expected_totals["invalid_instructions"],
        ),
    }


def test_normalize_campaign_dir_preflights_existing_outputs(tmp_path: Path):
    (tmp_path / "results_1.csv").write_text("insn,length,exit-type\n90,1,vmexit\n", encoding="ascii")
    (tmp_path / "invalid_instructions_1.csv").write_text(
        "insn,length,exit-type\n0f0b,2,invalid-opcode\n",
        encoding="ascii",
    )
    (tmp_path / "invalid_instructions.csv").write_text("existing\n", encoding="ascii")

    try:
        normalize_campaign_dir(tmp_path)
    except ValueError as exc:
        assert "Refusing to overwrite existing normalized file" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("normalize_campaign_dir should have raised ValueError")

    assert (tmp_path / "results_1.csv").exists()
    assert (tmp_path / "invalid_instructions_1.csv").exists()
    assert not (tmp_path / "results.csv").exists()
