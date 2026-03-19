"""Tests for diff module."""

import csv
from pathlib import Path

from bench.diff import diff


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


FIELDS = ["insn", "valid", "length", "exit_type"]


def test_identical_csvs_no_diffs(tmp_path: Path):
    rows = [
        {"insn": "90", "valid": "True", "length": "1", "exit_type": "valid"},
        {"insn": "0f0b", "valid": "True", "length": "2", "exit_type": "valid"},
    ]
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, rows, FIELDS)
    _write_csv(right, rows, FIELDS)

    out = tmp_path / "diff.csv"
    count = diff(left, right, out)
    assert count == 0


def test_different_validity(tmp_path: Path):
    left_rows = [
        {"insn": "90", "valid": "True", "length": "1", "exit_type": "valid"},
    ]
    right_rows = [
        {"insn": "90", "valid": "False", "length": "", "exit_type": "invalid"},
    ]
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, left_rows, FIELDS)
    _write_csv(right, right_rows, FIELDS)

    out = tmp_path / "diff.csv"
    count = diff(left, right, out)
    assert count == 1

    with open(out) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["valid_left"] == "True"
    assert rows[0]["valid_right"] == "False"


def test_length_difference_only(tmp_path: Path):
    left_rows = [
        {"insn": "cc", "valid": "True", "length": "1", "exit_type": "valid"},
    ]
    right_rows = [
        {"insn": "cc", "valid": "True", "length": "2", "exit_type": "valid"},
    ]
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, left_rows, FIELDS)
    _write_csv(right, right_rows, FIELDS)

    out = tmp_path / "diff.csv"
    count = diff(left, right, out, compare_columns=["length"])
    assert count == 1


def test_custom_compare_columns(tmp_path: Path):
    """When comparing only 'valid', length differences are ignored."""
    left_rows = [
        {"insn": "90", "valid": "True", "length": "1", "exit_type": "valid"},
    ]
    right_rows = [
        {"insn": "90", "valid": "True", "length": "99", "exit_type": "valid"},
    ]
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, left_rows, FIELDS)
    _write_csv(right, right_rows, FIELDS)

    out = tmp_path / "diff.csv"
    count = diff(left, right, out, compare_columns=["valid"])
    assert count == 0


def test_missing_insn_in_right_ignored(tmp_path: Path):
    left_rows = [
        {"insn": "90", "valid": "True", "length": "1", "exit_type": "valid"},
        {"insn": "ff", "valid": "True", "length": "1", "exit_type": "valid"},
    ]
    right_rows = [
        {"insn": "90", "valid": "True", "length": "1", "exit_type": "valid"},
    ]
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, left_rows, FIELDS)
    _write_csv(right, right_rows, FIELDS)

    out = tmp_path / "diff.csv"
    count = diff(left, right, out)
    assert count == 0
