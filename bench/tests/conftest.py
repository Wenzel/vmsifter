"""Shared test fixtures."""

import csv
import io
from pathlib import Path

import pytest


# Known x86 instructions for testing:
# 90         -> NOP (length=1)
# 0f1f00     -> multi-byte NOP (length=3)
# 0f0b       -> UD2 (length=2)
KNOWN_INSTRUCTIONS = [
    {"insn": "90", "length": "1", "exit-type": "37", "misc": "", "reg-delta": ""},
    {"insn": "0f1f00", "length": "3", "exit-type": "37", "misc": "", "reg-delta": ""},
    {"insn": "0f0b", "length": "2", "exit-type": "37", "misc": "", "reg-delta": ""},
]


@pytest.fixture
def sample_csv(tmp_path: Path) -> Path:
    """Create a sample VMSifter-format CSV with known instructions."""
    csv_path = tmp_path / "sample.csv"
    fieldnames = ["insn", "length", "exit-type", "misc", "reg-delta"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(KNOWN_INSTRUCTIONS)
    return csv_path


@pytest.fixture
def sample_csv_text() -> str:
    """Return sample CSV as a string."""
    buf = io.StringIO()
    fieldnames = ["insn", "length", "exit-type", "misc", "reg-delta"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(KNOWN_INSTRUCTIONS)
    return buf.getvalue()
