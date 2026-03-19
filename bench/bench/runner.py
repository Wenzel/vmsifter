"""CSV reader -> backend.process() -> CSV writer."""

import csv
import json
import sys
from pathlib import Path

from bench.schema import Backend

OUTPUT_COLUMNS = [
    "insn",
    "valid",
    "length",
    "exit_type",
    "reg_delta",
    "backend",
    "exec_mode",
    "misc",
]


def run(
    input_path: Path,
    backend: Backend,
    exec_mode: int,
    output_path: Path,
) -> None:
    """Read input CSV, process each instruction through backend, write output CSV."""
    _process(input_path, backend, exec_mode, output_path)


def _process(
    input_path: Path,
    backend: Backend,
    exec_mode: int,
    output_path: Path,
) -> None:
    with (
        open(input_path, newline="") as inf,
        open(output_path, "w", newline="") as outf,
    ):
        reader = csv.DictReader(inf)
        if "insn" not in (reader.fieldnames or []):
            print(f"Error: input CSV missing 'insn' column", file=sys.stderr)
            raise SystemExit(1)

        writer = csv.DictWriter(outf, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()

        for row in reader:
            insn_hex = row["insn"].strip()
            if not insn_hex:
                continue
            insn_bytes = bytes.fromhex(insn_hex)
            result = backend.process(insn_bytes)

            writer.writerow({
                "insn": insn_hex,
                "valid": result.valid,
                "length": result.length if result.length is not None else "",
                "exit_type": result.exit_type,
                "reg_delta": result.reg_delta or "",
                "backend": backend.name,
                "exec_mode": exec_mode,
                "misc": json.dumps(result.misc) if result.misc else "",
            })
