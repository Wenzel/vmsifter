"""CSV reader -> backend.process() -> CSV writer."""

import csv
import json
import logging
from pathlib import Path

import rich.progress

from bench.schema import Backend

logger = logging.getLogger(__name__)

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
    logger.info("Processing %s → %s (%d-bit)", input_path, output_path, exec_mode)
    _process(input_path, backend, exec_mode, output_path)


def _process(
    input_path: Path,
    backend: Backend,
    exec_mode: int,
    output_path: Path,
) -> None:
    with (
        rich.progress.open(input_path, "r", description="Processing") as inf,
        open(output_path, "w", newline="") as outf,
    ):
        reader = csv.DictReader(inf)
        if "insn" not in (reader.fieldnames or []):
            logger.error("Input CSV missing 'insn' column")
            raise SystemExit(1)

        writer = csv.DictWriter(outf, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()

        for row in reader:
            insn_hex = row["insn"].strip()
            if not insn_hex:
                continue
            insn_bytes = bytes.fromhex(insn_hex)
            result = backend.process(insn_bytes)
            logger.debug("insn=%s valid=%s len=%s", insn_hex, result.valid, result.length)

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
