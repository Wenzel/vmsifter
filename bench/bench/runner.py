"""CSV reader -> backend.process() -> CSV writer."""

import csv
import json
import logging
from contextlib import contextmanager
from pathlib import Path

import rich.progress

from bench.progress import ByteCountingTextReader, ByteRangeTextReader, ProgressReporter
from bench.schema import Backend, InvalidInstructionHexError, parse_instruction_hex

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
    progress_socket: Path | None = None,
    byte_start: int | None = None,
    byte_end: int | None = None,
) -> None:
    """Read input CSV, process each instruction through backend, write output CSV."""
    logger.info("Processing %s → %s (%d-bit)", input_path, output_path, exec_mode)
    _process(
        input_path,
        backend,
        exec_mode,
        output_path,
        progress_socket=progress_socket,
        byte_start=byte_start,
        byte_end=byte_end,
    )


def _process(
    input_path: Path,
    backend: Backend,
    exec_mode: int,
    output_path: Path,
    *,
    progress_socket: Path | None,
    byte_start: int | None,
    byte_end: int | None,
) -> None:
    fieldnames, data_start = _read_input_header(input_path)
    if "insn" not in fieldnames:
        logger.error("Input CSV missing 'insn' column")
        raise SystemExit(1)

    use_byte_range = byte_start is not None or byte_end is not None
    range_start = data_start if byte_start is None else max(byte_start, data_start)
    range_end = input_path.stat().st_size if byte_end is None else max(byte_end, range_start)
    total_bytes = range_end - range_start if use_byte_range else input_path.stat().st_size

    with (
        _open_input(
            input_path,
            description="Processing",
            progress_socket=progress_socket,
            byte_start=range_start if use_byte_range else None,
            byte_end=range_end if use_byte_range else None,
        ) as inf,
        ProgressReporter(progress_socket, phase="run", every=64 * 1024) as reporter,
        open(output_path, "w", newline="") as outf,
    ):
        reader = csv.DictReader(inf, fieldnames=fieldnames if use_byte_range else None)
        writer = csv.DictWriter(outf, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()

        for row_number, row in enumerate(reader, start=2):
            if progress_socket is not None:
                reporter.report(inf.bytes_read)
            insn_hex = row["insn"].strip()
            if not insn_hex:
                continue
            try:
                insn_bytes = parse_instruction_hex(row)
            except InvalidInstructionHexError as exc:
                if exc.insn_hex == "insn":
                    logger.warning("Skipping embedded CSV header at row %d", row_number)
                    continue
                _log_invalid_input_row(
                    row_number,
                    exc,
                    byte_start=range_start if use_byte_range else None,
                    byte_end=range_end if use_byte_range else None,
                )
                raise SystemExit(1) from exc
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

        if progress_socket is not None:
            reporter.report(total_bytes, force=True, done=True)


def _read_input_header(input_path: Path) -> tuple[list[str], int]:
    """Read the CSV header row and return field names plus the first data offset."""
    with open(input_path, "rb") as raw:
        header = raw.readline()
        data_start = raw.tell()
    if not header:
        logger.error("Input CSV is empty")
        raise SystemExit(1)

    fieldnames = next(csv.reader([header.decode("utf-8").rstrip("\r\n")]), [])
    if not fieldnames:
        logger.error("Input CSV header is empty")
        raise SystemExit(1)
    return fieldnames, data_start


def _log_invalid_input_row(
    row_number: int,
    exc: InvalidInstructionHexError,
    *,
    byte_start: int | None,
    byte_end: int | None,
) -> None:
    """Emit a high-signal error for malformed instruction hex values."""
    if byte_start is None or byte_end is None:
        logger.error(
            "Invalid instruction hex at CSV row %d: insn=%r row=%r",
            row_number,
            exc.insn_hex,
            dict(exc.raw_row),
        )
        return

    logger.error(
        "Invalid instruction hex at CSV row %d within byte range [%d, %d): insn=%r row=%r",
        row_number,
        byte_start,
        byte_end,
        exc.insn_hex,
        dict(exc.raw_row),
    )


@contextmanager
def _open_input(
    input_path: Path,
    *,
    description: str,
    progress_socket: Path | None,
    byte_start: int | None = None,
    byte_end: int | None = None,
):
    """Open an input CSV, keeping Rich progress for direct interactive runs only."""
    if byte_start is not None or byte_end is not None:
        start = 0 if byte_start is None else byte_start
        end = input_path.stat().st_size if byte_end is None else byte_end
        with ByteRangeTextReader(input_path, start, end) as inf:
            yield inf
        return

    if progress_socket is not None:
        with ByteCountingTextReader(input_path) as inf:
            yield inf
        return

    with rich.progress.open(input_path, "r", description=description) as inf:
        yield inf
