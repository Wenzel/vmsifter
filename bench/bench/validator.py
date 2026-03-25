"""Reference validation runner."""

from __future__ import annotations

import csv
import json
import logging
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

import rich.progress

from bench.progress import ByteCountingTextReader, ByteRangeTextReader, ProgressReporter
from bench.schema import (
    Backend,
    BackendResult,
    InvalidInstructionHexError,
    ParsedExitType,
    ReferenceRow,
    ValidationReport,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ValidationSummary:
    """Aggregate validation counters for a run."""

    total_rows: int
    comparable_rows: int
    discrepant_rows: int
    issue_count: int


@dataclass(frozen=True)
class SerializableReferenceRow:
    """JSON-friendly snapshot of a typed reference row."""

    insn: str
    length: int | None
    exit_type: str
    raw: dict[str, str]
    parsed_exit_type: ParsedExitType

    @classmethod
    def from_reference(cls, reference: ReferenceRow) -> "SerializableReferenceRow":
        return cls(
            insn=reference.insn.hex(),
            length=reference.length,
            exit_type=reference.exit_type,
            raw=dict(reference.raw),
            parsed_exit_type=reference.parsed_exit_type,
        )


@dataclass(frozen=True)
class ValidationFailure:
    """JSON-friendly representation of one validation failure."""

    reference: SerializableReferenceRow
    result: BackendResult
    report: ValidationReport


def validate(
    input_path: Path,
    backend: Backend,
    output_path: Path | None = None,
    progress_socket: Path | None = None,
    byte_start: int | None = None,
    byte_end: int | None = None,
) -> ValidationSummary:
    """Read an input CSV, validate it against a backend, and log discrepancies."""
    fieldnames, data_start = _read_input_header(input_path)
    if "insn" not in fieldnames:
        logger.error("Input CSV missing 'insn' column")
        raise SystemExit(1)

    use_byte_range = byte_start is not None or byte_end is not None
    range_start = data_start if byte_start is None else max(byte_start, data_start)
    range_end = input_path.stat().st_size if byte_end is None else max(byte_end, range_start)
    total_bytes = range_end - range_start if use_byte_range else input_path.stat().st_size
    total_rows = 0
    comparable_rows = 0
    discrepant_rows = 0
    issue_count = 0
    failures: list[ValidationFailure] = []

    with (
        _open_input(
            input_path,
            description="Validating",
            progress_socket=progress_socket,
            byte_start=range_start if use_byte_range else None,
            byte_end=range_end if use_byte_range else None,
        ) as inf,
        ProgressReporter(progress_socket, phase="validate", every=64 * 1024) as reporter,
    ):
        reader = csv.DictReader(inf, fieldnames=fieldnames if use_byte_range else None)

        for row_number, row in enumerate(reader, start=2):
            if progress_socket is not None:
                reporter.report(inf.bytes_read)
            insn_hex = row["insn"].strip()
            if not insn_hex:
                continue

            total_rows += 1
            try:
                reference = ReferenceRow.from_csv_row(row)
            except InvalidInstructionHexError as exc:
                _log_invalid_input_row(
                    row_number,
                    exc,
                    byte_start=range_start if use_byte_range else None,
                    byte_end=range_end if use_byte_range else None,
                )
                raise SystemExit(1) from exc
            result = backend.process(reference.insn)
            report = backend.validate(reference, result)
            if not report.comparable:
                continue

            comparable_rows += 1
            if report.ok:
                continue

            discrepant_rows += 1
            issue_count += len(report.issues)
            failures.append(ValidationFailure(
                reference=SerializableReferenceRow.from_reference(reference),
                result=result,
                report=report,
            ))
            for issue in report.issues:
                logger.error(
                    "insn=%s field=%s expected=%r actual=%r: %s",
                    insn_hex,
                    issue.field,
                    issue.expected,
                    issue.actual,
                    issue.message,
                )

        if progress_socket is not None:
            reporter.report(total_bytes, force=True, done=True)

    summary = ValidationSummary(
        total_rows=total_rows,
        comparable_rows=comparable_rows,
        discrepant_rows=discrepant_rows,
        issue_count=issue_count,
    )
    logger.info(
        "Validated %d row(s), comparable=%d, discrepant=%d, issues=%d",
        summary.total_rows,
        summary.comparable_rows,
        summary.discrepant_rows,
        summary.issue_count,
    )
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as outf:
            json.dump([asdict(failure) for failure in failures], outf, indent=2)
    return summary


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
