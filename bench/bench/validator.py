"""Reference validation runner."""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path

import rich.progress

from bench.schema import Backend, ReferenceRow

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ValidationSummary:
    """Aggregate validation counters for a run."""

    total_rows: int
    comparable_rows: int
    discrepant_rows: int
    issue_count: int


def validate(input_path: Path, backend: Backend) -> ValidationSummary:
    """Read an input CSV, validate it against a backend, and log discrepancies."""
    total_rows = 0
    comparable_rows = 0
    discrepant_rows = 0
    issue_count = 0

    with rich.progress.open(input_path, "r", description="Validating") as inf:
        reader = csv.DictReader(inf)
        if "insn" not in (reader.fieldnames or []):
            logger.error("Input CSV missing 'insn' column")
            raise SystemExit(1)

        for row in reader:
            insn_hex = row["insn"].strip()
            if not insn_hex:
                continue

            total_rows += 1
            reference = ReferenceRow.from_csv_row(row)
            result = backend.process(reference.insn)
            report = backend.validate(reference, result)
            if not report.comparable:
                continue

            comparable_rows += 1
            if report.ok:
                continue

            discrepant_rows += 1
            issue_count += len(report.issues)
            for issue in report.issues:
                logger.error(
                    "insn=%s field=%s expected=%r actual=%r: %s",
                    insn_hex,
                    issue.field,
                    issue.expected,
                    issue.actual,
                    issue.message,
                )

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
    return summary
