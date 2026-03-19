"""Two-CSV join-and-compare on the 'insn' column."""

import csv
import sys
from pathlib import Path

DEFAULT_COMPARE_COLUMNS = ["valid", "length", "exit_type"]


def diff(
    left_path: Path,
    right_path: Path,
    output_path: Path | None,
    compare_columns: list[str] | None = None,
) -> int:
    """Join two CSVs on 'insn' and output rows where compared columns differ.

    Returns the number of differing rows.
    """
    if compare_columns is None:
        compare_columns = DEFAULT_COMPARE_COLUMNS

    right_index = _index_csv(right_path)

    diff_count = 0
    out_fieldnames = ["insn"] + [
        f"{col}_{side}" for col in compare_columns for side in ("left", "right")
    ]

    outf_handle = None
    writer = None

    try:
        if output_path:
            outf_handle = open(output_path, "w", newline="")
        else:
            outf_handle = sys.stdout

        writer = csv.DictWriter(outf_handle, fieldnames=out_fieldnames)
        writer.writeheader()

        with open(left_path, newline="") as lf:
            reader = csv.DictReader(lf)
            for row in reader:
                insn = row["insn"].strip()
                if insn not in right_index:
                    continue
                right_row = right_index[insn]

                differs = False
                out_row: dict[str, str] = {"insn": insn}
                for col in compare_columns:
                    lval = row.get(col, "").strip()
                    rval = right_row.get(col, "").strip()
                    out_row[f"{col}_left"] = lval
                    out_row[f"{col}_right"] = rval
                    if lval != rval:
                        differs = True

                if differs:
                    writer.writerow(out_row)
                    diff_count += 1
    finally:
        if output_path and outf_handle:
            outf_handle.close()

    return diff_count


def _index_csv(path: Path) -> dict[str, dict[str, str]]:
    """Read a CSV into a dict keyed by the 'insn' column."""
    index: dict[str, dict[str, str]] = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            insn = row["insn"].strip()
            index[insn] = row
    return index
