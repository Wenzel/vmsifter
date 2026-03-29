"""Helpers for normalizing sharded campaign CSV outputs."""

import csv
import re
from pathlib import Path


_RESULTS_PATTERN = re.compile(r"^results_(\d+)\.csv$")
_INVALID_PATTERN = re.compile(r"^invalid_instructions_(\d+)\.csv$")


def normalize_campaign_dir(campaign_dir: Path) -> dict[str, Path]:
    """Merge sharded campaign CSVs into unified files in-place."""
    outputs = {
        "results": campaign_dir / "results.csv",
        "invalid_instructions": campaign_dir / "invalid_instructions.csv",
    }
    existing_outputs = [path for path in outputs.values() if path.exists()]
    if existing_outputs:
        names = ", ".join(str(path) for path in existing_outputs)
        raise ValueError(f"Refusing to overwrite existing normalized file(s): {names}")

    outputs["results"] = _merge_shards(campaign_dir, _RESULTS_PATTERN, outputs["results"])
    outputs["invalid_instructions"] = _merge_shards(campaign_dir, _INVALID_PATTERN, outputs["invalid_instructions"])
    return outputs


def _merge_shards(campaign_dir: Path, pattern: re.Pattern[str], output_path: Path) -> Path:
    shard_paths = sorted(
        (
            path
            for path in campaign_dir.iterdir()
            if path.is_file() and pattern.fullmatch(path.name) is not None
        ),
        key=lambda path: int(pattern.fullmatch(path.name).group(1)),
    )
    if not shard_paths:
        raise ValueError(
            f"No shard files matching {pattern.pattern!r} found in {campaign_dir}"
        )

    header: list[str] | None = None
    try:
        with output_path.open("w", newline="", encoding="ascii") as output_file:
            writer = csv.writer(output_file)
            for shard_path in shard_paths:
                with shard_path.open("r", newline="", encoding="ascii") as shard_file:
                    reader = csv.reader(shard_file)
                    shard_header = next(reader, None)
                    if shard_header is not None:
                        if header is None:
                            header = shard_header
                            writer.writerow(header)
                        elif shard_header != header:
                            raise ValueError(f"Header mismatch in {shard_path}")

                        for row in reader:
                            writer.writerow(row)

                output_file.flush()
                shard_path.unlink()
    except Exception:
        if output_path.exists():
            output_path.unlink()
        raise

    if header is None:
        if output_path.exists():
            output_path.unlink()
        raise ValueError(f"All shard files were empty in {campaign_dir}")

    return output_path
