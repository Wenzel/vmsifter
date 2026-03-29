"""Helpers for normalizing sharded campaign CSV outputs."""

import csv
import re
from pathlib import Path


_RESULTS_PATTERN = re.compile(r"^results_(\d+)\.csv$")
_INVALID_PATTERN = re.compile(r"^invalid_instructions_(\d+)\.csv$")


def normalize_campaign_dir(campaign_dir: Path) -> dict[str, Path]:
    """Merge sharded campaign CSVs into unified files in-place."""
    shard_groups = {
        "results": _find_shards(campaign_dir, _RESULTS_PATTERN),
        "invalid_instructions": _find_shards(campaign_dir, _INVALID_PATTERN),
    }
    if not any(shard_groups.values()):
        raise ValueError(f"No shard files found in {campaign_dir}")

    outputs: dict[str, Path] = {}
    for name, shard_paths in shard_groups.items():
        if not shard_paths:
            continue

        output_path = campaign_dir / f"{name}.csv"
        if output_path.exists():
            raise ValueError(f"Refusing to overwrite existing normalized file: {output_path}")

        outputs[name] = _merge_shards(shard_paths, output_path)

    return outputs


def _find_shards(campaign_dir: Path, pattern: re.Pattern[str]) -> list[Path]:
    return sorted(
        (
            path
            for path in campaign_dir.iterdir()
            if path.is_file() and pattern.fullmatch(path.name) is not None
        ),
        key=lambda path: int(pattern.fullmatch(path.name).group(1)),
    )


def _merge_shards(shard_paths: list[Path], output_path: Path) -> Path:
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
        raise ValueError(f"All shard files were empty for {output_path.name}")

    return output_path
