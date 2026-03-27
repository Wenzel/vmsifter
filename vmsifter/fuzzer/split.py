# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from typing import Optional, Sequence

from attrs import define


@define(frozen=True)
class SplitResult:
    """Immutable result of a range split."""

    lower_start: int
    lower_end: int
    upper_start: int
    upper_end: int


def split_range_midpoint(current: int, end: int, min_size: int = 2) -> Optional[SplitResult]:
    """Split a byte range [current, end] at the midpoint.

    Returns SplitResult or None if range too small.
    Pure function, no side effects.
    """
    if end - current < min_size:
        return None
    mid = current + (end - current) // 2
    return SplitResult(
        lower_start=current,
        lower_end=mid,
        upper_start=mid,
        upper_end=end,
    )


@define(frozen=True)
class DonorCandidate:
    """Immutable snapshot of a worker's state for donor selection."""

    worker_id: int
    remaining_range: int


def select_best_donor(
    candidates: Sequence[DonorCandidate],
    exclude_id: int,
    min_range: int = 2,
) -> Optional[int]:
    """Pick the worker with the most remaining work.

    Returns worker_id or None if no viable donor.
    Pure function, no side effects.
    """
    viable = [c for c in candidates if c.worker_id != exclude_id and c.remaining_range >= min_range]
    if not viable:
        return None
    return max(viable, key=lambda c: c.remaining_range).worker_id
