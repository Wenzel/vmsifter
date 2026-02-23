# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from typing import Counter

from vmsifter.fuzzer.split import DonorCandidate, SplitResult, select_best_donor, split_range_midpoint
from vmsifter.worker import WorkerStats, _merge_worker_stats

# ── split_range_midpoint ──


def test_split_midpoint_basic():
    r = split_range_midpoint(0x00, 0xFF)
    assert r == SplitResult(0x00, 0x7F, 0x7F, 0xFF)


def test_split_midpoint_small_range():
    r = split_range_midpoint(0x00, 0x02)
    assert r == SplitResult(0x00, 0x01, 0x01, 0x02)


def test_split_midpoint_too_small():
    assert split_range_midpoint(0xFE, 0xFF) is None


def test_split_midpoint_single_byte():
    assert split_range_midpoint(0x50, 0x50) is None


def test_split_midpoint_equal_halves():
    r = split_range_midpoint(0x10, 0x20)
    assert r is not None
    assert r.lower_end == r.upper_start
    assert r.lower_start == 0x10
    assert r.upper_end == 0x20


def test_split_midpoint_custom_min_size():
    # With min_size=10, a range of 5 should fail
    assert split_range_midpoint(0x00, 0x05, min_size=10) is None
    # With min_size=3, a range of 4 should succeed
    r = split_range_midpoint(0x00, 0x04, min_size=3)
    assert r is not None


# ── select_best_donor ──


def test_select_donor_picks_largest():
    candidates = [DonorCandidate(0, 10), DonorCandidate(1, 50), DonorCandidate(2, 30)]
    assert select_best_donor(candidates, exclude_id=99) == 1


def test_select_donor_excludes_self():
    candidates = [DonorCandidate(0, 100), DonorCandidate(1, 50)]
    assert select_best_donor(candidates, exclude_id=0) == 1


def test_select_donor_none_viable():
    candidates = [DonorCandidate(0, 1)]  # below min_range
    assert select_best_donor(candidates, exclude_id=99) is None


def test_select_donor_empty():
    assert select_best_donor([], exclude_id=0) is None


def test_select_donor_all_excluded():
    candidates = [DonorCandidate(0, 100)]
    assert select_best_donor(candidates, exclude_id=0) is None


def test_select_donor_custom_min_range():
    candidates = [DonorCandidate(0, 5), DonorCandidate(1, 3)]
    assert select_best_donor(candidates, exclude_id=99, min_range=4) == 0
    assert select_best_donor(candidates, exclude_id=99, min_range=6) is None


# ── _merge_worker_stats ──


def test_merge_stats_basic():
    s1 = WorkerStats(nb_insn=100, total_seconds=1.0)
    s2 = WorkerStats(nb_insn=200, total_seconds=2.0)
    merged = _merge_worker_stats([s1, s2])
    assert merged.nb_insn == 300
    assert merged.total_seconds == 3.0


def test_merge_stats_single():
    s = WorkerStats(nb_insn=42, total_seconds=1.5)
    merged = _merge_worker_stats([s])
    assert merged.nb_insn == 42
    assert merged.total_seconds == 1.5


def test_merge_stats_counters():
    s1 = WorkerStats(nb_insn=10, total_seconds=1.0, exitstats=Counter({0: 5, 1: 3}))
    s2 = WorkerStats(nb_insn=20, total_seconds=2.0, exitstats=Counter({0: 2, 2: 7}))
    merged = _merge_worker_stats([s1, s2])
    assert merged.exitstats[0] == 7
    assert merged.exitstats[1] == 3
    assert merged.exitstats[2] == 7


def test_merge_stats_empty():
    merged = _merge_worker_stats([])
    assert merged.nb_insn == 0
    assert merged.total_seconds == 0.0
