# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import multiprocessing

from vmsifter.scheduler import _SPLIT_GRACE_POLLS, WorkScheduler


def test_scheduler_detects_idle_and_signals_donor():
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)

    idle_evt_0.set()  # Worker 0 is idle
    scheduler.poll_and_redistribute()

    assert split_evt_1.is_set()  # Worker 1 (larger range) was asked to split
    assert not split_evt_0.is_set()


def test_scheduler_no_donor_available():
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt = multiprocessing.Event()
    split_evt = multiprocessing.Event()
    scheduler.register_worker(0, idle_evt, split_evt, range_size=1)  # too small

    idle_evt.set()
    scheduler.poll_and_redistribute()
    assert not split_evt.is_set()  # no one to split


def test_scheduler_unregister():
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)
    evt = multiprocessing.Event()
    scheduler.register_worker(0, evt, evt, range_size=10)
    scheduler.unregister_worker(0)
    assert len(scheduler._slots) == 0


def test_scheduler_mark_done():
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt = multiprocessing.Event()
    split_evt = multiprocessing.Event()
    scheduler.register_worker(0, idle_evt, split_evt, range_size=50)

    scheduler.mark_done(0)
    assert not scheduler._slots[0].active


def test_scheduler_skips_inactive_workers():
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)

    # Mark worker 1 as done (inactive)
    scheduler.mark_done(1)

    idle_evt_0.set()  # Worker 0 is idle
    scheduler.poll_and_redistribute()

    # Worker 1 is inactive, should not be asked to split
    assert not split_evt_1.is_set()


def test_scheduler_multiple_idle_workers():
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()
    idle_evt_2 = multiprocessing.Event()
    split_evt_2 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)
    scheduler.register_worker(2, idle_evt_2, split_evt_2, range_size=100)

    # Workers 0 and 1 are idle, only worker 2 is busy
    idle_evt_0.set()
    idle_evt_1.set()
    scheduler.poll_and_redistribute()

    # Worker 2 (largest range, still active) should be asked to split
    assert split_evt_2.is_set()


# ── Pending split tracking: no log spam ──


def test_scheduler_does_not_repeat_split_request():
    """Once a split is requested, subsequent polls should NOT re-request."""
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)

    idle_evt_0.set()  # Worker 0 is idle

    # First poll: should request split
    scheduler.poll_and_redistribute()
    assert split_evt_1.is_set()
    assert 0 in scheduler._pending_split

    # Simulate donor hasn't processed yet (split_event still set)
    # Second poll: should NOT re-request, just wait
    scheduler.poll_and_redistribute()
    # pending_split still tracked, polls decremented
    assert 0 in scheduler._pending_split


def test_scheduler_clears_pending_on_success():
    """When an idle worker picks up work (idle_event cleared), pending state is cleaned."""
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)

    idle_evt_0.set()
    scheduler.poll_and_redistribute()
    assert 0 in scheduler._pending_split

    # Simulate: worker 0 picked up work
    idle_evt_0.clear()
    scheduler.poll_and_redistribute()
    assert 0 not in scheduler._pending_split


def test_scheduler_tries_next_donor_after_failure():
    """After grace period expires, scheduler marks donor as failed and tries next."""
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()
    idle_evt_2 = multiprocessing.Event()
    split_evt_2 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)
    scheduler.register_worker(2, idle_evt_2, split_evt_2, range_size=30)

    idle_evt_0.set()  # Worker 0 is idle

    # First poll: requests split from Worker 1 (largest range)
    scheduler.poll_and_redistribute()
    assert split_evt_1.is_set()
    split_evt_1.clear()  # Simulate: donor processed but split_remaining returned None

    # Exhaust grace period (+1: N polls count down, then next poll triggers fallthrough)
    for _ in range(_SPLIT_GRACE_POLLS + 1):
        scheduler.poll_and_redistribute()

    # Now it should have tried Worker 2 (next viable donor)
    assert split_evt_2.is_set()
    assert 1 in scheduler._failed_donors.get(0, set())


def test_scheduler_sends_sentinel_when_all_donors_fail():
    """When all donors have failed, send a sentinel to the idle worker."""
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)

    idle_evt_0.set()

    # Request split from Worker 1
    scheduler.poll_and_redistribute()
    split_evt_1.clear()

    # Exhaust grace period — Worker 1 failed (+1 for fallthrough)
    for _ in range(_SPLIT_GRACE_POLLS + 1):
        scheduler.poll_and_redistribute()

    # No more donors: sentinel should be on queue, worker 0 deactivated
    assert not scheduler._slots[0].active
    sentinel = work_queue.get(timeout=1)
    assert sentinel is None


def test_scheduler_all_idle_sends_sentinels():
    """When all workers are idle, send sentinels to all of them."""
    work_queue = multiprocessing.Queue()
    scheduler = WorkScheduler(work_queue)

    idle_evt_0 = multiprocessing.Event()
    split_evt_0 = multiprocessing.Event()
    idle_evt_1 = multiprocessing.Event()
    split_evt_1 = multiprocessing.Event()

    scheduler.register_worker(0, idle_evt_0, split_evt_0, range_size=10)
    scheduler.register_worker(1, idle_evt_1, split_evt_1, range_size=50)

    idle_evt_0.set()
    idle_evt_1.set()
    scheduler.poll_and_redistribute()

    # Both should get sentinels
    assert not scheduler._slots[0].active
    assert not scheduler._slots[1].active
    assert work_queue.get(timeout=1) is None
    assert work_queue.get(timeout=1) is None
