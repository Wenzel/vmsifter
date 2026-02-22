# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import multiprocessing

from vmsifter.scheduler import WorkScheduler


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
