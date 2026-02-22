# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from __future__ import annotations

import logging
from typing import Any, Dict

from attrs import define

from vmsifter.fuzzer.split import DonorCandidate, select_best_donor


@define
class WorkerSlot:
    """Tracks the IPC handles for one worker."""

    worker_id: int
    idle_event: Any  # multiprocessing.Event or Manager().Event() proxy
    split_event: Any  # multiprocessing.Event or Manager().Event() proxy
    original_range_size: int
    active: bool = True


class WorkScheduler:
    """Coordinates dynamic work redistribution.

    Decoupled from executor/injector/socket -- operates only on Events and Queue.
    Testable without any Xen dependencies.
    """

    def __init__(self, work_queue: Any):
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._work_queue = work_queue
        self._slots: Dict[int, WorkerSlot] = {}

    def register_worker(
        self,
        worker_id: int,
        idle_event: Any,
        split_event: Any,
        range_size: int,
    ) -> None:
        self._slots[worker_id] = WorkerSlot(
            worker_id=worker_id,
            idle_event=idle_event,
            split_event=split_event,
            original_range_size=range_size,
        )

    def unregister_worker(self, worker_id: int) -> None:
        self._slots.pop(worker_id, None)

    def poll_and_redistribute(self) -> None:
        """Check for idle workers and trigger splits. Called periodically by executor."""
        idle_slots = []
        for slot in list(self._slots.values()):
            if slot.active and slot.idle_event.is_set():
                idle_slots.append(slot)

        if not idle_slots:
            return

        # Check if any active worker is still busy (potential donor)
        has_busy = any(s.active and not s.idle_event.is_set() for s in self._slots.values())

        for slot in idle_slots:
            if has_busy:
                self._handle_idle(slot)
            else:
                # All active workers are idle -- no donors possible.
                # Send sentinel to unblock idle workers.
                self._logger.info("No busy workers remain, sending stop to Worker %s", slot.worker_id)
                self._work_queue.put(None)
                slot.active = False

    def _handle_idle(self, idle_slot: WorkerSlot) -> None:
        candidates = [
            DonorCandidate(s.worker_id, s.original_range_size)
            for s in self._slots.values()
            if s.active and not s.idle_event.is_set()
        ]
        donor_id = select_best_donor(candidates, exclude_id=idle_slot.worker_id)
        if donor_id is None:
            self._logger.info("No donor available for Worker %s", idle_slot.worker_id)
            return

        donor_slot = self._slots[donor_id]
        self._logger.info(
            "Requesting split from Worker %s for idle Worker %s",
            donor_slot.worker_id,
            idle_slot.worker_id,
        )
        donor_slot.split_event.set()

    def mark_done(self, worker_id: int) -> None:
        slot = self._slots.get(worker_id)
        if slot:
            slot.active = False
