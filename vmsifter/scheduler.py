# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from __future__ import annotations

import logging
from typing import Any, Dict, Set, Tuple

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


# Number of poll cycles (× 0.5s each) to wait for a split to complete
# before declaring it failed and trying the next donor.
_SPLIT_GRACE_POLLS = 10  # 5 seconds


class WorkScheduler:
    """Coordinates dynamic work redistribution.

    Decoupled from executor/injector/socket -- operates only on Events and Queue.
    Testable without any Xen dependencies.
    """

    def __init__(self, work_queue: Any):
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._work_queue = work_queue
        self._slots: Dict[int, WorkerSlot] = {}
        # Pending split: idle_worker_id -> (donor_worker_id, polls_remaining)
        self._pending_split: Dict[int, Tuple[int, int]] = {}
        # Donors that failed to produce work: idle_worker_id -> {donor_ids}
        self._failed_donors: Dict[int, Set[int]] = {}

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
        self._pending_split.pop(worker_id, None)
        self._failed_donors.pop(worker_id, None)

    def poll_and_redistribute(self) -> None:
        """Check for idle workers and trigger splits. Called periodically by executor."""
        # Clean up resolved pending splits (idle workers that picked up work)
        for wid in list(self._pending_split):
            slot = self._slots.get(wid)
            if slot is None or not slot.idle_event.is_set():
                self._pending_split.pop(wid, None)
                self._failed_donors.pop(wid, None)

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
        wid = idle_slot.worker_id

        # Check pending split request
        if wid in self._pending_split:
            donor_id, polls_left = self._pending_split[wid]
            donor_slot = self._slots.get(donor_id)
            donor_busy = donor_slot is not None and donor_slot.active and not donor_slot.idle_event.is_set()

            if donor_busy and polls_left > 0:
                # Still waiting for donor to process the split
                self._pending_split[wid] = (donor_id, polls_left - 1)
                return

            # Timed out or donor finished — split produced no work
            del self._pending_split[wid]
            self._failed_donors.setdefault(wid, set()).add(donor_id)
            self._logger.info(
                "Split from Worker %s produced no work for idle Worker %s",
                donor_id,
                wid,
            )

        # Find new donor, excluding previously failed ones
        failed = self._failed_donors.get(wid, set())
        candidates = [
            DonorCandidate(s.worker_id, s.original_range_size)
            for s in self._slots.values()
            if s.active and not s.idle_event.is_set() and s.worker_id not in failed
        ]
        donor_id = select_best_donor(candidates, exclude_id=wid)

        if donor_id is None:
            # No viable donors left — send sentinel so worker exits cleanly
            self._logger.info("No viable donor for Worker %s, sending stop", wid)
            self._work_queue.put(None)
            idle_slot.active = False
            self._failed_donors.pop(wid, None)
            return

        donor_slot = self._slots[donor_id]
        self._logger.info(
            "Requesting split from Worker %s for idle Worker %s",
            donor_id,
            wid,
        )
        donor_slot.split_event.set()
        self._pending_split[wid] = (donor_id, _SPLIT_GRACE_POLLS)

    def mark_done(self, worker_id: int) -> None:
        slot = self._slots.get(worker_id)
        if slot:
            slot.active = False
