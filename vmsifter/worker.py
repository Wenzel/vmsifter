# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from __future__ import annotations

import logging
import queue as queue_mod
from datetime import datetime
from itertools import count
from pathlib import Path
from typing import Any, Counter, List

from attr import define, field

from vmsifter.config import settings
from vmsifter.fuzzer.types import AbstractInsnGenerator, ResultView, Splittable
from vmsifter.injector.types import InjectorResultMessage
from vmsifter.output import CSVOutput
from vmsifter.utils import pformat
from vmsifter.utils.protected_manager import ProtectedContextManager


@define(slots=True)
class WorkerStats:
    nb_insn: int
    total_seconds: float
    general: Counter = field(factory=Counter)
    exitstats: Counter = field(factory=Counter)
    interruptstats: Counter = field(factory=Counter)

    @property
    def exec_speed(self) -> int:
        if self.total_seconds == 0:
            return 0
        return int(self.nb_insn / self.total_seconds)


def _merge_worker_stats(stats_list: List[WorkerStats]) -> WorkerStats:
    """Merge stats from multiple ranges processed by a single worker. Pure function."""
    total_insn = sum(s.nb_insn for s in stats_list)
    total_seconds = sum(s.total_seconds for s in stats_list)
    general: Counter = Counter()
    exitstats: Counter = Counter()
    interruptstats: Counter = Counter()
    for s in stats_list:
        general += s.general
        exitstats += s.exitstats
        interruptstats += s.interruptstats
    return WorkerStats(
        nb_insn=total_insn,
        total_seconds=total_seconds,
        general=general,
        exitstats=exitstats,
        interruptstats=interruptstats,
    )


class Worker(ProtectedContextManager):
    def __init__(self, id: int, fuzzer: AbstractInsnGenerator) -> None:
        super().__init__()
        self._id = id
        self._fuzzer = fuzzer

        # stats
        self._stats: Counter = Counter()
        self._exitstats: Counter = Counter()
        self._interruptstats: Counter = Counter()
        # workaround dynaconf perf issue
        self._cache_dyna_insn_buf_size = settings.insn_buf_size
        self._cache_dyna_refresh_frequency = settings.refresh_frequency

    def init_logger_worker(self):
        """Remove exiting stdout logging and log to a file"""
        self._logger = logging.getLogger()
        # remove existing stdout handler
        while self._logger.handlers:
            self._logger.handlers.pop()
        # add File handler
        self._workdir_path = Path(settings.workdir)
        file_handler = logging.FileHandler(self._workdir_path / f"worker_{self._id}.log")
        file_handler.setFormatter(settings.logging.format)
        self._logger.addHandler(file_handler)

    @property
    def id(self):
        return self._id

    @property
    def fuzzer(self):
        return self._fuzzer

    def _send_instruction(self, cli_sock, index, new_insn):
        """Send instruction to the injector"""
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("[%d]Sending buffer %s", index, new_insn.hex())
        try:
            cli_sock.send(new_insn)
        except (BrokenPipeError, ConnectionResetError) as e:
            raise EOFError("Injector has closed the communication") from e

    def _recv_into(self, cli_sock, recv_view):
        try:
            num_bytes: int = cli_sock.recv_into(recv_view)
            if num_bytes == 0:
                raise EOFError("Injector has closed the communication")
        except ConnectionResetError as e:
            raise EOFError("Injector has closed the communication") from e

    def handle_client(
        self,
        cli_sock,
        cli_addr,
        work_queue: Any = None,
        idle_event: Any = None,
        split_event: Any = None,
    ) -> WorkerStats:
        """Run fuzzer ranges until no more work is available.

        Without queue/events: legacy single-range behavior (unchanged).
        With queue/events: runs current range, then waits for new work from scheduler.
        """
        self.init_logger_worker()
        self._logger.debug("Injector connected: %s", cli_addr)

        # Pre-allocate ONCE before loop -- reused across all ranges
        recv_buf = bytearray(InjectorResultMessage.size())
        recv_view = memoryview(recv_buf)
        msg = InjectorResultMessage.from_buffer(recv_buf)
        result_view = ResultView(msg)

        # Wait for initial injector handshake (once, reused across ranges)
        self._recv_into(cli_sock, recv_view)
        result_view.invalidate()

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("[0]Recv msg %s", pformat(msg.repr_recv()))

        all_stats: List[WorkerStats] = []

        while True:
            stats = self._run_single_range(
                cli_sock,
                recv_view,
                msg,
                result_view,
                work_queue,
                split_event,
            )
            all_stats.append(stats)

            # Legacy mode (no queue): exit after single range
            if work_queue is None or idle_event is None:
                break

            # Signal idle, poll for new work with short timeouts
            # (short timeouts keep the worker responsive to CTRL-C;
            #  broad except catches Manager proxy errors on shutdown)
            self._logger.info("Range exhausted, waiting for new work...")
            try:
                idle_event.set()
            except Exception:
                break
            got_work = False
            for _ in range(120):  # 120 * 0.5s = 60s max wait
                try:
                    new_fuzzer = work_queue.get(timeout=0.5)
                except queue_mod.Empty:
                    continue
                except Exception:
                    # Manager died (CTRL-C shutdown) — exit cleanly
                    break
                if new_fuzzer is None:
                    # Sentinel: scheduler says no more work available
                    break
                self._fuzzer = new_fuzzer
                try:
                    idle_event.clear()
                except Exception:
                    pass
                self._logger.info("Picked up new range: %s", self._fuzzer.str_fuzzing_range())
                got_work = True
                break
            if not got_work:
                self._logger.info("No more work available, exiting.")
                break

        return _merge_worker_stats(all_stats)

    def _run_single_range(
        self,
        cli_sock,
        recv_view: memoryview,
        msg: InjectorResultMessage,
        result_view: ResultView,
        work_queue: Any = None,
        split_event: Any = None,
    ) -> WorkerStats:
        """Execute one fuzzer range to completion. Inner logic extracted from handle_client."""
        # Reset per-range stats
        self._stats = Counter()
        self._exitstats = Counter()
        self._interruptstats = Counter()

        with CSVOutput(self._id) as csvlog:
            self._logger.info("Fuzzing range: %s", self.fuzzer.str_fuzzing_range())

            gen = self.fuzzer.gen()

            error = None

            try:
                begin = datetime.now()
                cur_begin = begin
                first_iteration = True
                for index in count(start=1):
                    try:
                        if first_iteration:
                            new_insn = next(gen)
                            first_iteration = False
                        else:
                            new_insn = gen.send(result_view)
                    except StopIteration:
                        if result_view.final is not None:
                            csvlog.log(result_view.final)
                        break

                    if len(new_insn) > self._cache_dyna_insn_buf_size:
                        self._logger.debug(
                            "[%d]Fuzzer generated instruction larger then our current limit, "
                            "forgot to increase INSN_BUF_SIZE?",
                            index,
                        )
                        break

                    # previous execution result has been processed by fuzzer
                    # check for final and log
                    if result_view.final is not None:
                        csvlog.log(result_view.final)

                    # print current insn + split checkpoint
                    if not index % self._cache_dyna_refresh_frequency:
                        cur_end = datetime.now()
                        total_sec = (cur_end - cur_begin).total_seconds()
                        cur_speed = int(self._cache_dyna_refresh_frequency / total_sec)
                        self._logger.info("[%d]insn: %s | %s exec/sec", index, self.fuzzer, cur_speed)
                        # update current
                        cur_begin = datetime.now()

                        # Split checkpoint: check if scheduler requested a split
                        if split_event is not None and split_event.is_set() and isinstance(self._fuzzer, Splittable):
                            split_event.clear()
                            new_fuzzer = self._fuzzer.split_remaining()
                            if new_fuzzer is not None and work_queue is not None:
                                work_queue.put(new_fuzzer)
                                self._logger.info(
                                    "Split: keeping %s, donated %s",
                                    self._fuzzer.str_fuzzing_range(),
                                    new_fuzzer.str_fuzzing_range(),
                                )

                    try:
                        # send new insn to injector
                        self._send_instruction(cli_sock, index, new_insn)
                        # get execution result
                        self._recv_into(cli_sock, recv_view)
                        result_view.invalidate()
                    except EOFError:
                        self._logger.info("[%d]Injector has closed the communication", index)
                        break

                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.debug("[%d]Recv msg %s", index, pformat(msg.repr_recv()))

                    # sanity check
                    if result_view.rep_length is None:
                        self._logger.info(
                            "[%d]Impossible length recorded by CPU on VMEXIT for %s: %i",
                            index,
                            new_insn.hex(),
                            msg.insn_length,
                        )
                    # update exitstats -- raw int key, format at display time
                    self._exitstats[msg.reason] += 1
            except Exception as e:
                error = e
            else:
                self._logger.info("Fuzzing complete.")
            finally:
                end = datetime.now()
                final_stats = WorkerStats(
                    general=self._stats,
                    exitstats=self._exitstats,
                    interruptstats=self._interruptstats,
                    nb_insn=index,
                    total_seconds=(end - begin).total_seconds(),
                )
                self._logger.info("VMEXIT Stats: %s", pformat(self._exitstats))
                self._logger.info("Interrupt Stats: %s", pformat(self._interruptstats))
                self._logger.info("Sifter Stats: %s", pformat(self._stats))
                self._logger.info("Speed: %s insn/sec", final_stats.exec_speed)
                # return will omit raising the exception if any
                if error is not None:
                    raise error
                return final_stats
