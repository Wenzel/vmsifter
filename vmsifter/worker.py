# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
from datetime import datetime
from itertools import count
from pathlib import Path
from typing import Counter

from attr import define, field

from vmsifter.config import settings
from vmsifter.fuzzer.types import AbstractInsnGenerator, ResultView
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
        return int(self.nb_insn / self.total_seconds)


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

    def handle_client(self, cli_sock, cli_addr) -> WorkerStats:
        self.init_logger_worker()
        self._logger.debug("Injector connected: %s", cli_addr)
        with CSVOutput(self._id) as csvlog:
            self._logger.info("Fuzzing range: %s", self.fuzzer.str_fuzzing_range())

            gen = self.fuzzer.gen()

            # Pre-allocate ONCE before loop
            recv_buf = bytearray(InjectorResultMessage.size())
            recv_view = memoryview(recv_buf)
            msg = InjectorResultMessage.from_buffer(recv_buf)
            result_view = ResultView(msg)

            # wait for first message from injector
            self._recv_into(cli_sock, recv_view)
            result_view.invalidate()

            if self._logger.isEnabledFor(logging.DEBUG):
                self._logger.debug("[0]Recv msg %s", pformat(msg.repr_recv()))

            # store error if any
            # since we want to always display Client statistics in the finally block
            # but returning from finally erases the exception
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

                    # print current insn
                    if not index % self._cache_dyna_refresh_frequency:
                        cur_end = datetime.now()
                        total_sec = (cur_end - cur_begin).total_seconds()
                        cur_speed = int(self._cache_dyna_refresh_frequency / total_sec)
                        self._logger.info("[%d]insn: %s | %s exec/sec", index, self.fuzzer, cur_speed)
                        # update current
                        cur_begin = datetime.now()

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
                    # update exitstats — raw int key, format at display time
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
