# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import ctypes

from vmsifter.injector import ExitReasonEnum
from vmsifter.injector.types import InjectorResultMessage


class MockSocket:
    """Simulates injector socket protocol for testing without Xen.

    Responds to every send() with a configurable InjectorResultMessage via recv_into().
    """

    def __init__(self, result_factory=None):
        self._factory = result_factory or self._default_mtf
        self._last_insn: bytes = b""

    def send(self, data):
        self._last_insn = bytes(data)

    def recv_into(self, buffer):
        msg = self._factory()
        raw = bytes(msg)
        # buffer is a memoryview over a bytearray; slice-assign works
        buffer[: len(raw)] = raw
        return len(raw)

    @staticmethod
    def _default_mtf():
        buf = bytearray(InjectorResultMessage.size())
        msg = InjectorResultMessage.from_buffer(buf)
        msg.reason = ExitReasonEnum.MTF.value
        msg.insn_length = 1
        return msg
