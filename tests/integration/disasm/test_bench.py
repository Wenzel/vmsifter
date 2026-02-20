# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from itertools import count

import pytest

from vmsifter.disasm.adapter import DisasmAdapter
from vmsifter.disasm.capstone import CapstoneDisasmAdaptee
from vmsifter.fuzzer.tunnel import TunnelFuzzer
from vmsifter.fuzzer.types import ResultView
from vmsifter.injector.types import EPTQualEnum, ExitReasonEnum, InjectorResultMessage


def _ept_execute_view() -> ResultView:
    buf = bytearray(InjectorResultMessage.size())
    msg = InjectorResultMessage.from_buffer(buf)
    msg.reason = ExitReasonEnum.EPT.value
    msg.qualification = EPTQualEnum.EXECUTE.value
    return ResultView(msg)


def _valid_view(insn_length: int) -> ResultView:
    buf = bytearray(InjectorResultMessage.size())
    msg = InjectorResultMessage.from_buffer(buf)
    msg.reason = ExitReasonEnum.MTF.value
    msg.insn_length = insn_length
    return ResultView(msg)


@pytest.mark.parametrize("max_count", [10**3, 10**4, 10**5, 10**6])
def test_capstone_tunnel(max_count: int):
    # arrange
    cap_adaptee = CapstoneDisasmAdaptee()
    adapter = DisasmAdapter(cap_adaptee)
    # act
    tun = TunnelFuzzer()
    gen = tun.gen()
    result = None
    for i in count():
        if i == max_count:
            break
        next_buff = gen.send(result)
        # disasm
        disas_res = adapter.disasm(next_buff)
        if disas_res is None:
            result = _ept_execute_view()
        else:
            result = _valid_view(disas_res.size)
