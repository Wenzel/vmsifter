# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from itertools import count

import pytest
from capstone import CS_MODE_64

from vmsifter.disasm.capstone import CapstoneDisasmAdaptee
from vmsifter.disasm.interface import DisasmEngineType, DisasmResult
from vmsifter.disasm.pool import DisasmPoolExecutor
from vmsifter.disasm.yaxpeax import YaxpeaxDisasmAdaptee
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


def test_pool_disasm_one():
    # arrange
    cap_adaptee = CapstoneDisasmAdaptee(mode=CS_MODE_64)
    yaxpeax_adaptee = YaxpeaxDisasmAdaptee()
    engines = {DisasmEngineType.CAPSTONE: cap_adaptee, DisasmEngineType.YAXPEAX: yaxpeax_adaptee}
    buffer = b"\x55"
    expected_res = DisasmResult(1, "push rbp")
    with DisasmPoolExecutor(engines) as pool:
        # act
        pool.submit_disasm(buffer)
        # assert
        result = list(pool.as_completed())
        print(result)
        assert len(result) == len(engines)
        for res in result:
            assert res.disas_res == expected_res


@pytest.mark.parametrize("max_count", [10**3, 10**4, 10**5])
def test_capstone_tunnel(max_count: int):
    # arrange
    cap_adaptee = CapstoneDisasmAdaptee()
    yaxpeax_adaptee = YaxpeaxDisasmAdaptee()
    tun = TunnelFuzzer()
    gen = tun.gen()

    # act
    result = None
    engines = {DisasmEngineType.CAPSTONE: cap_adaptee, DisasmEngineType.YAXPEAX: yaxpeax_adaptee}

    with DisasmPoolExecutor(engines) as pool:
        for i in count():
            if i == max_count:
                break
            next_buff = gen.send(result)
            # disasm
            pool.submit_disasm(next_buff.tobytes())
            pool_res = next(pool.as_completed())
            if pool_res.disas_res is None:
                result = _ept_execute_view()
            else:
                result = _valid_view(pool_res.disas_res.size)
