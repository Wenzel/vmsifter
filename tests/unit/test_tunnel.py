# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from itertools import chain

import pytest

from vmsifter.config import settings
from vmsifter.fuzzer import ResultView, TunnelFuzzer
from vmsifter.fuzzer.partition import X86Range, partition
from vmsifter.injector import ExitReasonEnum, InjectorResultMessage
from vmsifter.injector.types import EPTQualEnum


def _make_view(reason=0, qualification=0, insn_length=0, intr_info=0, intr_error=0, **kwargs) -> ResultView:
    """Helper: create a fresh ResultView backed by a new InjectorResultMessage."""
    buf = bytearray(InjectorResultMessage.size())
    msg = InjectorResultMessage.from_buffer(buf)
    msg.reason = reason
    msg.qualification = qualification
    msg.insn_length = insn_length
    msg.intr_info = intr_info
    msg.intr_error = intr_error
    for k, v in kwargs.items():
        setattr(msg, k, v)
    return ResultView(msg)


def _interrupted_view() -> ResultView:
    return _make_view(reason=ExitReasonEnum.EXTERNAL_INTERRUPT.value)


def _ept_execute_view() -> ResultView:
    return _make_view(reason=ExitReasonEnum.EPT.value, qualification=EPTQualEnum.EXECUTE.value)


def _other_view(reason_enum=ExitReasonEnum.MTF, insn_length=0) -> ResultView:
    return _make_view(reason=reason_enum.value, insn_length=insn_length)


def _view_from_msg(msg: InjectorResultMessage) -> ResultView:
    """Create a ResultView that reads from the given msg (shares memory)."""
    return ResultView(msg)


def test_tunnel_retry():
    """The tunnel should send the same insn if retry is requested"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    # act
    failed_insn = gen.send(None).tobytes()
    next_insn = gen.send(_interrupted_view()).tobytes()
    # assert
    assert failed_insn == next_insn


def test_default_tunnel_first_insn_is_one_byte_0x0():
    """The default tunnel should return a one byte 0x0 as its first insn"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    # act
    insn = gen.send(None).tobytes()
    # assert
    assert insn == b"\x00"


def test_first_insn_is_same_as_init_value():
    # arrange
    init_fuzzer = [0x04, 0x05, 0xFF, 0xA, 0x22]
    tun = TunnelFuzzer(bytearray(init_fuzzer))
    gen = tun.gen()
    # act
    insn = gen.send(None).tobytes()
    # assert
    assert insn == bytes(init_fuzzer)


def test_pagefault_next_insn():
    """On a pagefault exec result, the next instruction should get one byte bigger"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    # act
    new_insn = gen.send(_ept_execute_view()).tobytes()
    # assert
    assert len(new_insn) == len(prev_insn) + 1
    # last element should be set to 0
    assert new_insn[-1] == 0


def test_same_length_increment_last_byte():
    """on a valid exec result, if the length is the same, the last byte should be incremented"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    # act
    new_insn = gen.send(_other_view()).tobytes()
    # assert
    assert new_insn[-1] == prev_insn[-1] + 1


def test_rollover_previous_byte():
    """on a valid exec result, if the last byte was 0xFF, reset to 0 and move marker to previous byte"""
    # arrange
    tun = TunnelFuzzer(bytearray([0x04, 0xFF]), marker_idx=1)
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    # act
    new_insn = gen.send(_other_view()).tobytes()
    # assert
    assert new_insn == bytes([0x05])
    # marker should be on 0x04 byte
    assert tun.marker_idx == 0


def test_rollover_multiple_bytes():
    # arrange
    init_content = [0x04, 0x05, 0xFF, 0xFF, 0xFF]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=4)
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    # act
    new_insn = gen.send(_other_view()).tobytes()
    # assert
    assert new_insn == bytes([0x04, 0x06])
    assert tun.marker_idx == 1


@pytest.mark.skip(reason="double check backward search")
def test_marker_moved_new_instruction_length():
    """on a valid exec result, if the length has changed, the marker should have moved to the
    end of the new instruction"""
    # arrange
    init_content = [0xC7, 0x04, 0x06]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=2)
    gen = tun.gen()
    gen.send(None).tobytes()
    view = _other_view(insn_length=7)
    # act
    new_insn = gen.send(view).tobytes()
    # assert
    # marker should have moved, and last byte incremented
    assert list(new_insn) == [0xC7, 0x04, 0x06, 0x00, 0x00, 0x00, 0x01]


def test_need_more_bytes_max_insn_size():
    """on a pagefault exec result, if the tunnel requests more bytes than an x86 insn can contain,
    the marker byte should be increased and the length reset to the marker index"""
    # arrange
    init_content = [0x6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=0)
    gen = tun.gen()
    gen.send(None).tobytes()
    # act
    new_insn = gen.send(_ept_execute_view()).tobytes()
    # assert
    assert list(new_insn) == [0x7]


@pytest.mark.parametrize("x86_range", list(chain(*[partition(i) for i in [1, 3, 8, 64]])))
def test_fuzzing_complete(x86_range: X86Range):
    """test that the tunnel generator stops"""
    # arrange
    init_content = [int.from_bytes(x86_range.end, byteorder="big")]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=0, end_first_byte=x86_range.end)
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    view = _other_view(reason_enum=ExitReasonEnum.APIC_ACCESS, insn_length=len(prev_insn))
    # act
    with pytest.raises(StopIteration):
        gen.send(view)


@pytest.mark.parametrize("mode", ["32", "64"])
def test_min_prefix(mode):
    # arrange
    settings.x86.exec_mode = mode
    settings.min_prefix_count = 1
    settings.max_prefix_count = 5
    settings.validators.validate()
    settings.prefix_range = range(settings.min_prefix_count, settings.max_prefix_count + 1)
    tun = TunnelFuzzer(marker_idx=settings.min_prefix_count + 1)
    gen = tun.gen()
    # act
    prev_insn = gen.send(None).tobytes()
    view = _other_view(insn_length=len(prev_insn))
    new_insn = gen.send(view)
    # assert
    assert len([b for b in prev_insn if b in settings.x86.prefix]) >= settings.min_prefix_count
    assert len([b for b in prev_insn if b in settings.x86.prefix]) < settings.max_prefix_count


def test_backward_search():
    # arrange
    init_content = bytearray([0x00, 0xC0, 0x00, 0x00, 0x00, 0x00])
    tun = TunnelFuzzer(insn_buffer=init_content, marker_idx=1)
    gen = tun.gen()
    # act
    gen.send(None)
    # Create views with reason=37 (MTF), insn_length=2
    insn_1 = gen.send(_make_view(reason=37, qualification=0, insn_length=2))
    insn_2 = gen.send(_make_view(reason=37, qualification=0, insn_length=2))
    insn_3 = gen.send(_make_view(reason=37, qualification=0, insn_length=2))
    insn_4 = gen.send(_make_view(reason=37, qualification=0, insn_length=2))
    # assert
    assert list(insn_1) == [0x00, 0xC0, 0x00, 0x00, 0x00]
    assert list(insn_2) == [0x00, 0xC0, 0x00, 0x00]
    assert list(insn_3) == [0x00, 0xC0, 0x00]
    assert list(insn_4) == [0x00, 0xC0]


# ── split_remaining / remaining_range_size tests ──


@pytest.fixture(autouse=False)
def _reset_prefix_settings():
    """Ensure min_prefix_count is reset for split tests that create 1-byte buffers."""
    old_min = settings.min_prefix_count
    old_max = settings.max_prefix_count
    settings.min_prefix_count = 0
    settings.max_prefix_count = 0
    settings.prefix_range = range(0, 1)
    yield
    settings.min_prefix_count = old_min
    settings.max_prefix_count = old_max
    settings.prefix_range = range(old_min, old_max + 1)


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_split_remaining_halves_range():
    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    new = tun.split_remaining()
    assert new is not None
    assert tun.end_first_byte_int == 0x7F  # self shrunk
    assert new.insn_buffer[0] == 0x7F  # new starts at midpoint
    assert new.end_first_byte == b"\xFF"  # new ends at original end


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_split_remaining_too_small():
    tun = TunnelFuzzer(insn_buffer=bytearray([0xFE]), end_first_byte=b"\xFF")
    assert tun.split_remaining() is None


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_split_remaining_preserves_marker():
    tun = TunnelFuzzer(insn_buffer=bytearray([0x04, 0x05]), marker_idx=1, end_first_byte=b"\x40")
    tun.split_remaining()
    assert tun.marker_idx == 1  # unchanged


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_split_result_picklable():
    import pickle

    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    new = tun.split_remaining()
    assert new is not None
    roundtripped = pickle.loads(pickle.dumps(new))
    assert roundtripped.insn_buffer[0] == new.insn_buffer[0]


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_remaining_range_size():
    tun = TunnelFuzzer(insn_buffer=bytearray([0x40]), end_first_byte=b"\x80")
    assert tun.remaining_range_size() == 0x40


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_remaining_range_size_zero():
    tun = TunnelFuzzer(insn_buffer=bytearray([0x80]), end_first_byte=b"\x80")
    assert tun.remaining_range_size() == 0


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_split_updates_completion_tracker():
    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    old_end = tun.byterange_completion.range_end
    tun.split_remaining()
    # ByteRangeCompletion should have been recalculated with new (smaller) range
    assert tun.byterange_completion.range_end != old_end


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_splittable_protocol():
    from vmsifter.fuzzer.types import Splittable

    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    assert isinstance(tun, Splittable)


@pytest.mark.usefixtures("_reset_prefix_settings")
def test_split_remaining_consecutive_splits():
    """Multiple splits should keep shrinking the range."""
    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    split1 = tun.split_remaining()
    assert split1 is not None
    # tun is now [0x00, 0x7F], split1 is [0x7F, 0xFF]
    split2 = tun.split_remaining()
    assert split2 is not None
    # tun is now [0x00, 0x3F], split2 is [0x3F, 0x7F]
    assert tun.end_first_byte_int == 0x3F
    assert split2.insn_buffer[0] == 0x3F


@pytest.mark.skip(reason="infinite recursion since prefix added")
def test_bump_10_insn():
    # arrange
    init_content = bytearray([0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00])
    tun = TunnelFuzzer(content=init_content, marker_idx=2)
    gen = tun.gen()
    # act
    # init with 2 exec similar behavior
    gen.send(None)
    view = _make_view(reason=48, qualification=0x7AB, insn_length=7)
    insn = gen.send(view)
    assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x01]
    view2 = _make_view(reason=48, qualification=0x783, insn_length=7)
    insn = gen.send(view2)
    # now counter has started for 10 insn
    assert tun.counter == 1
    assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x02]
    last_byte = 0x2
    for _ in range(8):
        insn = gen.send(view2)
        last_byte += 1
        assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, last_byte]

    # check first insn with bump
    first_insn_bump = list(gen.send(view2))
    # continue for 9 insn
    last_byte = 0x10
    for _ in range(9):
        insn = gen.send(view2)
        last_byte += 0x10
        assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, last_byte]
    # check last insn is final marker 0xFF
    final_insn_bump = list(gen.send(view2))
    # assert
    assert list(first_insn_bump) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x10]
    assert list(final_insn_bump) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x01]
