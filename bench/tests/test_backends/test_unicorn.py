"""Tests for Unicorn backend — skipped if unicorn is not installed."""

import pytest

try:
    from bench.backends.unicorn_be import UnicornBackend

    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

pytestmark = pytest.mark.skipif(not HAS_UNICORN, reason="unicorn not installed")


@pytest.fixture
def uc():
    with UnicornBackend(exec_mode=64) as backend:
        yield backend


@pytest.fixture
def uc32():
    with UnicornBackend(exec_mode=32) as backend:
        yield backend


def test_nop_execute(uc):
    result = uc.process(b"\x90")
    assert result.valid is True
    assert result.length == 1
    assert result.exit_type == "valid"


def test_multibyte_nop(uc):
    result = uc.process(bytes.fromhex("0f1f00"))
    assert result.valid is True
    assert result.length == 3


def test_ud2_faults(uc):
    result = uc.process(bytes.fromhex("0f0b"))
    assert result.valid is False
    assert "fault" in result.exit_type


def test_invalid_instruction(uc):
    # 0x06 = PUSH ES, invalid in 64-bit mode
    result = uc.process(b"\x06")
    assert result.valid is False


def test_mode_32(uc32):
    result = uc32.process(b"\x90")
    assert result.valid is True
    assert result.length == 1


def test_reg_delta_mov(uc):
    # mov eax, 0x42 → b8 42 00 00 00
    result = uc.process(b"\xb8\x42\x00\x00\x00")
    assert result.valid is True
    assert result.reg_delta is not None
    assert "rax" in result.reg_delta


def test_kind_is_emulator(uc):
    assert uc.kind == "emulator"
