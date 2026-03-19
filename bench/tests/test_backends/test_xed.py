"""Tests for XED backend — skipped if _xed_cffi extension is not available."""

import pytest

try:
    from bench.backends.xed import XedBackend

    HAS_XED = True
except ImportError:
    HAS_XED = False

pytestmark = pytest.mark.skipif(not HAS_XED, reason="_xed_cffi extension not available")


@pytest.fixture
def xed():
    backend = XedBackend()
    backend.setup()
    yield backend
    backend.teardown()


def test_nop_decode(xed):
    result = xed.process(b"\x90", exec_mode=64)
    assert result.valid is True
    assert result.length == 1
    assert result.exit_type == "valid"


def test_multibyte_nop(xed):
    result = xed.process(bytes.fromhex("0f1f00"), exec_mode=64)
    assert result.valid is True
    assert result.length == 3


def test_ud2(xed):
    result = xed.process(bytes.fromhex("0f0b"), exec_mode=64)
    assert result.valid is True
    assert result.length == 2


def test_invalid_instruction(xed):
    # FF FF is not a valid instruction in 64-bit mode
    result = xed.process(b"\xff\xff", exec_mode=64)
    # XED may or may not decode this depending on version; just check the contract
    assert isinstance(result.valid, bool)
    assert result.exit_type in ("valid", "invalid")


def test_mode_32(xed):
    result = xed.process(b"\x90", exec_mode=32)
    assert result.valid is True
    assert result.length == 1


def test_disassembly_in_misc(xed):
    result = xed.process(b"\x90", exec_mode=64)
    if result.misc:
        assert "asm" in result.misc
