"""Tests for Capstone backend — skipped if capstone is not installed."""

import pytest

try:
    from bench.backends.capstone_be import CapstoneBackend

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

pytestmark = pytest.mark.skipif(not HAS_CAPSTONE, reason="capstone not installed")


@pytest.fixture
def cs():
    backend = CapstoneBackend()
    backend.setup()
    yield backend
    backend.teardown()


def test_nop_decode(cs):
    result = cs.process(b"\x90", exec_mode=64)
    assert result.valid is True
    assert result.length == 1
    assert result.exit_type == "valid"


def test_multibyte_nop(cs):
    result = cs.process(bytes.fromhex("0f1f00"), exec_mode=64)
    assert result.valid is True
    assert result.length == 3


def test_ud2(cs):
    result = cs.process(bytes.fromhex("0f0b"), exec_mode=64)
    assert result.valid is True
    assert result.length == 2


def test_invalid_instruction(cs):
    result = cs.process(b"\x06", exec_mode=64)
    assert result.valid is False
    assert result.length is None
    assert result.exit_type == "invalid"


def test_mode_32(cs):
    result = cs.process(b"\x90", exec_mode=32)
    assert result.valid is True
    assert result.length == 1


def test_disassembly_in_misc(cs):
    result = cs.process(b"\x90", exec_mode=64)
    assert result.misc is not None
    assert "asm" in result.misc
    assert "nop" in result.misc["asm"].lower()
