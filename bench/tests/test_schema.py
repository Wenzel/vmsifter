"""Tests for BackendResult dataclass."""

import pytest

from bench.schema import BackendResult


def test_create_valid_result():
    r = BackendResult(valid=True, length=3, exit_type="valid")
    assert r.valid is True
    assert r.length == 3
    assert r.exit_type == "valid"
    assert r.reg_delta is None
    assert r.misc is None


def test_create_invalid_result():
    r = BackendResult(valid=False, length=None, exit_type="invalid", misc={"error": "bad"})
    assert r.valid is False
    assert r.length is None
    assert r.misc == {"error": "bad"}


def test_frozen_immutability():
    r = BackendResult(valid=True, length=1, exit_type="valid")
    with pytest.raises(AttributeError):
        r.valid = False  # type: ignore[misc]


def test_equality():
    a = BackendResult(valid=True, length=1, exit_type="valid")
    b = BackendResult(valid=True, length=1, exit_type="valid")
    assert a == b


def test_with_all_fields():
    r = BackendResult(
        valid=True,
        length=5,
        exit_type="valid",
        reg_delta="rax=0x1",
        misc={"asm": "nop"},
    )
    assert r.reg_delta == "rax=0x1"
    assert r.misc == {"asm": "nop"}
