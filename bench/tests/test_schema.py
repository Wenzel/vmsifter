"""Tests for schema dataclasses and parsing helpers."""

import pytest

from bench.schema import BackendResult, ReferenceRow, parse_exit_type


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


def test_parse_exit_type_mtf():
    parsed = parse_exit_type("vmexit:37")

    assert parsed.kind == "vmexit"
    assert parsed.vmexit_reason == 37
    assert parsed.interrupt_type is None


def test_parse_exit_type_invalid_opcode():
    parsed = parse_exit_type("vmexit:0 interrupt_type:hw_exc interrupt_vector:invalid_opcode")

    assert parsed.kind == "vmexit"
    assert parsed.vmexit_reason == 0
    assert parsed.interrupt_type == "hw_exc"
    assert parsed.interrupt_vector == "invalid_opcode"


def test_reference_row_parses_and_exposes_xed_comparability():
    reference = ReferenceRow.from_csv_row({
        "insn": "90",
        "length": "1",
        "exit-type": "vmexit:37",
        "misc": "",
        "reg-delta": "",
    })

    assert reference.insn == b"\x90"
    assert reference.length == 1
    assert reference.expected_xed_validity() is True
    assert reference.is_xed_comparable() is True


def test_reference_row_skips_invalid_opcode_for_xed():
    reference = ReferenceRow.from_csv_row({
        "insn": "0f0b",
        "length": "2",
        "exit-type": "vmexit:0 interrupt_type:hw_exc interrupt_vector:invalid_opcode",
        "misc": "",
        "reg-delta": "",
    })

    assert reference.expected_xed_validity() is None
    assert reference.is_xed_comparable() is False
