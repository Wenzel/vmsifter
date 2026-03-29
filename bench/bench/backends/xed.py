"""Intel XED decoder backend using CFFI bindings."""

import logging

from _xed_cffi import ffi, lib  # type: ignore[import-not-found]

from bench.backends.base import register
from bench.schema import Backend, BackendResult, ReferenceRow, ValidationIssue, ValidationReport

logger = logging.getLogger(__name__)

_MODE_MAP = {
    32: (lib.XED_MACHINE_MODE_LEGACY_32, lib.XED_ADDRESS_WIDTH_32b),
    64: (lib.XED_MACHINE_MODE_LONG_64, lib.XED_ADDRESS_WIDTH_64b),
}

_WRITE_ACTIONS = frozenset({
    lib.XED_OPERAND_ACTION_W,
    lib.XED_OPERAND_ACTION_RW,
    lib.XED_OPERAND_ACTION_RCW,
    lib.XED_OPERAND_ACTION_CW,
})

_REG_SLOTS = frozenset({
    lib.XED_OPERAND_REG0,
    lib.XED_OPERAND_REG1,
    lib.XED_OPERAND_REG2,
    lib.XED_OPERAND_REG3,
    lib.XED_OPERAND_REG4,
    lib.XED_OPERAND_REG5,
    lib.XED_OPERAND_REG6,
    lib.XED_OPERAND_REG7,
    lib.XED_OPERAND_REG8,
})

_UD_ICLASSES = frozenset({
    lib.XED_ICLASS_UD0,
    lib.XED_ICLASS_UD1,
    lib.XED_ICLASS_UD2,
})


@register
class XedBackend(Backend):
    name = "xed"
    kind = "decoder"

    def __init__(self, exec_mode: int) -> None:
        if exec_mode not in _MODE_MAP:
            raise ValueError(f"Unsupported exec_mode {exec_mode}; expected 32 or 64")
        self._exec_mode = exec_mode
        logger.debug("XED init: mode=%d-bit", exec_mode)
        lib.xed_tables_init()
        self._state = ffi.new("xed_state_t *")
        self._xedd = ffi.new("xed_decoded_inst_t *")
        self._buf = ffi.new("char[256]")
        machine_mode, addr_width = _MODE_MAP[exec_mode]
        lib.xed_state_init2(self._state, machine_mode, addr_width)

    def process(self, insn_bytes: bytes) -> BackendResult:
        lib.xed_decoded_inst_zero_set_mode(self._xedd, self._state)
        err = lib.xed_decode(self._xedd, insn_bytes, len(insn_bytes))

        if err != lib.XED_ERROR_NONE:
            error_str = ffi.string(lib.xed_error_enum_t2str(err)).decode()
            return BackendResult(
                valid=False,
                length=None,
                exit_type="invalid",
                misc={"error": error_str},
            )

        length = lib.xed_decoded_inst_get_length(self._xedd)
        iclass = lib.xed_decoded_inst_get_iclass(self._xedd)
        iclass_name = ffi.string(lib.xed_iclass_enum_t2str(iclass)).decode()
        exit_type = "fault/UD" if iclass in _UD_ICLASSES else "valid"

        # Format disassembly
        asm = None
        if lib.xed_format_context(
            lib.XED_SYNTAX_INTEL, self._xedd, self._buf, 256, 0x1000, ffi.NULL, ffi.NULL
        ):
            asm = ffi.string(self._buf).decode()

        reg_delta = self._written_registers()

        misc: dict[str, str] | None = {"iclass": iclass_name}
        if asm:
            misc["asm"] = asm

        return BackendResult(
            valid=True,
            length=length,
            exit_type=exit_type,
            reg_delta=reg_delta,
            misc=misc,
        )

    def validate(self, reference: ReferenceRow, result: BackendResult) -> ValidationReport:
        expected_exit_type = reference.expected_xed_exit_type()
        if expected_exit_type is None:
            return ValidationReport.skip()

        issues: list[ValidationIssue] = []
        if result.exit_type != expected_exit_type:
            issues.append(ValidationIssue(
                field="exit_type",
                expected=expected_exit_type,
                actual=result.exit_type,
                message="XED exit type disagrees with the reference row",
            ))
        if reference.length is not None and result.length != reference.length:
            issues.append(ValidationIssue(
                field="length",
                expected=reference.length,
                actual=result.length,
                message="XED decoded length disagrees with the reference row",
            ))

        return ValidationReport(comparable=True, issues=tuple(issues))

    def _written_registers(self) -> str | None:
        """Return space-joined sorted register names written by the decoded instruction."""
        inst = lib.xed_decoded_inst_inst(self._xedd)
        nops = lib.xed_inst_noperands(inst)
        regs: set[str] = set()
        for i in range(nops):
            op = lib.xed_inst_operand(inst, i)
            if lib.xed_operand_rw(op) not in _WRITE_ACTIONS:
                continue
            op_name = lib.xed_operand_name(op)
            if op_name not in _REG_SLOTS:
                continue
            reg = lib.xed_decoded_inst_get_reg(self._xedd, op_name)
            if reg == lib.XED_REG_INVALID:
                continue
            name = ffi.string(lib.xed_reg_enum_t2str(reg)).decode().lower()
            regs.add(name)
        return " ".join(sorted(regs)) if regs else None

    def close(self) -> None:
        self._state = None
        self._xedd = None
        self._buf = None
