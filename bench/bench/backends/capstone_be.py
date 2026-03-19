"""Capstone disassembler decoder backend."""

import capstone

from bench.backends.base import register
from bench.schema import Backend, BackendResult

_MODE_MAP = {
    32: capstone.CS_MODE_32,
    64: capstone.CS_MODE_64,
}


@register
class CapstoneBackend(Backend):
    name = "capstone"
    kind = "decoder"

    def setup(self) -> None:
        self._md: capstone.Cs | None = None
        self._mode: int | None = None

    def _set_mode(self, exec_mode: int) -> None:
        if exec_mode not in _MODE_MAP:
            raise ValueError(f"Unsupported exec_mode {exec_mode}; expected 32 or 64")
        self._md = capstone.Cs(capstone.CS_ARCH_X86, _MODE_MAP[exec_mode])
        self._mode = exec_mode

    def process(self, insn_bytes: bytes, exec_mode: int) -> BackendResult:
        if exec_mode != self._mode:
            self._set_mode(exec_mode)

        insns = list(self._md.disasm(insn_bytes, 0x1000, count=1))

        if not insns:
            return BackendResult(valid=False, length=None, exit_type="invalid")

        insn = insns[0]
        return BackendResult(
            valid=True,
            length=insn.size,
            exit_type="valid",
            misc={"asm": f"{insn.mnemonic} {insn.op_str}".strip()},
        )

    def teardown(self) -> None:
        self._md = None
        self._mode = None
