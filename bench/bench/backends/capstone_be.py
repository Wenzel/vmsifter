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

    def __init__(self, exec_mode: int) -> None:
        if exec_mode not in _MODE_MAP:
            raise ValueError(f"Unsupported exec_mode {exec_mode}; expected 32 or 64")
        self._exec_mode = exec_mode
        self._md = capstone.Cs(capstone.CS_ARCH_X86, _MODE_MAP[exec_mode])

    def process(self, insn_bytes: bytes) -> BackendResult:
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

    def close(self) -> None:
        self._md = None
