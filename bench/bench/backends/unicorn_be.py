"""Unicorn Engine emulator backend."""

import logging

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP,
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)
from unicorn.unicorn_const import (
    UC_ERR_INSN_INVALID,
    UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_FETCH_UNMAPPED,
    UC_ERR_EXCEPTION,
)

from bench.backends.base import register
from bench.schema import Backend, BackendResult

logger = logging.getLogger(__name__)

CODE_ADDR = 0x10000
STACK_ADDR = 0x20000
PAGE_SIZE = 2 * 0x1000  # 8 KiB

# GP registers and their canary values (0x1100 + offset).
# RSP/ESP gets the stack pointer instead.
_REGS_64 = [
    ("rax", UC_X86_REG_RAX, 0x1100),
    ("rbx", UC_X86_REG_RBX, 0x1101),
    ("rcx", UC_X86_REG_RCX, 0x1102),
    ("rdx", UC_X86_REG_RDX, 0x1103),
    ("rsi", UC_X86_REG_RSI, 0x1104),
    ("rdi", UC_X86_REG_RDI, 0x1105),
    ("rbp", UC_X86_REG_RBP, 0x1106),
    ("rsp", UC_X86_REG_RSP, None),  # set to stack
    ("r8",  UC_X86_REG_R8,  0x1108),
    ("r9",  UC_X86_REG_R9,  0x1109),
    ("r10", UC_X86_REG_R10, 0x110A),
    ("r11", UC_X86_REG_R11, 0x110B),
    ("r12", UC_X86_REG_R12, 0x110C),
    ("r13", UC_X86_REG_R13, 0x110D),
    ("r14", UC_X86_REG_R14, 0x110E),
    ("r15", UC_X86_REG_R15, 0x110F),
]

_REGS_32 = [
    ("eax", UC_X86_REG_EAX, 0x1100),
    ("ebx", UC_X86_REG_EBX, 0x1101),
    ("ecx", UC_X86_REG_ECX, 0x1102),
    ("edx", UC_X86_REG_EDX, 0x1103),
    ("esi", UC_X86_REG_ESI, 0x1104),
    ("edi", UC_X86_REG_EDI, 0x1105),
    ("ebp", UC_X86_REG_EBP, 0x1106),
    ("esp", UC_X86_REG_ESP, None),  # set to stack
]

_IP_REG = {32: UC_X86_REG_EIP, 64: UC_X86_REG_RIP}
_STACK_PTR = STACK_ADDR + 0x1000


def _map_uc_error(errno: int) -> str:
    """Map a Unicorn error code to a normalized exit_type string."""
    if errno == UC_ERR_INSN_INVALID:
        return "fault/UD"
    if errno in (UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_FETCH_UNMAPPED):
        return "fault/PF"
    if errno == UC_ERR_EXCEPTION:
        return "fault/GP"
    return f"other/{errno}"


@register
class UnicornBackend(Backend):
    name = "unicorn"
    kind = "emulator"

    def __init__(self, exec_mode: int) -> None:
        if exec_mode not in (32, 64):
            raise ValueError(f"Unsupported exec_mode {exec_mode}; expected 32 or 64")
        self._exec_mode = exec_mode
        self._regs = _REGS_64 if exec_mode == 64 else _REGS_32
        logger.debug("Unicorn init: mode=%d-bit", exec_mode)

        mode = UC_MODE_64 if exec_mode == 64 else UC_MODE_32
        self._uc = Uc(UC_ARCH_X86, mode)
        self._uc.mem_map(CODE_ADDR, PAGE_SIZE)
        self._uc.mem_map(STACK_ADDR, PAGE_SIZE)

    def process(self, insn_bytes: bytes) -> BackendResult:
        uc = self._uc

        # Write instruction bytes to code page.
        uc.mem_write(CODE_ADDR, insn_bytes)

        # Set canary register values.
        for _name, uc_reg, canary in self._regs:
            uc.reg_write(uc_reg, _STACK_PTR if canary is None else canary)

        # Execute one instruction.
        try:
            uc.emu_start(CODE_ADDR, CODE_ADDR + len(insn_bytes), count=1)
        except UcError as exc:
            exit_type = _map_uc_error(exc.errno)
            logger.debug("Unicorn fault: %s (errno=%d)", exit_type, exc.errno)
            return BackendResult(valid=False, length=None, exit_type=exit_type)

        # Success — compute length from RIP/EIP delta.
        ip = uc.reg_read(_IP_REG[self._exec_mode])
        length = ip - CODE_ADDR

        # Compute register delta.
        reg_delta = self._reg_delta()

        logger.debug("Unicorn valid: length=%d reg_delta=%s", length, reg_delta)
        return BackendResult(
            valid=True,
            length=length,
            exit_type="valid",
            reg_delta=reg_delta,
        )

    def _reg_delta(self) -> str | None:
        """Return space-joined sorted names of registers that changed from canary values."""
        changed: list[str] = []
        for name, uc_reg, canary in self._regs:
            if canary is None:
                expected = _STACK_PTR
            else:
                expected = canary
            actual = self._uc.reg_read(uc_reg)
            if actual != expected:
                changed.append(name)
        return " ".join(sorted(changed)) if changed else None

    def close(self) -> None:
        del self._uc
