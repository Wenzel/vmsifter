# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
from abc import ABC, abstractmethod
from typing import Any, Generator, List, Optional, Protocol, Tuple, Union, runtime_checkable

from attr import define, evolve, field

from vmsifter.config import settings
from vmsifter.injector import NUMBER_OF_REGISTERS, ExitReasonEnum, InjInterruptEnum, InjInterruptTypeEnum, RegistersEnum
from vmsifter.injector.types import InjectorResultMessage
from vmsifter.utils import fact_logging

REGISTER_CANARY = 0x1100

# ── Module-level constants: raw ints, no Enum overhead in hot path ──

_NMI_REASON = ExitReasonEnum.NMI.value  # 0
_EXT_INT_REASON = ExitReasonEnum.EXTERNAL_INTERRUPT.value  # 1
_EPT_REASON = ExitReasonEnum.EPT.value  # 48
_EPT_X_BIT = 0x4
_INTR_VALID = 0x80000000
_INTR_TYPE_SHIFT = 8
_INTR_TYPE_MASK = 0x7
_HW_EXC_TYPE = InjInterruptTypeEnum.HW_EXC.value  # 3
_INVALID_OPCODE_VEC = InjInterruptEnum.INVALID_OPCODE.value  # 6

# ── Module-level lookup tables for cold path (ResultSnapshot) ──

_REGS_ENUM_TABLE: list = [RegistersEnum(i) for i in range(NUMBER_OF_REGISTERS)]
_CR2_VALUE: int = RegistersEnum.CR2.value
_RIP_VALUE: int = RegistersEnum.RIP.value
_EXIT_REASON_MAP: dict = {er.value: er for er in ExitReasonEnum}
_INTR_TYPE_ENUM_MAP: dict = {e.value: e for e in InjInterruptTypeEnum}
_INTR_ENUM_MAP: dict = {e.value: e for e in InjInterruptEnum}


# ══════════════════════════════════════════════════════════════════════
# Tier 1: ResultView — mutable, zero-allocation, reused every iteration
# ══════════════════════════════════════════════════════════════════════


@define(slots=True)
class ResultView:
    """Mutable view over the shared ctypes recv buffer.

    One instance exists for the entire loop lifetime.
    Properties read directly from the ctypes struct fields --
    no copying, no object creation.
    """

    _msg: InjectorResultMessage
    _fingerprint: Optional[tuple] = field(init=False, default=None)
    # Mutable slot for the fuzzer to attach a FinalLogResult when ready
    final: Optional["FinalLogResult"] = field(init=False, default=None)

    def invalidate(self):
        """Call after recv_into. Clears cached derivations."""
        self._fingerprint = None
        self.final = None

    # ── Hot path: classification (direct int comparisons) ──

    @property
    def is_interrupted(self) -> bool:
        return self._msg.reason == _EXT_INT_REASON

    @property
    def is_ept_execute(self) -> bool:
        return self._msg.reason == _EPT_REASON and bool(self._msg.qualification & _EPT_X_BIT)

    @property
    def is_nmi(self) -> bool:
        return self._msg.reason == _NMI_REASON

    @property
    def reason(self) -> int:
        return self._msg.reason

    @property
    def rep_length(self) -> Optional[int]:
        v = self._msg.insn_length
        return v if v != 0 else None

    @property
    def is_invalid_opcode(self) -> bool:
        m = self._msg
        if m.reason != _NMI_REASON:
            return False
        info = m.intr_info
        return (
            bool(info & _INTR_VALID)
            and (info >> _INTR_TYPE_SHIFT) & _INTR_TYPE_MASK == _HW_EXC_TYPE
            and info & 0xFF == _INVALID_OPCODE_VEC
        )

    # ── Hot path: equality fingerprint (cached tuple of 2-3 ints) ──

    @property
    def fingerprint(self) -> tuple:
        """Captures exactly the fields that the old attrs __eq__ compared.
        Computed at most once per recv. Cheap tuple of raw ints."""
        if self._fingerprint is None:
            m = self._msg
            r = m.reason
            if r == _NMI_REASON:
                info = m.intr_info
                if info & _INTR_VALID:
                    itype = (info >> _INTR_TYPE_SHIFT) & _INTR_TYPE_MASK
                else:
                    itype = -1
                self._fingerprint = (r, itype)
            elif r == _EPT_REASON:
                self._fingerprint = (r, m.qualification & 0x7)
            else:
                self._fingerprint = (r,)
        return self._fingerprint

    # ── Cold path: snapshot for logging (object creation only here) ──

    def snapshot(self) -> "ResultSnapshot":
        """Freeze current buffer state into an immutable object for CSV logging.
        Called ONLY when a result becomes 'final'. This is the ONLY place
        that creates Python objects from the buffer."""
        return ResultSnapshot.from_msg(self._msg)


# ══════════════════════════════════════════════════════════════════════
# Tier 2: ResultSnapshot — immutable, created only at log time
# ══════════════════════════════════════════════════════════════════════


@define(slots=True)
class ResultSnapshot:
    """Immutable parsed result. Created only for results that will be logged."""

    reason: int
    exit_reason: ExitReasonEnum
    qualification: int
    insn_length: int
    perfct: Tuple[int, ...] = field()
    raw_regs: Tuple[int, ...] = field()
    intr_info: int
    intr_error: int
    vec_info: int
    vec_error: int
    insn_info: int
    gla: int
    stack_value: int

    @classmethod
    def from_msg(cls, msg: InjectorResultMessage) -> "ResultSnapshot":
        reason = msg.reason
        return cls(
            reason=reason,
            exit_reason=_EXIT_REASON_MAP.get(reason, ExitReasonEnum.UNKNOWN),
            qualification=msg.qualification,
            insn_length=msg.insn_length,
            perfct=tuple(msg.perfct),
            raw_regs=tuple(msg.regs),
            intr_info=msg.intr_info,
            intr_error=msg.intr_error,
            vec_info=msg.vec_info,
            vec_error=msg.vec_error,
            insn_info=msg.insn_info,
            gla=msg.gla,
            stack_value=msg.stack_value,
        )

    # ── String formatting methods (only called during CSV write) ──

    def type_str(self) -> str:
        r = self.reason
        if r == _NMI_REASON:
            return self._nmi_type_str()
        elif r == _EPT_REASON:
            q = self.qualification
            rwx = f"{'r' if q & 1 else ''}{'w' if q & 2 else ''}{'x' if q & 4 else ''}"
            return f"vmexit:{r} ept:{rwx}"
        elif r == _EXT_INT_REASON:
            return "interrupted"
        else:
            return f"vmexit:{r}"

    def _nmi_type_str(self) -> str:
        s = f"vmexit:{self.reason}"
        info = self.intr_info
        if not (info & _INTR_VALID):
            return s
        itype = (info >> _INTR_TYPE_SHIFT) & _INTR_TYPE_MASK
        itype_enum = _INTR_TYPE_ENUM_MAP.get(itype, InjInterruptTypeEnum.INVALID)
        s += f" interrupt_type:{itype_enum.name.lower()}"
        vector = info & 0xFF
        if itype_enum == InjInterruptTypeEnum.EXTERNAL:
            s += f" external_vector:{hex(vector)}"
        else:
            intr_enum = _INTR_ENUM_MAP.get(vector)
            if intr_enum is not None:
                s += f" interrupt_vector:{intr_enum.name.lower()}"
                if intr_enum == InjInterruptEnum.PAGE_FAULT and info & 0x800:
                    ec = self.intr_error
                    pf = f"{'w' if ec & 2 else 'r'}{'x' if ec & 0x10 else ''}"
                    pf += f"{'p' if ec & 1 else ''}{'RSVD' if ec & 8 else ''}"
                    s += f":{pf}"
        return s

    def reg_delta_str(self) -> str:
        parts = []
        for index, value in enumerate(self.raw_regs):
            if index == _CR2_VALUE or index == _RIP_VALUE:
                continue
            if value != REGISTER_CANARY + index:
                parts.append(f"{_REGS_ENUM_TABLE[index].name.lower()}:{hex(value)}")
        return " ".join(parts)

    def misc_str(self) -> str:
        rep = self.insn_length if self.insn_length != 0 else None
        s = f"cpu_len:{rep}"
        if self.insn_info and self.insn_info != 0:
            s += f" insn_info:{self.insn_info}"
        if self.vec_info and self.vec_info != 0:
            s += f" vec_info:{self.vec_info}"
        if self.vec_error and self.vec_error != 0:
            s += f" vec_error:{self.vec_error}"
        # NMI-specific fields
        if self.reason == _NMI_REASON:
            info = self.intr_info
            if info & _INTR_VALID:
                vector = info & 0xFF
                if vector != InjInterruptEnum.PAGE_FAULT.value and self.stack_value:
                    s += f" stack:{hex(self.stack_value)}"
                cr2 = self.raw_regs[_CR2_VALUE]
                if cr2:
                    s += f" cr2:{hex(cr2)}"
                if (info >> 12) & 1:
                    s += " nmi_unblocking_due_to_iret"
        # EPT-specific fields
        elif self.reason == _EPT_REASON:
            if self.qualification & 0x80 and self.gla:
                s += f" gla:{hex(self.gla)}"
        return s

    @property
    def is_invalid_opcode(self) -> bool:
        if self.reason != _NMI_REASON:
            return False
        info = self.intr_info
        return (
            bool(info & _INTR_VALID)
            and (info >> _INTR_TYPE_SHIFT) & _INTR_TYPE_MASK == _HW_EXC_TYPE
            and info & 0xFF == _INVALID_OPCODE_VEC
        )


# ══════════════════════════════════════════════════════════════════════
# AbstractInsnGenerator and FinalLogResult
# ══════════════════════════════════════════════════════════════════════


@define(slots=True, auto_attribs=True, auto_detect=True)
class AbstractInsnGenerator(ABC):
    """Abstract class implemented by every fuzzer"""

    @staticmethod
    def _get_default_buffer():
        buffer = bytearray(settings.insn_buf_size)
        # pick first available prefix if required
        for i in range(settings.min_prefix_count):
            buffer[i] = settings.mode_prefix[0]
        return buffer

    logger: logging.Logger = field(init=False, default=fact_logging)
    insn_buffer: bytearray = None  # type: ignore[assignment]
    extra_params: Optional[List[str]] = None
    insn_length: int = field(init=False)
    view: memoryview = field(init=False)
    # workaround dynaconf perf bug
    # retrieve values here and keep them
    cache_dyna_mode_prefix: List[int] = field(init=False, default=settings.mode_prefix)
    cache_dyna_prefix_range: range = field(init=False, default=settings.prefix_range)
    cache_dyna_insn_buf_size: int = field(init=False, default=settings.insn_buf_size)

    def __attrs_post_init__(self):
        self.init_buffer(self.insn_buffer)

    # open this method since we might need to reinit the buffer in a child class
    # due to additional fuzzer params
    def init_buffer(self, buffer):
        min_len = settings.min_prefix_count + 1
        if buffer is None:
            self.insn_length = min_len
            self.insn_buffer = self.__class__._get_default_buffer()
        else:
            self.insn_length = len(self.insn_buffer)
            # fill if needed
            fill_size = settings.insn_buf_size - self.insn_length
            self.insn_buffer.extend(bytearray(fill_size))
        # validate length
        if self.insn_length < min_len:
            raise ValueError(f"insn_length < settings.min_prefix_count + 1 ({min_len})")
        # init view
        self.view = memoryview(self.insn_buffer)

    # required custom impl to be able to pickle this class and sent it to ProcessPool
    def __reduce__(self) -> Union[str, Tuple[Any, ...]]:
        # all attrs declared attributes for this class
        # who are init args
        # ['insn_buffer', 'extra_params', ...]
        init_args_name = [attribute.name for attribute in self.__attrs_attrs__ if attribute.init]
        # (class, [self.insn_buffer, self.extra_params, ... + child attributes])
        init_args = [getattr(self, attr_name) for attr_name in init_args_name]
        # special case for insn_buffer (first arg)
        init_args[0] = self.insn_buffer[: self.insn_length]
        return (self.__class__, tuple(init_args))

    def __str__(self):
        current_str = self.current_insn.hex(" ")
        # 15 * 2: one byte uses 2 chars to be displayed: 00
        # 15 - 1: the spaces between the bytes
        filler_size: int = (15 * 2 + (15 - 1)) - len(current_str)
        return f"{current_str}{' ' * filler_size}"

    @property
    def current_insn(self) -> memoryview:
        return self.view[: self.insn_length]

    @abstractmethod
    def gen(self) -> Generator[memoryview, ResultView, None]:
        """Generate the next instruction for the injector and receives a ResultView upon execution"""
        pass

    def partition(self, nb_parts: int) -> Generator["AbstractInsnGenerator", None, None]:
        """
        Partition the fuzzer's own search space into smaller chunks, if supported.
        Otherwise just return a copy of itself
        """
        # default implementation: assume cannot partition, return copy of itself
        for _ in range(nb_parts):
            # invoke classmethod and pass own self instance
            yield self.__class__.from_instance(self)

    @staticmethod
    def from_instance(other_instance: "AbstractInsnGenerator", **changes: Any) -> "AbstractInsnGenerator":
        """Copy constructor from another instance"""
        # dumb implementation based on attrs
        return evolve(other_instance, **changes)

    def str_fuzzing_range(self) -> str:
        """Display fuzzing range according to the current Fuzzer type"""
        return "Undefined"


@define(slots=True)
class FinalLogResult:
    snapshot: ResultSnapshot
    insn: str
    len: int
    misc: str = ""


@runtime_checkable
class Splittable(Protocol):
    """Structural protocol for fuzzers that support dynamic mid-execution splitting.

    Any class implementing these two methods satisfies the protocol -- no inheritance needed.
    """

    def split_remaining(self) -> Optional["AbstractInsnGenerator"]: ...  # noqa: E704

    def remaining_range_size(self) -> int: ...  # noqa: E704
