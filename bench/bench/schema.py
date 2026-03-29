"""Backend result schema and abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class BackendResult:
    """Normalized result from processing a single instruction."""

    valid: bool
    length: int | None
    exit_type: str
    reg_delta: str | None = None
    misc: dict | None = None


@dataclass(frozen=True)
class ParsedExitType:
    """Structured representation of a VMSifter CSV exit-type field."""

    kind: str
    vmexit_reason: int | None = None
    interrupt_type: str | None = None
    interrupt_vector: str | None = None
    ept_qual: str | None = None
    raw: str = ""


@dataclass(frozen=True)
class InvalidInstructionHexError(ValueError):
    """Raised when a CSV row contains a non-hexadecimal ``insn`` value."""

    insn_hex: str
    raw_row: Mapping[str, str]

    def __str__(self) -> str:
        return f"invalid instruction hex {self.insn_hex!r}"


def parse_exit_type(value: str) -> ParsedExitType:
    """Parse a VMSifter CSV exit-type string into a structured representation."""
    value = value.strip()
    if value == "interrupted":
        return ParsedExitType(kind="interrupted", raw=value)

    parts = value.split()
    if not parts or not parts[0].startswith("vmexit:"):
        return ParsedExitType(kind="unknown", raw=value)

    try:
        vmexit_reason = int(parts[0].split(":", 1)[1], 10)
    except ValueError:
        return ParsedExitType(kind="unknown", raw=value)

    interrupt_type = None
    interrupt_vector = None
    ept_qual = None
    for part in parts[1:]:
        key, sep, rest = part.partition(":")
        if sep != ":":
            continue
        if key == "interrupt_type":
            interrupt_type = rest
        elif key == "interrupt_vector":
            interrupt_vector = rest
        elif key == "ept":
            ept_qual = rest
    return ParsedExitType(
        kind="vmexit",
        vmexit_reason=vmexit_reason,
        interrupt_type=interrupt_type,
        interrupt_vector=interrupt_vector,
        ept_qual=ept_qual,
        raw=value,
    )


def _parse_optional_int(value: str | None) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    return int(value, 10)


def parse_instruction_hex(row: Mapping[str, str]) -> bytes:
    """Parse the ``insn`` column and raise a structured error when malformed."""
    insn_hex = row.get("insn", "").strip()
    try:
        return bytes.fromhex(insn_hex)
    except ValueError as exc:
        raise InvalidInstructionHexError(insn_hex=insn_hex, raw_row=dict(row)) from exc


@dataclass(frozen=True)
class ReferenceRow:
    """Typed representation of an input CSV row."""

    insn: bytes
    length: int | None
    exit_type: str
    raw: Mapping[str, str]
    parsed_exit_type: ParsedExitType

    @classmethod
    def from_csv_row(cls, row: Mapping[str, str]) -> "ReferenceRow":
        exit_type = row.get("exit-type", "").strip()
        return cls(
            insn=parse_instruction_hex(row),
            length=_parse_optional_int(row.get("length")),
            exit_type=exit_type,
            raw=dict(row),
            parsed_exit_type=parse_exit_type(exit_type),
        )

    def expected_xed_exit_type(self) -> str | None:
        """Return the expected XED exit type when the reference row is comparable."""
        if self.parsed_exit_type.kind == "vmexit" and self.parsed_exit_type.vmexit_reason == 37:
            return "valid"
        if (
            self.parsed_exit_type.kind == "vmexit"
            and self.parsed_exit_type.interrupt_type == "hw_exc"
            and self.parsed_exit_type.interrupt_vector == "invalid_opcode"
        ):
            return "fault/UD"
        return None

    def is_xed_comparable(self) -> bool:
        """Return whether the row is comparable against XED in the current model."""
        return self.expected_xed_exit_type() is not None


@dataclass(frozen=True)
class ValidationIssue:
    """One discrepancy found while validating a backend result."""

    field: str
    expected: object | None
    actual: object | None
    message: str


@dataclass(frozen=True)
class ValidationReport:
    """Structured validation outcome for one input row."""

    comparable: bool
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.issues

    @classmethod
    def skip(cls) -> "ValidationReport":
        return cls(comparable=False, issues=())


class Backend(ABC):
    """Abstract base class for instruction-processing backends."""

    name: str
    kind: str  # "decoder" or "emulator"

    @abstractmethod
    def __init__(self, exec_mode: int) -> None:
        """Initialize the backend for the given execution mode (32 or 64)."""
        ...

    @abstractmethod
    def process(self, insn_bytes: bytes) -> BackendResult:
        """Process a single instruction. Must be stateless between calls."""
        ...

    def validate(self, reference: ReferenceRow, result: BackendResult) -> ValidationReport:
        """Validate a backend result against a typed reference row."""
        raise NotImplementedError(f"{self.name} validation is not implemented")

    def close(self) -> None:
        """Cleanup. Override to release resources."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
