"""Backend result schema and abstract base class."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class BackendResult:
    """Normalized result from processing a single instruction."""

    valid: bool
    length: int | None
    exit_type: str
    reg_delta: str | None = None
    misc: dict | None = None


class Backend(ABC):
    """Abstract base class for instruction-processing backends."""

    name: str
    kind: str  # "decoder" or "emulator"

    @abstractmethod
    def process(self, insn_bytes: bytes, exec_mode: int) -> BackendResult:
        """Process a single instruction. Must be stateless between calls."""
        ...

    def setup(self) -> None:
        """One-time initialization (load libraries, allocate state, etc.)."""

    def teardown(self) -> None:
        """Cleanup."""
