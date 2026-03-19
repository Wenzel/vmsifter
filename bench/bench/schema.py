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
    def __init__(self, exec_mode: int) -> None:
        """Initialize the backend for the given execution mode (32 or 64)."""
        ...

    @abstractmethod
    def process(self, insn_bytes: bytes) -> BackendResult:
        """Process a single instruction. Must be stateless between calls."""
        ...

    def close(self) -> None:
        """Cleanup. Override to release resources."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
