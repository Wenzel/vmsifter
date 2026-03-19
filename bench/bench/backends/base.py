"""Backend registry with @register decorator."""

import logging

from bench.schema import Backend

logger = logging.getLogger(__name__)

_registry: dict[str, type[Backend]] = {}


def register(cls: type[Backend]) -> type[Backend]:
    """Class decorator that registers a backend by its ``name`` attribute."""
    logger.debug("Registered backend %r", cls.name)
    _registry[cls.name] = cls
    return cls


def get_backend(name: str, exec_mode: int = 64) -> Backend:
    """Instantiate a registered backend by name."""
    logger.info("Instantiating backend %r (exec_mode=%d)", name, exec_mode)
    if name not in _registry:
        available = ", ".join(sorted(_registry)) or "(none)"
        raise KeyError(f"Unknown backend {name!r}. Available: {available}")
    return _registry[name](exec_mode)


def list_backends() -> list[str]:
    """Return sorted list of registered backend names."""
    return sorted(_registry)
