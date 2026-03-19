"""Backend registry with @register decorator."""

from bench.schema import Backend

_registry: dict[str, type[Backend]] = {}


def register(cls: type[Backend]) -> type[Backend]:
    """Class decorator that registers a backend by its ``name`` attribute."""
    _registry[cls.name] = cls
    return cls


def get_backend(name: str) -> Backend:
    """Instantiate a registered backend by name."""
    if name not in _registry:
        available = ", ".join(sorted(_registry)) or "(none)"
        raise KeyError(f"Unknown backend {name!r}. Available: {available}")
    return _registry[name]()


def list_backends() -> list[str]:
    """Return sorted list of registered backend names."""
    return sorted(_registry)
