"""Backend registry — importing this package triggers registration of all backends."""

from bench.backends.base import get_backend, list_backends  # noqa: F401

# Import backends to trigger @register decorators.
# Backends that require optional native extensions guard their imports
# and skip registration if the extension is unavailable.
try:
    from bench.backends import xed  # noqa: F401
except ImportError:
    pass

try:
    from bench.backends import capstone_be  # noqa: F401
except ImportError:
    pass

try:
    from bench.backends import unicorn_be  # noqa: F401
except ImportError:
    pass
