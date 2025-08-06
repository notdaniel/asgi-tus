"""
tus-asgi: A Python ASGI implementation of the tus resumable upload protocol.

This package provides:
- Core tus protocol implementation
- Storage backend interface
- FastAPI and Starlette integrations
- Support for all standard tus extensions
"""

from .core import TusASGIApp
from .config import TusConfig
from .storage import StorageBackend, FileStorage

__version__ = "0.1.0"
__all__ = [
    "TusASGIApp",
    "TusConfig",
    "StorageBackend",
    "FileStorage",
    "TusFastAPIRouter",
    "create_tus_router",
    "TusStarletteApp",
    "create_tus_app",
    "TusMount",
]

try:
    from .integrations.fastapi import TusFastAPIRouter, create_tus_router

    __all__.extend(
        [
            "TusFastAPIRouter",
            "create_tus_router",
        ]
    )
except ImportError:
    pass

try:
    from .integrations.starlette import TusStarletteApp, create_tus_app, TusMount

    __all__.extend(
        [
            "TusStarletteApp",
            "create_tus_app",
            "TusMount",
        ]
    )
except ImportError:
    pass
