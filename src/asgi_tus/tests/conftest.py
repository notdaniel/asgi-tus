"""
Shared test configuration and utilities.
"""

import tempfile
from unittest.mock import AsyncMock

import pytest_asyncio

from ..core import ASGITusApp
from ..config import TusConfig
from ..storage import FileStorage


@pytest_asyncio.fixture
async def temp_storage():
    """Create temporary storage for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage = FileStorage(temp_dir)
        yield storage


@pytest_asyncio.fixture
def tus_config():
    """Create test configuration."""
    return TusConfig(
        max_size=1024 * 1024,  # 1MB
        extensions={"creation", "creation-with-upload", "termination", "checksum"},
        checksum_algorithms={"sha1", "md5"},
    )


@pytest_asyncio.fixture
def full_config():
    """Create full-featured test configuration."""
    return TusConfig(
        max_size=1024 * 1024,  # 1MB
        extensions={
            "creation",
            "creation-with-upload",
            "creation-defer-length",
            "termination",
            "checksum",
            "expiration",
        },
        checksum_algorithms={"sha1", "md5", "sha256", "crc32"},
        cors_enabled=True,
    )


@pytest_asyncio.fixture
async def tus_app(temp_storage, tus_config):
    """Create basic tus ASGI app for testing."""
    return ASGITusApp(temp_storage, tus_config)


@pytest_asyncio.fixture
async def full_tus_app(temp_storage, full_config):
    """Create full-featured tus ASGI app for testing."""
    return ASGITusApp(temp_storage, full_config)


async def call_asgi_app(app, method="GET", path="/files", headers=None, body=b""):
    """Helper to call ASGI app and return response messages."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
    }

    receive = AsyncMock()
    receive.return_value = {
        "type": "http.request",
        "body": body,
        "more_body": False,
    }

    sent_messages = []

    async def send(message):
        sent_messages.append(message)

    await app(scope, receive, send)
    return sent_messages


def get_header_value(headers, header_name):
    """Get header value with case-insensitive lookup."""
    header_name_lower = header_name.lower()
    for key, value in headers.items():
        if key.decode().lower() == header_name_lower:
            return value
    return None


def has_header(headers, header_name):
    """Check if header exists with case-insensitive lookup."""
    return get_header_value(headers, header_name) is not None


def get_response_headers(messages):
    """Extract headers dict from response messages."""
    if not messages:
        return {}
    return dict(messages[0].get("headers", []))


def assert_status(messages, expected_status):
    """Assert response status matches expected."""
    assert len(messages) >= 1
    assert messages[0]["status"] == expected_status


def assert_has_headers(headers, *header_names):
    """Assert all specified headers exist."""
    for header_name in header_names:
        assert has_header(headers, header_name), f"Missing header: {header_name}"
