"""
Test suite for core tus protocol implementation.
"""

import tempfile
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from ..core import TusASGIApp
from ..config import TusConfig
from ..storage import FileStorage


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
async def tus_app(temp_storage, tus_config):
    """Create tus ASGI app for testing."""
    return TusASGIApp(temp_storage, tus_config)


@pytest.mark.asyncio(loop_scope="class")
class TestTusCore:
    """Test core tus protocol functionality."""

    async def test_options_request(self, tus_app):
        """Test OPTIONS request for server capabilities."""
        scope = {
            "type": "http",
            "method": "OPTIONS",
            "path": "/files",
            "headers": [],
        }

        receive = AsyncMock()
        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Check response
        assert len(sent_messages) >= 2
        start_msg = sent_messages[0]
        assert start_msg["type"] == "http.response.start"
        assert start_msg["status"] == 204

        # Check headers
        headers = dict(start_msg["headers"])
        assert has_header(headers, "tus-resumable")
        assert has_header(headers, "tus-version")
        assert has_header(headers, "tus-extension")

    async def test_create_upload(self, tus_app):
        """Test upload creation."""
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"100"),
                (b"content-length", b"0"),
            ],
        }

        receive = AsyncMock()
        receive.return_value = {"type": "http.request", "body": b"", "more_body": False}

        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Check response
        assert len(sent_messages) >= 2
        start_msg = sent_messages[0]
        assert start_msg["type"] == "http.response.start"
        assert start_msg["status"] == 201

        # Check Location header
        headers = dict(start_msg["headers"])
        assert has_header(headers, "location")
        location = get_header_value(headers, "location").decode()
        assert location.startswith("/files/")

    async def test_head_request(self, tus_app, temp_storage):
        """Test HEAD request to get upload info."""
        # First create an upload
        upload_info = await temp_storage.create_upload(length=100)

        scope = {
            "type": "http",
            "method": "HEAD",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
            ],
        }

        receive = AsyncMock()
        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Check response
        start_msg = sent_messages[0]
        assert start_msg["status"] == 200

        # Check headers
        headers = dict(start_msg["headers"])
        assert has_header(headers, "upload-offset")
        assert get_header_value(headers, "upload-offset") == b"0"
        assert has_header(headers, "upload-length")
        assert get_header_value(headers, "upload-length") == b"100"

    async def test_patch_upload(self, tus_app, temp_storage):
        """Test PATCH request to upload data."""
        # Create upload
        upload_info = await temp_storage.create_upload(length=11)
        test_data = b"hello world"

        scope = {
            "type": "http",
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"11"),
                (b"upload-offset", b"0"),
            ],
        }

        receive = AsyncMock()
        receive.return_value = {
            "type": "http.request",
            "body": test_data,
            "more_body": False,
        }

        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Check response
        start_msg = sent_messages[0]
        assert start_msg["status"] == 204

        # Check new offset
        headers = dict(start_msg["headers"])
        assert get_header_value(headers, "upload-offset") == b"11"

        # Verify data was written
        stored_data = await temp_storage.read_chunk(upload_info.id, 0, 11)
        assert stored_data == test_data

    async def test_invalid_tus_version(self, tus_app):
        """Test request with invalid tus version."""
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"0.5.0"),  # Invalid version
                (b"upload-length", b"100"),
                (b"content-length", b"0"),
            ],
        }

        receive = AsyncMock()
        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Should return 412 Precondition Failed
        start_msg = sent_messages[0]
        assert start_msg["status"] == 412

        headers = dict(start_msg["headers"])
        assert has_header(headers, "tus-version")

    async def test_upload_not_found(self, tus_app):
        """Test request to non-existent upload."""
        scope = {
            "type": "http",
            "method": "HEAD",
            "path": "/files/nonexistent123456789012345678901234",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
            ],
        }

        receive = AsyncMock()
        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Should return 404
        start_msg = sent_messages[0]
        assert start_msg["status"] == 404

    async def test_patch_offset_mismatch(self, tus_app, temp_storage):
        """Test PATCH with incorrect offset."""
        upload_info = await temp_storage.create_upload(length=100)

        scope = {
            "type": "http",
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"10"),
                (b"upload-offset", b"50"),  # Wrong offset (should be 0)
            ],
        }

        receive = AsyncMock()
        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Should return 409 Conflict
        start_msg = sent_messages[0]
        assert start_msg["status"] == 409


@pytest.mark.asyncio(loop_scope="class")
class TestTusExtensions:
    """Test tus protocol extensions."""

    async def test_termination_extension(self, tus_app, temp_storage):
        """Test DELETE request (termination extension)."""
        upload_info = await temp_storage.create_upload(length=100)

        scope = {
            "type": "http",
            "method": "DELETE",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
            ],
        }

        receive = AsyncMock()
        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Should return 204
        start_msg = sent_messages[0]
        assert start_msg["status"] == 204

        # Upload should be deleted
        deleted_upload = await temp_storage.get_upload(upload_info.id)
        assert deleted_upload is None

    async def test_creation_with_upload(self, tus_app):
        """Test creation with initial upload data."""
        test_data = b"hello"

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"5"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
            ],
        }

        receive = AsyncMock()
        receive.return_value = {
            "type": "http.request",
            "body": test_data,
            "more_body": False,
        }

        sent_messages = []

        async def send(message):
            sent_messages.append(message)

        await tus_app(scope, receive, send)

        # Should return 201 with Upload-Offset
        start_msg = sent_messages[0]
        assert start_msg["status"] == 201

        headers = dict(start_msg["headers"])
        assert get_header_value(headers, "upload-offset") == b"5"


if __name__ == "__main__":
    pytest.main([__file__])
