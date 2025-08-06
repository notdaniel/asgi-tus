"""
Comprehensive test suite for TUS protocol implementation.
Tests all endpoints, methods, and extensions.
"""

import asyncio
import base64
import hashlib
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from ..core import TusASGIApp, TusError, TusProtocolError
from ..config import TusConfig
from ..storage import FileStorage, UploadInfo


@pytest_asyncio.fixture
async def temp_storage():
    """Create temporary storage for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage = FileStorage(temp_dir)
        yield storage


@pytest_asyncio.fixture
def base_config():
    """Base configuration for testing."""
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
async def tus_app(temp_storage, base_config):
    """Create TUS ASGI app for testing."""
    return TusASGIApp(temp_storage, base_config)


@pytest_asyncio.fixture
def mock_scope():
    """Base HTTP scope for testing."""
    return {
        "type": "http",
        "method": "GET",
        "path": "/files",
        "headers": [],
    }


async def call_app(app, scope, body=b"", more_body=False):
    """Helper to call ASGI app and collect response."""
    receive = AsyncMock()
    receive.return_value = {
        "type": "http.request",
        "body": body,
        "more_body": more_body,
    }
    
    sent_messages = []
    async def send(message):
        sent_messages.append(message)
    
    await app(scope, receive, send)
    return sent_messages


def get_headers_dict(messages):
    """Extract headers from response messages."""
    if not messages:
        return {}
    return dict(messages[0].get("headers", []))


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


@pytest.mark.asyncio(loop_scope="class")
class TestCoreProtocol:
    """Test core TUS protocol functionality."""
    
    async def test_options_server_capabilities(self, tus_app, mock_scope):
        """Test OPTIONS request returns server capabilities."""
        scope = {**mock_scope, "method": "OPTIONS", "path": "/files"}
        messages = await call_app(tus_app, scope)
        
        assert len(messages) >= 2
        assert messages[0]["status"] == 204
        
        headers = get_headers_dict(messages)
        assert has_header(headers, "tus-resumable")
        assert has_header(headers, "tus-version")
        assert has_header(headers, "tus-extension")
        assert has_header(headers, "tus-max-size")
        
        # Verify extension list
        extensions = get_header_value(headers, "tus-extension").decode()
        expected_extensions = ["creation", "creation-with-upload", "creation-defer-length", 
                              "termination", "checksum", "expiration"]
        for ext in expected_extensions:
            assert ext in extensions
    
    async def test_options_with_checksum_algorithms(self, tus_app, mock_scope):
        """Test OPTIONS includes checksum algorithms."""
        scope = {**mock_scope, "method": "OPTIONS", "path": "/files"}
        messages = await call_app(tus_app, scope)
        
        headers = get_headers_dict(messages)
        assert has_header(headers, "tus-checksum-algorithm")
        
        algorithms = get_header_value(headers, "tus-checksum-algorithm").decode()
        for alg in ["sha1", "md5", "sha256", "crc32"]:
            assert alg in algorithms
    
    async def test_head_upload_info(self, tus_app, temp_storage, mock_scope):
        """Test HEAD request returns upload information."""
        # Create upload first
        upload_info = await temp_storage.create_upload(length=100, metadata={"filename": "test.txt"})
        
        scope = {
            **mock_scope,
            "method": "HEAD",
            "path": f"/files/{upload_info.id}",
            "headers": [(b"tus-resumable", b"1.0.0")],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 200
        
        headers = get_headers_dict(messages)
        assert get_header_value(headers, "upload-offset") == b"0"
        assert get_header_value(headers, "upload-length") == b"100"
        assert get_header_value(headers, "cache-control") == b"no-store"
        assert has_header(headers, "upload-metadata")
    
    async def test_head_nonexistent_upload(self, tus_app, mock_scope):
        """Test HEAD request for non-existent upload returns 404."""
        scope = {
            **mock_scope,
            "method": "HEAD", 
            "path": "/files/nonexistent123456789012345678901234",
            "headers": [(b"tus-resumable", b"1.0.0")],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 404
    
    async def test_patch_upload_data(self, tus_app, temp_storage, mock_scope):
        """Test PATCH request uploads data correctly."""
        upload_info = await temp_storage.create_upload(length=11)
        test_data = b"hello world"
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"11"),
                (b"upload-offset", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 204
        
        headers = get_headers_dict(messages)
        assert get_header_value(headers, "upload-offset") == b"11"
        
        # Verify data was written
        stored_data = await temp_storage.read_chunk(upload_info.id, 0, 11)
        assert stored_data == test_data
    
    async def test_patch_wrong_content_type(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with wrong content type returns 415."""
        upload_info = await temp_storage.create_upload(length=10)
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"text/plain"),  # Wrong content type
                (b"content-length", b"5"),
                (b"upload-offset", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope, b"hello")
        assert messages[0]["status"] == 415
    
    async def test_patch_offset_mismatch(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with wrong offset returns 409."""
        upload_info = await temp_storage.create_upload(length=100)
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"10"),
                (b"upload-offset", b"50"),  # Wrong offset (should be 0)
            ],
        }
        
        messages = await call_app(tus_app, scope, b"1234567890")
        assert messages[0]["status"] == 409
    
    async def test_patch_empty_data(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with empty data returns current offset."""
        upload_info = await temp_storage.create_upload(length=100)
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"0"),
                (b"upload-offset", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope, b"")
        assert messages[0]["status"] == 204
        
        headers = get_headers_dict(messages)
        assert get_header_value(headers, "upload-offset") == b"0"
    
    async def test_invalid_tus_version(self, tus_app, mock_scope):
        """Test request with invalid TUS version returns 412."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"0.5.0"),  # Invalid version
                (b"upload-length", b"100"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 412
        
        headers = get_headers_dict(messages)
        assert has_header(headers, "tus-version")
    
    async def test_missing_tus_resumable_header(self, tus_app, mock_scope):
        """Test request without Tus-Resumable header returns 400."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"upload-length", b"100"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 400


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestCreationExtension:
    """Test upload creation extension."""
    
    async def test_create_upload_basic(self, tus_app, mock_scope):
        """Test basic upload creation."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"100"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 201
        
        headers = get_headers_dict(messages)
        assert has_header(headers, "location")
        location = get_header_value(headers, "location").decode()
        assert location.startswith("/files/")
        assert len(location.split("/")[-1]) == 32  # UUID without dashes
    
    async def test_create_upload_with_metadata(self, tus_app, mock_scope):
        """Test upload creation with metadata."""
        # Base64 encode metadata values
        filename_b64 = base64.b64encode(b"test_file.txt").decode()
        
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"100"),
                (b"upload-metadata", f"filename {filename_b64},type".encode()),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 201
    
    async def test_create_upload_deferred_length(self, tus_app, mock_scope):
        """Test upload creation with deferred length."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-defer-length", b"1"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 201
    
    async def test_create_upload_invalid_defer_length(self, tus_app, mock_scope):
        """Test creation with invalid defer length value."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-defer-length", b"2"),  # Invalid value
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 400
    
    async def test_create_upload_missing_length_headers(self, tus_app, mock_scope):
        """Test creation without length headers returns 400."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 400
    
    async def test_create_upload_exceeds_max_size(self, tus_app, mock_scope):
        """Test creation with size exceeding limit returns 413."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"2097152"),  # 2MB, exceeds 1MB limit
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 413
    
    async def test_create_empty_upload(self, tus_app, mock_scope):
        """Test creation of empty file (0 bytes)."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"0"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 201


@pytest.mark.asyncio 
@pytest.mark.asyncio(loop_scope="class")
class TestCreationWithUploadExtension:
    """Test creation-with-upload extension."""
    
    async def test_creation_with_upload(self, tus_app, mock_scope):
        """Test creation with initial upload data."""
        test_data = b"hello"
        
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"5"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 201
        
        headers = get_headers_dict(messages)
        assert get_header_value(headers, "upload-offset") == b"5"
    
    async def test_creation_with_upload_wrong_content_type(self, tus_app, mock_scope):
        """Test creation-with-upload with wrong content type."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"5"),
                (b"content-type", b"text/plain"),  # Wrong content type
                (b"content-length", b"5"),
            ],
        }
        
        messages = await call_app(tus_app, scope, b"hello")
        assert messages[0]["status"] == 415
    
    async def test_creation_with_partial_upload(self, tus_app, mock_scope):
        """Test creation with partial initial data."""
        test_data = b"hello"
        
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"11"),  # Total size larger than initial data
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 201
        
        headers = get_headers_dict(messages)
        assert get_header_value(headers, "upload-offset") == b"5"


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestChecksumExtension:
    """Test checksum extension."""
    
    def calculate_checksum(self, data, algorithm):
        """Calculate checksum for data."""
        if algorithm == "sha1":
            hasher = hashlib.sha1()
        elif algorithm == "md5":
            hasher = hashlib.md5()
        elif algorithm == "sha256":
            hasher = hashlib.sha256()
        elif algorithm == "crc32":
            import zlib
            crc = zlib.crc32(data) & 0xFFFFFFFF
            return base64.b64encode(crc.to_bytes(4, "big")).decode()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher.update(data)
        return base64.b64encode(hasher.digest()).decode()
    
    async def test_patch_with_valid_checksum(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with valid checksum."""
        upload_info = await temp_storage.create_upload(length=11)
        test_data = b"hello world"
        checksum = self.calculate_checksum(test_data, "sha1")
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"11"),
                (b"upload-offset", b"0"),
                (b"upload-checksum", f"sha1 {checksum}".encode()),
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 204
    
    async def test_patch_with_invalid_checksum(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with invalid checksum returns 460."""
        upload_info = await temp_storage.create_upload(length=11)
        test_data = b"hello world"
        wrong_checksum = "invalidchecksum"
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"11"),
                (b"upload-offset", b"0"),
                (b"upload-checksum", f"sha1 {wrong_checksum}".encode()),
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 460
    
    async def test_patch_with_unsupported_algorithm(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with unsupported checksum algorithm."""
        upload_info = await temp_storage.create_upload(length=11)
        test_data = b"hello world"
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"11"),
                (b"upload-offset", b"0"),
                (b"upload-checksum", b"blake2 invalidchecksum"),  # Unsupported algorithm
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 400
    
    async def test_creation_with_upload_checksum(self, tus_app, mock_scope):
        """Test creation-with-upload with checksum validation."""
        test_data = b"hello"
        checksum = self.calculate_checksum(test_data, "md5")
        
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"5"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
                (b"upload-checksum", f"md5 {checksum}".encode()),
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 201


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestTerminationExtension:
    """Test termination extension."""
    
    async def test_delete_upload(self, tus_app, temp_storage, mock_scope):
        """Test DELETE request terminates upload."""
        upload_info = await temp_storage.create_upload(length=100)
        
        scope = {
            **mock_scope,
            "method": "DELETE",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 204
        
        # Verify upload was deleted
        deleted_upload = await temp_storage.get_upload(upload_info.id)
        assert deleted_upload is None
    
    async def test_delete_nonexistent_upload(self, tus_app, mock_scope):
        """Test DELETE on non-existent upload returns 404."""
        scope = {
            **mock_scope,
            "method": "DELETE",
            "path": "/files/nonexistent123456789012345678901234",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 404


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestExpirationExtension:
    """Test expiration extension."""
    
    async def test_head_includes_expiration(self, tus_app, temp_storage, mock_scope):
        """Test HEAD response includes Upload-Expires header."""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        upload_info = await temp_storage.create_upload(length=100, expires_at=expires_at)
        
        scope = {
            **mock_scope,
            "method": "HEAD",
            "path": f"/files/{upload_info.id}",
            "headers": [(b"tus-resumable", b"1.0.0")],
        }
        
        messages = await call_app(tus_app, scope)
        headers = get_headers_dict(messages)
        assert has_header(headers, "upload-expires")
    
    async def test_patch_includes_expiration(self, tus_app, temp_storage, mock_scope):
        """Test PATCH response includes Upload-Expires header."""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        upload_info = await temp_storage.create_upload(length=5, expires_at=expires_at)
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
                (b"upload-offset", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope, b"hello")
        headers = get_headers_dict(messages)
        assert has_header(headers, "upload-expires")


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestCORSSupport:
    """Test CORS functionality."""
    
    async def test_options_includes_cors_headers(self, tus_app, mock_scope):
        """Test OPTIONS request includes CORS headers."""
        scope = {
            **mock_scope,
            "method": "OPTIONS",
            "path": "/files",
            "headers": [(b"origin", b"https://example.com")],
        }
        
        messages = await call_app(tus_app, scope)
        headers = get_headers_dict(messages)
        
        assert has_header(headers, "access-control-allow-origin")
        assert has_header(headers, "access-control-allow-methods")
        assert has_header(headers, "access-control-allow-headers")
        assert has_header(headers, "access-control-expose-headers")
    
    async def test_upload_options_cors(self, tus_app, temp_storage, mock_scope):
        """Test OPTIONS on upload resource includes CORS headers."""
        upload_info = await temp_storage.create_upload(length=100)
        
        scope = {
            **mock_scope,
            "method": "OPTIONS",
            "path": f"/files/{upload_info.id}",
            "headers": [(b"origin", b"https://example.com")],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 204
        
        headers = get_headers_dict(messages)
        assert has_header(headers, "access-control-allow-origin")


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestErrorHandling:
    """Test error handling and edge cases."""
    
    async def test_unsupported_method(self, tus_app, mock_scope):
        """Test unsupported HTTP method returns 405."""
        scope = {**mock_scope, "method": "PUT", "path": "/files"}
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 405
        
        headers = get_headers_dict(messages)
        assert has_header(headers, "allow")
    
    async def test_invalid_upload_path(self, tus_app, mock_scope):
        """Test request to invalid path returns 404."""
        scope = {**mock_scope, "method": "GET", "path": "/invalid"}
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 404
    
    async def test_non_http_scope(self, tus_app):
        """Test non-HTTP scope returns 404."""
        scope = {"type": "websocket"}
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 404
    
    async def test_patch_size_exceeds_declared_length(self, tus_app, temp_storage, mock_scope):
        """Test PATCH that would exceed declared length returns 400."""
        upload_info = await temp_storage.create_upload(length=5)
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"10"),  # Exceeds declared length
                (b"upload-offset", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope, b"1234567890")
        assert messages[0]["status"] == 400
    
    async def test_patch_missing_headers(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with missing required headers."""
        upload_info = await temp_storage.create_upload(length=100)
        
        # Missing Upload-Offset
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
            ],
        }
        
        messages = await call_app(tus_app, scope, b"hello")
        assert messages[0]["status"] == 400
    
    async def test_patch_invalid_offset_header(self, tus_app, temp_storage, mock_scope):
        """Test PATCH with invalid offset header value."""
        upload_info = await temp_storage.create_upload(length=100)
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
                (b"upload-offset", b"invalid"),  # Invalid offset
            ],
        }
        
        messages = await call_app(tus_app, scope, b"hello")
        assert messages[0]["status"] == 400


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestDeferredLength:
    """Test deferred length functionality."""
    
    async def test_create_deferred_length_upload(self, tus_app, mock_scope):
        """Test creating upload with deferred length."""
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-defer-length", b"1"),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 201
    
    async def test_head_deferred_length_upload(self, tus_app, temp_storage, mock_scope):
        """Test HEAD on deferred length upload includes defer header."""
        upload_info = await temp_storage.create_upload(defer_length=True)
        
        scope = {
            **mock_scope,
            "method": "HEAD",
            "path": f"/files/{upload_info.id}",
            "headers": [(b"tus-resumable", b"1.0.0")],
        }
        
        messages = await call_app(tus_app, scope)
        headers = get_headers_dict(messages)
        assert has_header(headers, "upload-defer-length")
        assert get_header_value(headers, "upload-defer-length") == b"1"
    
    async def test_patch_set_deferred_length(self, tus_app, temp_storage, mock_scope):
        """Test PATCH that sets deferred length."""
        upload_info = await temp_storage.create_upload(defer_length=True)
        test_data = b"hello"
        
        scope = {
            **mock_scope,
            "method": "PATCH",
            "path": f"/files/{upload_info.id}",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"content-type", b"application/offset+octet-stream"),
                (b"content-length", b"5"),
                (b"upload-offset", b"0"),
                (b"upload-length", b"5"),  # Set the deferred length
            ],
        }
        
        messages = await call_app(tus_app, scope, test_data)
        assert messages[0]["status"] == 204
        
        # Verify length was set
        updated_info = await temp_storage.get_upload(upload_info.id)
        assert updated_info.length == 5
        assert not updated_info.defer_length


@pytest.mark.asyncio
@pytest.mark.asyncio(loop_scope="class")
class TestMetadataHandling:
    """Test metadata encoding/decoding."""
    
    async def test_metadata_encoding_decoding(self, tus_app, temp_storage, mock_scope):
        """Test metadata is properly encoded and decoded."""
        # Create upload with metadata
        filename_b64 = base64.b64encode(b"test file.txt").decode()
        type_b64 = base64.b64encode(b"text/plain").decode()
        metadata_header = f"filename {filename_b64},type {type_b64},empty"
        
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"100"),
                (b"upload-metadata", metadata_header.encode()),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        assert messages[0]["status"] == 201
        
        # Extract upload ID from location
        headers = get_headers_dict(messages)
        location = get_header_value(headers, "location").decode()
        upload_id = location.split("/")[-1]
        
        # Verify metadata was saved correctly
        upload_info = await temp_storage.get_upload(upload_id)
        assert upload_info.metadata["filename"] == "test file.txt"
        assert upload_info.metadata["type"] == "text/plain"
        assert upload_info.metadata["empty"] == ""
    
    async def test_invalid_metadata_encoding(self, tus_app, mock_scope):
        """Test invalid metadata encoding is handled."""
        # Invalid base64 in metadata
        invalid_metadata = "filename invalidbase64=="
        
        scope = {
            **mock_scope,
            "method": "POST",
            "path": "/files",
            "headers": [
                (b"tus-resumable", b"1.0.0"),
                (b"upload-length", b"100"),
                (b"upload-metadata", invalid_metadata.encode()),
                (b"content-length", b"0"),
            ],
        }
        
        messages = await call_app(tus_app, scope)
        # Should handle gracefully - either 400 or create with empty metadata
        assert messages[0]["status"] in [201, 400]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])