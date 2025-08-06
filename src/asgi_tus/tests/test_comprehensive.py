"""
Comprehensive test suite for TUS protocol implementation.
Clean, readable tests without unnecessary class structure.
"""

import base64
import hashlib
import pytest

from .conftest import (
    call_asgi_app,
    get_response_headers,
    get_header_value,
    has_header,
    assert_status,
    assert_has_headers,
)

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


# Core Protocol Tests


async def test_options_server_capabilities(full_tus_app):
    """Test OPTIONS request returns all server capabilities."""
    messages = await call_asgi_app(full_tus_app, "OPTIONS", "/files")
    assert_status(messages, 204)

    headers = get_response_headers(messages)
    assert_has_headers(
        headers, "tus-resumable", "tus-version", "tus-extension", "tus-max-size"
    )

    # Verify all extensions are listed
    extensions = get_header_value(headers, "tus-extension").decode()
    expected = [
        "creation",
        "creation-with-upload",
        "creation-defer-length",
        "termination",
        "checksum",
        "expiration",
    ]
    for ext in expected:
        assert ext in extensions


async def test_options_includes_checksum_algorithms(full_tus_app):
    """Test OPTIONS includes all supported checksum algorithms."""
    messages = await call_asgi_app(full_tus_app, "OPTIONS", "/files")

    headers = get_response_headers(messages)
    assert has_header(headers, "tus-checksum-algorithm")

    algorithms = get_header_value(headers, "tus-checksum-algorithm").decode()
    for alg in ["sha1", "md5", "sha256", "crc32"]:
        assert alg in algorithms


async def test_head_upload_info(full_tus_app, temp_storage):
    """Test HEAD request returns complete upload information."""
    upload_info = await temp_storage.create_upload(
        length=100, metadata={"filename": "test.txt"}
    )

    headers = [(b"tus-resumable", b"1.0.0")]
    messages = await call_asgi_app(
        full_tus_app, "HEAD", f"/files/{upload_info.id}", headers
    )
    assert_status(messages, 200)

    response_headers = get_response_headers(messages)
    assert get_header_value(response_headers, "upload-offset") == b"0"
    assert get_header_value(response_headers, "upload-length") == b"100"
    assert get_header_value(response_headers, "cache-control") == b"no-store"
    assert has_header(response_headers, "upload-metadata")


async def test_patch_upload_data(full_tus_app, temp_storage):
    """Test PATCH request uploads data correctly."""
    upload_info = await temp_storage.create_upload(length=11)
    test_data = b"hello world"

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"11"),
        (b"upload-offset", b"0"),
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, test_data
    )
    assert_status(messages, 204)

    response_headers = get_response_headers(messages)
    assert get_header_value(response_headers, "upload-offset") == b"11"

    # Verify data was written
    stored_data = await temp_storage.read_chunk(upload_info.id, 0, 11)
    assert stored_data == test_data


# Creation Tests


async def test_create_upload_basic(full_tus_app):
    """Test basic upload creation."""
    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"upload-length", b"100"),
        (b"content-length", b"0"),
    ]

    messages = await call_asgi_app(full_tus_app, "POST", "/files", headers)
    assert_status(messages, 201)

    response_headers = get_response_headers(messages)
    assert has_header(response_headers, "location")
    location = get_header_value(response_headers, "location").decode()
    assert location.startswith("/files/")


async def test_create_upload_with_metadata(full_tus_app):
    """Test upload creation with metadata."""
    filename_b64 = base64.b64encode(b"test file.txt").decode()
    type_b64 = base64.b64encode(b"text/plain").decode()
    metadata = f"filename {filename_b64},type {type_b64},empty"

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"upload-length", b"100"),
        (b"upload-metadata", metadata.encode()),
        (b"content-length", b"0"),
    ]

    messages = await call_asgi_app(full_tus_app, "POST", "/files", headers)
    assert_status(messages, 201)


async def test_creation_with_upload(full_tus_app):
    """Test creation-with-upload extension."""
    test_data = b"hello"
    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"upload-length", b"5"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"5"),
    ]

    messages = await call_asgi_app(full_tus_app, "POST", "/files", headers, test_data)
    assert_status(messages, 201)

    response_headers = get_response_headers(messages)
    assert get_header_value(response_headers, "upload-offset") == b"5"


# Deferred Length Tests


async def test_create_deferred_length_upload(full_tus_app):
    """Test creating upload with deferred length."""
    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"upload-defer-length", b"1"),
        (b"content-length", b"0"),
    ]

    messages = await call_asgi_app(full_tus_app, "POST", "/files", headers)
    assert_status(messages, 201)


async def test_head_deferred_length_upload(full_tus_app, temp_storage):
    """Test HEAD on deferred length upload."""
    upload_info = await temp_storage.create_upload(defer_length=True)

    headers = [(b"tus-resumable", b"1.0.0")]
    messages = await call_asgi_app(
        full_tus_app, "HEAD", f"/files/{upload_info.id}", headers
    )

    response_headers = get_response_headers(messages)
    assert has_header(response_headers, "upload-defer-length")
    assert get_header_value(response_headers, "upload-defer-length") == b"1"


async def test_patch_set_deferred_length(full_tus_app, temp_storage):
    """Test PATCH that sets deferred length."""
    upload_info = await temp_storage.create_upload(defer_length=True)
    test_data = b"hello"

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"5"),
        (b"upload-offset", b"0"),
        (b"upload-length", b"5"),  # Set the deferred length
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, test_data
    )
    assert_status(messages, 204)

    # Verify length was set
    updated_info = await temp_storage.get_upload(upload_info.id)
    assert updated_info.length == 5
    assert not updated_info.defer_length


# Checksum Tests


async def test_patch_with_checksum_validation(full_tus_app, temp_storage):
    """Test PATCH with checksum validation."""
    upload_info = await temp_storage.create_upload(length=5)
    test_data = b"hello"
    expected_sha1 = base64.b64encode(hashlib.sha1(test_data).digest()).decode()

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"5"),
        (b"upload-offset", b"0"),
        (b"upload-checksum", f"sha1 {expected_sha1}".encode()),
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, test_data
    )
    assert_status(messages, 204)


async def test_patch_with_invalid_checksum(full_tus_app, temp_storage):
    """Test PATCH with invalid checksum returns 460."""
    upload_info = await temp_storage.create_upload(length=5)
    test_data = b"hello"

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"5"),
        (b"upload-offset", b"0"),
        (b"upload-checksum", b"sha1 invalidchecksum"),
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, test_data
    )
    assert_status(messages, 460)


# Termination Tests


async def test_delete_upload(full_tus_app, temp_storage):
    """Test DELETE request (termination extension)."""
    upload_info = await temp_storage.create_upload(length=100)

    headers = [(b"tus-resumable", b"1.0.0")]
    messages = await call_asgi_app(
        full_tus_app, "DELETE", f"/files/{upload_info.id}", headers
    )
    assert_status(messages, 204)

    # Upload should be deleted
    deleted_upload = await temp_storage.get_upload(upload_info.id)
    assert deleted_upload is None


# CORS Tests


async def test_options_cors_headers(full_tus_app):
    """Test OPTIONS request includes CORS headers."""
    headers = [(b"origin", b"https://example.com")]
    messages = await call_asgi_app(full_tus_app, "OPTIONS", "/files", headers)

    response_headers = get_response_headers(messages)
    assert_has_headers(
        response_headers,
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
    )


# Error Handling Tests


async def test_unsupported_method(full_tus_app):
    """Test unsupported HTTP method returns 405."""
    messages = await call_asgi_app(full_tus_app, "PUT", "/files")
    assert_status(messages, 405)

    response_headers = get_response_headers(messages)
    assert has_header(response_headers, "allow")


async def test_invalid_tus_version(full_tus_app):
    """Test request with invalid tus version returns 412."""
    headers = [
        (b"tus-resumable", b"0.5.0"),  # Invalid version
        (b"upload-length", b"100"),
        (b"content-length", b"0"),
    ]

    messages = await call_asgi_app(full_tus_app, "POST", "/files", headers)
    assert_status(messages, 412)

    response_headers = get_response_headers(messages)
    assert has_header(response_headers, "tus-version")


async def test_upload_not_found(full_tus_app):
    """Test request to non-existent upload returns 404."""
    headers = [(b"tus-resumable", b"1.0.0")]
    messages = await call_asgi_app(
        full_tus_app, "HEAD", "/files/nonexistent123456", headers
    )
    assert_status(messages, 404)


async def test_patch_offset_mismatch(full_tus_app, temp_storage):
    """Test PATCH with wrong offset returns 409."""
    upload_info = await temp_storage.create_upload(length=100)

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"10"),
        (b"upload-offset", b"50"),  # Wrong offset (should be 0)
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, b"1234567890"
    )
    assert_status(messages, 409)


async def test_patch_wrong_content_type(full_tus_app, temp_storage):
    """Test PATCH with wrong content type returns 415."""
    upload_info = await temp_storage.create_upload(length=10)

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"text/plain"),  # Wrong content type
        (b"content-length", b"5"),
        (b"upload-offset", b"0"),
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, b"hello"
    )
    assert_status(messages, 415)


async def test_patch_size_exceeds_declared_length(full_tus_app, temp_storage):
    """Test PATCH that would exceed declared length returns 400."""
    upload_info = await temp_storage.create_upload(length=5)

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"10"),  # Exceeds declared length
        (b"upload-offset", b"0"),
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, b"1234567890"
    )
    assert_status(messages, 400)


async def test_patch_missing_offset_header(full_tus_app, temp_storage):
    """Test PATCH with missing Upload-Offset header returns 400."""
    upload_info = await temp_storage.create_upload(length=100)

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"5"),
        # Missing Upload-Offset header
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, b"hello"
    )
    assert_status(messages, 400)


async def test_patch_invalid_offset_value(full_tus_app, temp_storage):
    """Test PATCH with invalid offset header value returns 400."""
    upload_info = await temp_storage.create_upload(length=100)

    headers = [
        (b"tus-resumable", b"1.0.0"),
        (b"content-type", b"application/offset+octet-stream"),
        (b"content-length", b"5"),
        (b"upload-offset", b"invalid"),  # Invalid offset
    ]

    messages = await call_asgi_app(
        full_tus_app, "PATCH", f"/files/{upload_info.id}", headers, b"hello"
    )
    assert_status(messages, 400)
