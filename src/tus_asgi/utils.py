"""
Utility functions for tus-asgi.
"""

import re
import hashlib
import base64
from typing import Dict, Optional, Tuple, Any
from datetime import datetime, timezone
import orjson


def validate_upload_id(upload_id: str) -> bool:
    """Validate upload ID format."""
    return bool(re.match(r"^[a-zA-Z0-9]{32}$", upload_id))


def parse_content_range(content_range: str) -> Tuple[int, int, Optional[int]]:
    """Parse Content-Range header.

    Returns:
        Tuple of (start, end, total_size)
        total_size is None if unknown (indicated by '*')
    """
    # Format: bytes start-end/total or bytes start-end/*
    match = re.match(r"bytes (\d+)-(\d+)/(\d+|\*)", content_range)
    if not match:
        raise ValueError("Invalid Content-Range format")

    start = int(match.group(1))
    end = int(match.group(2))
    total_str = match.group(3)
    total = None if total_str == "*" else int(total_str)

    return start, end, total


def format_http_date(dt: datetime) -> str:
    """Format datetime for HTTP headers (RFC 7231)."""
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def parse_http_date(date_str: str) -> datetime:
    """Parse HTTP date string to datetime."""
    try:
        return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S GMT").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        # Try alternative format
        return datetime.strptime(date_str, "%a, %d-%b-%Y %H:%M:%S GMT").replace(
            tzinfo=timezone.utc
        )


def calculate_checksum(data: bytes, algorithm: str) -> str:
    """Calculate checksum for data using specified algorithm."""
    algorithm = algorithm.lower()

    if algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha512":
        hasher = hashlib.sha512()
    elif algorithm == "crc32":
        import zlib

        crc = zlib.crc32(data) & 0xFFFFFFFF
        return base64.b64encode(crc.to_bytes(4, "big")).decode()
    else:
        raise ValueError(f"Unsupported checksum algorithm: {algorithm}")

    hasher.update(data)
    return base64.b64encode(hasher.digest()).decode()


def validate_metadata_key(key: str) -> bool:
    """Validate metadata key according to tus spec."""
    if not key:
        return False

    # Key MUST NOT contain spaces and commas and MUST NOT be empty
    if " " in key or "," in key:
        return False

    return True


def encode_metadata_value(value: str) -> str:
    """Encode metadata value for Upload-Metadata header."""
    return base64.b64encode(value.encode()).decode()


def decode_metadata_value(encoded_value: str) -> str:
    """Decode metadata value from Upload-Metadata header."""
    try:
        return base64.b64decode(encoded_value).decode()
    except Exception as e:
        raise ValueError(f"Invalid metadata encoding: {e}")


def parse_upload_concat(concat_header: str) -> Tuple[bool, bool, list]:
    """Parse Upload-Concat header.

    Returns:
        Tuple of (is_partial, is_final, partial_upload_urls)
    """
    concat_header = concat_header.strip()

    if concat_header == "partial":
        return True, False, []
    elif concat_header.startswith("final;"):
        urls = concat_header[6:].strip().split()
        return False, True, urls
    else:
        raise ValueError("Invalid Upload-Concat header format")


def extract_upload_id_from_url(url: str, base_path: str) -> Optional[str]:
    """Extract upload ID from URL path."""
    # Remove base path prefix
    if url.startswith(base_path):
        url = url[len(base_path) :]

    # Remove leading/trailing slashes
    url = url.strip("/")

    # Should be just the upload ID
    if validate_upload_id(url):
        return url

    return None


def get_safe_filename(filename: str, max_length: int = 255) -> str:
    """Get safe filename by removing dangerous characters."""
    # Remove path separators and other dangerous characters
    safe_chars = re.sub(r"[^\w\-_\.]", "_", filename)

    # Limit length
    if len(safe_chars) > max_length:
        name, ext = safe_chars.rsplit(".", 1) if "." in safe_chars else (safe_chars, "")
        name = name[: max_length - len(ext) - 1]
        safe_chars = f"{name}.{ext}" if ext else name

    return safe_chars


def validate_content_type(content_type: str, expected: str) -> bool:
    """Validate Content-Type header."""
    # Handle charset and other parameters
    content_type = content_type.split(";")[0].strip().lower()
    return content_type == expected.lower()


def get_request_size(headers: Dict[bytes, bytes]) -> Optional[int]:
    """Get request content length from headers."""
    content_length = headers.get(b"content-length")
    if content_length:
        try:
            return int(content_length.decode())
        except ValueError:
            return None
    return None


def is_request_method_override(headers: Dict[bytes, bytes]) -> Optional[str]:
    """Check for X-HTTP-Method-Override header."""
    override = headers.get(b"x-http-method-override")
    if override:
        return override.decode().upper()
    return None


class HeaderDict:
    """Case-insensitive header dictionary."""

    def __init__(self, headers: list):
        self._headers = {}
        for name, value in headers:
            key = name.decode().lower() if isinstance(name, bytes) else name.lower()
            val = value.decode() if isinstance(value, bytes) else value
            self._headers[key] = val

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get header value."""
        return self._headers.get(key.lower(), default)

    def __contains__(self, key: str) -> bool:
        """Check if header exists."""
        return key.lower() in self._headers

    def __getitem__(self, key: str) -> str:
        """Get header value (raises KeyError if not found)."""
        return self._headers[key.lower()]


def create_error_response_body(
    error_code: str, message: str, details: Optional[Dict[str, Any]] = None
) -> bytes:
    """Create JSON error response body."""
    error_data = {
        "error": {
            "code": error_code,
            "message": message,
        }
    }

    if details:
        error_data["error"]["details"] = details

    return orjson.dumps(error_data).encode()


def log_upload_event(
    event: str, upload_id: str, details: Optional[Dict[str, Any]] = None, logger=None
):
    """Log upload event for debugging/monitoring."""
    if logger:
        data = {
            "event": event,
            "upload_id": upload_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if details:
            data.update(details)

        logger.info("tus_upload_event", extra=data)
