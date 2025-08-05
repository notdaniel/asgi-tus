"""
Core tus protocol ASGI application.
"""

import re
import hashlib
import base64
from typing import Any
from datetime import datetime, timezone

from .config import TusConfig
from .storage import StorageBackend


class TusError(Exception):
    """Base exception for tus protocol errors."""

    def __init__(
        self, status_code: int, message: str, headers: dict[str, str] | None = None
    ):
        self.status_code = status_code
        self.message = message
        self.headers = headers or {}
        super().__init__(message)


class TusProtocolError(TusError):
    """Tus protocol validation error."""

    ...


class TusASGIApp:
    """Main tus ASGI application."""

    def __init__(self, storage: StorageBackend, config: TusConfig | None = None):
        self.storage = storage
        self.config = config or TusConfig()

        # Compile URL pattern for upload resources
        self.upload_pattern = re.compile(
            rf"^{re.escape(self.config.upload_path)}/([a-zA-Z0-9]+)/?$"
        )

    async def __call__(self, scope: dict[str, Any], receive, send):
        """ASGI application entry point."""
        if scope["type"] != "http":
            await self._send_error(send, 404, "Not Found")
            return

        try:
            await self._handle_request(scope, receive, send)
        except TusError as e:
            await self._send_tus_error(send, e, scope)
        except Exception:
            # Add CORS headers to 500 errors if enabled
            headers = {}
            if self.config.cors_enabled:
                headers.update(self._get_cors_headers(scope))
            await self._send_response(send, 500, headers, b"Internal Server Error")

    async def _handle_request(self, scope: dict[str, Any], receive, send):
        """Handle HTTP request."""
        method = scope["method"]
        path = scope["path"]

        # Check if this is an upload resource request
        match = self.upload_pattern.match(path)
        if match:
            upload_id = match.group(1)
            await self._handle_upload_request(method, upload_id, scope, receive, send)
            return

        # Check if this is creation endpoint
        if path == self.config.upload_path or path == f"{self.config.upload_path}/":
            if method == "POST":
                await self._handle_creation_request(scope, receive, send)
            elif method == "OPTIONS":
                await self._handle_options_request(scope, receive, send)
            else:
                raise TusError(405, "Method Not Allowed", {"Allow": "POST, OPTIONS"})
            return

        # Not a tus endpoint
        raise TusError(404, "Not Found")

    async def _handle_upload_request(
        self, method: str, upload_id: str, scope: dict[str, Any], receive, send
    ):
        """Handle requests to upload resources."""
        if method == "HEAD":
            await self._handle_head_request(upload_id, scope, receive, send)
        elif method == "PATCH":
            await self._handle_patch_request(upload_id, scope, receive, send)
        elif method == "DELETE":
            await self._handle_delete_request(upload_id, scope, receive, send)
        elif method == "OPTIONS":
            await self._handle_upload_options_request(upload_id, scope, receive, send)
        else:
            raise TusError(
                405, "Method Not Allowed", {"Allow": "HEAD, PATCH, DELETE, OPTIONS"}
            )

    async def _handle_options_request(self, scope: dict[str, Any], receive, send):
        """Handle OPTIONS request for server capabilities."""
        headers = {
            "Tus-Resumable": self.config.version,
            "Tus-Version": self.config.get_supported_versions(),
            "Tus-Extension": self.config.get_supported_extensions(),
        }

        if self.config.max_size:
            headers["Tus-Max-Size"] = str(self.config.max_size)

        if self.config.supports_extension("checksum"):
            headers["Tus-Checksum-Algorithm"] = (
                self.config.get_supported_checksum_algorithms()
            )

        # Add CORS headers if enabled
        if self.config.cors_enabled:
            headers.update(self._get_cors_headers(scope))

        await self._send_response(send, 204, headers)

    async def _handle_head_request(
        self, upload_id: str, scope: dict[str, Any], receive, send
    ):
        """Handle HEAD request to get upload info."""
        await self._validate_tus_resumable(scope)

        upload_info = await self.storage.get_upload(upload_id)
        if not upload_info:
            raise TusError(404, "Not Found")

        if upload_info.is_expired:
            raise TusError(410, "Gone")

        headers = {
            "Tus-Resumable": self.config.version,
            "Upload-Offset": str(upload_info.offset),
            "Cache-Control": "no-store",
        }

        # Add Upload-Length if known
        if upload_info.length is not None:
            headers["Upload-Length"] = str(upload_info.length)

        # Add Upload-Defer-Length if length is deferred
        if upload_info.defer_length:
            headers["Upload-Defer-Length"] = "1"

        # Add metadata if present
        if upload_info.metadata:
            headers["Upload-Metadata"] = self._encode_metadata(upload_info.metadata)

        # Add Upload-Concat for concatenation extension
        if upload_info.is_partial:
            headers["Upload-Concat"] = "partial"
        elif upload_info.is_final:
            partial_urls = " ".join(
                f"{self.config.upload_path}/{pid}"
                for pid in upload_info.partial_uploads
            )
            headers["Upload-Concat"] = f"final;{partial_urls}"

        # Add expiration if configured
        if upload_info.expires_at and self.config.supports_extension("expiration"):
            headers["Upload-Expires"] = upload_info.expires_at.strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )

        # Add CORS headers if enabled
        if self.config.cors_enabled:
            headers.update(self._get_cors_headers(scope))

        await self._send_response(send, 200, headers)

    async def _handle_patch_request(
        self, upload_id: str, scope: dict[str, Any], receive, send
    ):
        """Handle PATCH request to upload data."""
        headers_dict = dict(scope["headers"])

        await self._validate_tus_resumable(scope)

        # Validate Content-Type
        content_type = headers_dict.get(b"content-type", b"").decode()
        if content_type != "application/offset+octet-stream":
            raise TusError(415, "Unsupported Media Type")

        # Get upload info
        upload_info = await self.storage.get_upload(upload_id)
        if not upload_info:
            raise TusError(404, "Not Found")

        if upload_info.is_expired:
            raise TusError(410, "Gone")

        # Final uploads cannot be modified
        if upload_info.is_final:
            raise TusError(403, "Forbidden")

        # Get and validate Upload-Offset
        offset_header = headers_dict.get(b"upload-offset")
        if not offset_header:
            raise TusError(400, "Missing Upload-Offset header")

        try:
            client_offset = int(offset_header.decode())
        except ValueError:
            raise TusError(400, "Invalid Upload-Offset header")

        if client_offset != upload_info.offset:
            raise TusError(409, "Conflict")

        # Get Content-Length
        content_length_header = headers_dict.get(b"content-length")
        if not content_length_header:
            raise TusError(400, "Missing Content-Length header")

        try:
            content_length = int(content_length_header.decode())
        except ValueError:
            raise TusError(400, "Invalid Content-Length header")

        if content_length == 0:
            # Empty PATCH request, just return current offset
            response_headers = {
                "Tus-Resumable": self.config.version,
                "Upload-Offset": str(upload_info.offset),
            }
            await self._send_response(send, 204, response_headers)
            return

        # Check if upload length is deferred and this PATCH sets it
        upload_length_header = headers_dict.get(b"upload-length")
        if upload_info.defer_length and upload_length_header:
            try:
                upload_length = int(upload_length_header.decode())
                await self.storage.set_upload_length(upload_id, upload_length)
                upload_info.length = upload_length
                upload_info.defer_length = False
            except ValueError:
                raise TusError(400, "Invalid Upload-Length header")

        # Check size limits
        if upload_info.length is not None:
            if client_offset + content_length > upload_info.length:
                raise TusError(400, "Upload size exceeds declared length")

        if self.config.max_size:
            if client_offset + content_length > self.config.max_size:
                raise TusError(413, "Request Entity Too Large")

        # Read request body
        body_data = await self._read_request_body(receive, content_length)

        # Validate checksum if provided
        checksum_header = headers_dict.get(b"upload-checksum")
        if checksum_header and self.config.supports_extension("checksum"):
            await self._validate_checksum(body_data, checksum_header.decode())

        # Write data to storage
        bytes_written = await self.storage.write_chunk(
            upload_id, client_offset, body_data
        )
        new_offset = client_offset + bytes_written

        # Prepare response headers
        response_headers = {
            "Tus-Resumable": self.config.version,
            "Upload-Offset": str(new_offset),
        }

        # Add expiration header if configured
        if upload_info.expires_at and self.config.supports_extension("expiration"):
            response_headers["Upload-Expires"] = upload_info.expires_at.strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )

        # Add CORS headers if enabled
        if self.config.cors_enabled:
            response_headers.update(self._get_cors_headers(scope))

        await self._send_response(send, 204, response_headers)

    async def _handle_creation_request(self, scope: dict[str, Any], receive, send):
        """Handle POST request to create new upload."""
        headers_dict = dict(scope["headers"])

        await self._validate_tus_resumable(scope)

        # Parse headers
        upload_length = None
        defer_length = False
        metadata = {}
        is_partial = False
        is_final = False
        partial_uploads = []

        # Handle Upload-Length or Upload-Defer-Length
        upload_length_header = headers_dict.get(b"upload-length")
        defer_length_header = headers_dict.get(b"upload-defer-length")

        if upload_length_header:
            try:
                upload_length = int(upload_length_header.decode())
            except ValueError:
                raise TusError(400, "Invalid Upload-Length header")
        elif defer_length_header:
            if defer_length_header.decode() == "1":
                defer_length = True
            else:
                raise TusError(400, "Invalid Upload-Defer-Length header")
        else:
            raise TusError(400, "Missing Upload-Length or Upload-Defer-Length header")

        # Check size limits
        if upload_length is not None and self.config.max_size:
            if upload_length > self.config.max_size:
                raise TusError(413, "Request Entity Too Large")

        # Handle Upload-Metadata
        metadata_header = headers_dict.get(b"upload-metadata")
        if metadata_header:
            metadata = self._decode_metadata(metadata_header.decode())

        # Handle Upload-Concat for concatenation extension
        concat_header = headers_dict.get(b"upload-concat")
        if concat_header and self.config.supports_extension("concatenation"):
            concat_value = concat_header.decode()
            if concat_value == "partial":
                is_partial = True
            elif concat_value.startswith("final;"):
                is_final = True
                partial_urls = concat_value[6:].split()  # Remove "final;" prefix
                partial_uploads = [url.split("/")[-1] for url in partial_urls]
                upload_length = None  # Final uploads don't specify length

        # Calculate expiration time
        expires_at = None
        if self.config.upload_expires and self.config.supports_extension("expiration"):
            expires_at = datetime.now(timezone.utc) + self.config.upload_expires

        # Create upload
        upload_info = await self.storage.create_upload(
            length=upload_length,
            metadata=metadata,
            expires_at=expires_at,
            defer_length=defer_length,
            is_partial=is_partial,
            is_final=is_final,
            partial_uploads=partial_uploads,
        )

        # Handle creation-with-upload extension
        content_length_header = headers_dict.get(b"content-length")
        initial_offset = 0

        if content_length_header and self.config.supports_extension(
            "creation-with-upload"
        ):
            try:
                content_length = int(content_length_header.decode())
                if content_length > 0:
                    # Validate Content-Type for creation-with-upload
                    content_type = headers_dict.get(b"content-type", b"").decode()
                    if content_type != "application/offset+octet-stream":
                        raise TusError(415, "Unsupported Media Type")

                    # Read and write initial data
                    body_data = await self._read_request_body(receive, content_length)

                    # Validate checksum if provided
                    checksum_header = headers_dict.get(b"upload-checksum")
                    if checksum_header and self.config.supports_extension("checksum"):
                        await self._validate_checksum(
                            body_data, checksum_header.decode()
                        )

                    bytes_written = await self.storage.write_chunk(
                        upload_info.id, 0, body_data
                    )
                    initial_offset = bytes_written
            except ValueError:
                raise TusError(400, "Invalid Content-Length header")

        # Handle concatenation if this is a final upload
        if is_final:
            await self.storage.concatenate_uploads(upload_info.id, partial_uploads)

        # Prepare response headers
        upload_url = f"{self.config.upload_path}/{upload_info.id}"
        response_headers = {
            "Tus-Resumable": self.config.version,
            "Location": upload_url,
        }

        # Add Upload-Offset for creation-with-upload
        if initial_offset > 0:
            response_headers["Upload-Offset"] = str(initial_offset)

        # Add expiration header if configured
        if expires_at and self.config.supports_extension("expiration"):
            response_headers["Upload-Expires"] = expires_at.strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )

        # Add CORS headers if enabled
        if self.config.cors_enabled:
            response_headers.update(self._get_cors_headers(scope))

        await self._send_response(send, 201, response_headers)

    async def _handle_upload_options_request(
        self, upload_id: str, scope: dict[str, Any], receive, send
    ):
        """Handle OPTIONS request to upload resource for CORS preflight."""
        headers = {
            "Tus-Resumable": self.config.version,
        }

        # Add CORS headers if enabled
        if self.config.cors_enabled:
            headers.update(self._get_cors_headers(scope))

        await self._send_response(send, 204, headers)

    async def _handle_delete_request(
        self, upload_id: str, scope: dict[str, Any], receive, send
    ):
        """Handle DELETE request to terminate upload."""
        if not self.config.supports_extension("termination"):
            raise TusError(404, "Not Found")

        await self._validate_tus_resumable(scope)

        upload_info = await self.storage.get_upload(upload_id)
        if not upload_info:
            raise TusError(404, "Not Found")

        await self.storage.delete_upload(upload_id)

        response_headers = {
            "Tus-Resumable": self.config.version,
        }

        # Add CORS headers if enabled
        if self.config.cors_enabled:
            response_headers.update(self._get_cors_headers(scope))

        await self._send_response(send, 204, response_headers)

    async def _validate_tus_resumable(self, scope: dict[str, Any]):
        """Validate Tus-Resumable header."""
        headers_dict = dict(scope["headers"])
        tus_resumable = headers_dict.get(b"tus-resumable")

        if not tus_resumable:
            raise TusError(400, "Missing Tus-Resumable header")

        version = tus_resumable.decode()
        if version != self.config.version:
            raise TusProtocolError(
                412,
                "Precondition Failed",
                {
                    "Tus-Resumable": self.config.version,
                    "Tus-Version": self.config.get_supported_versions(),
                },
            )

    async def _validate_checksum(self, data: bytes, checksum_header: str):
        """Validate upload checksum."""
        try:
            algorithm, encoded_checksum = checksum_header.split(" ", 1)
        except ValueError:
            raise TusError(400, "Invalid Upload-Checksum header format")

        if algorithm not in self.config.checksum_algorithms:
            raise TusError(400, f"Checksum algorithm '{algorithm}' not supported")

        # Calculate checksum
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
            calculated_checksum = base64.b64encode(crc.to_bytes(4, "big")).decode()
        else:
            raise TusError(400, f"Unsupported checksum algorithm: {algorithm}")

        if algorithm != "crc32":
            hasher.update(data)
            calculated_checksum = base64.b64encode(hasher.digest()).decode()

        if calculated_checksum != encoded_checksum:
            raise TusError(460, "Checksum Mismatch")

    def _encode_metadata(self, metadata: dict[str, str]) -> str:
        """Encode metadata for Upload-Metadata header."""
        pairs = []
        for key, value in metadata.items():
            if value:
                encoded_value = base64.b64encode(value.encode()).decode()
                pairs.append(f"{key} {encoded_value}")
            else:
                pairs.append(key)
        return ",".join(pairs)

    def _decode_metadata(self, metadata_header: str) -> dict[str, str]:
        """Decode metadata from Upload-Metadata header."""
        metadata = {}
        if not metadata_header.strip():
            return metadata

        pairs = metadata_header.split(",")
        for pair in pairs:
            pair = pair.strip()
            if " " in pair:
                key, encoded_value = pair.split(" ", 1)
                try:
                    value = base64.b64decode(encoded_value).decode()
                    metadata[key] = value
                except Exception:
                    raise TusError(400, "Invalid metadata encoding")
            else:
                metadata[pair] = ""

        return metadata

    def _get_cors_headers(self, scope: dict[str, Any]) -> dict[str, str]:
        """Get CORS headers."""
        headers = {}

        if self.config.cors_origins is None:
            headers["Access-Control-Allow-Origin"] = "*"
        else:
            origin = dict(scope["headers"]).get(b"origin", b"").decode()
            if origin in self.config.cors_origins:
                headers["Access-Control-Allow-Origin"] = origin

        headers["Access-Control-Allow-Methods"] = (
            "GET, HEAD, POST, PATCH, DELETE, OPTIONS"
        )
        headers["Access-Control-Allow-Headers"] = (
            "Authorization, Content-Type, Tus-Resumable, Upload-Offset, "
            "Upload-Length, Upload-Metadata, Upload-Concat, Upload-Defer-Length, "
            "Upload-Checksum, X-HTTP-Method-Override"
        )
        headers["Access-Control-Expose-Headers"] = (
            "Location, Tus-Resumable, Tus-Version, Tus-Extension, Tus-Max-Size, "
            "Upload-Offset, Upload-Length, Upload-Metadata, Upload-Expires, "
            "Upload-Concat, Tus-Checksum-Algorithm"
        )

        return headers

    async def _read_request_body(self, receive, content_length: int) -> bytes:
        """Read request body."""
        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                body += chunk
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                raise TusError(400, "Client disconnected")

        if len(body) != content_length:
            raise TusError(400, "Content-Length mismatch")

        return body

    async def _send_response(
        self,
        send,
        status_code: int,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ):
        """Send HTTP response."""
        response_headers = []
        if headers:
            for name, value in headers.items():
                response_headers.append([name.encode(), value.encode()])

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": response_headers,
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )

    async def _send_error(self, send, status_code: int, message: str):
        """Send error response."""
        await self._send_response(send, status_code, body=message.encode())

    async def _send_tus_error(
        self, send, error: TusError, scope: dict[str, Any] = None
    ):
        """Send tus protocol error response."""
        headers = {"Tus-Resumable": self.config.version}
        headers.update(error.headers)

        # Add CORS headers if enabled and scope is available
        if self.config.cors_enabled and scope:
            headers.update(self._get_cors_headers(scope))

        await self._send_response(
            send, error.status_code, headers, error.message.encode()
        )
