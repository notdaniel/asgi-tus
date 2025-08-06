"""
Configuration settings for tus-asgi server.
"""

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class TusConfig:
    """Configuration for tus server."""

    # Protocol version
    version: str = "1.0.0"

    # Supported extensions
    extensions: set[str] = field(
        default_factory=lambda: {
            "creation",
            "creation-with-upload",
            "creation-defer-length",
            "termination",
            "checksum",
            "checksum-trailer",
            "expiration",
        }
    )

    # Maximum upload size in bytes (None = unlimited)
    max_size: int | None = None

    # Supported checksum algorithms
    checksum_algorithms: set[str] = field(
        default_factory=lambda: {"sha1", "md5", "sha256", "sha512", "crc32"}
    )

    # Default upload expiration time
    upload_expires: timedelta | None = field(default_factory=lambda: timedelta(days=7))

    # Upload URL pattern (for routing)
    upload_path: str = "/files"

    # Whether to allow CORS requests
    cors_enabled: bool = True

    # CORS origins (None = allow all)
    cors_origins: set[str] | None = None

    def get_supported_versions(self) -> str:
        """Get comma-separated list of supported versions."""
        return self.version

    def get_supported_extensions(self) -> str:
        """Get comma-separated list of supported extensions."""
        return ",".join(sorted(self.extensions))

    def get_supported_checksum_algorithms(self) -> str:
        """Get comma-separated list of supported checksum algorithms."""
        return ",".join(sorted(self.checksum_algorithms))

    def supports_extension(self, extension: str) -> bool:
        """Check if an extension is supported."""
        return extension in self.extensions
