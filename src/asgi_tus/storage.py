"""
Storage backend interface and implementations for asgi-tus.
"""

import uuid
from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone
from pathlib import Path
import aiofiles
import orjson


class UploadInfo:
    """Information about an upload."""

    def __init__(
        self,
        id: str,
        offset: int = 0,
        length: Optional[int] = None,
        metadata: Optional[Dict[str, str]] = None,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        is_partial: bool = False,
        is_final: bool = False,
        partial_uploads: Optional[List[str]] = None,
        filename: Optional[str] = None,
        defer_length: bool = False,
    ):
        self.id = id
        self.offset = offset
        self.length = length
        self.metadata = metadata or {}
        self.created_at = created_at or datetime.now(timezone.utc)
        self.expires_at = expires_at
        self.is_partial = is_partial
        self.is_final = is_final
        self.partial_uploads = partial_uploads or []
        self.filename = filename
        self.defer_length = defer_length

    @property
    def is_completed(self) -> bool:
        """Check if upload is completed."""
        return self.length is not None and self.offset >= self.length

    @property
    def is_expired(self) -> bool:
        """Check if upload has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    async def create_upload(
        self,
        length: Optional[int] = None,
        metadata: Optional[Dict[str, str]] = None,
        expires_at: Optional[datetime] = None,
        defer_length: bool = False,
        is_partial: bool = False,
        is_final: bool = False,
        partial_uploads: Optional[List[str]] = None,
    ) -> UploadInfo:
        """Create a new upload."""
        pass

    @abstractmethod
    async def get_upload(self, upload_id: str) -> Optional[UploadInfo]:
        """Get upload information."""
        pass

    @abstractmethod
    async def write_chunk(self, upload_id: str, offset: int, data: bytes) -> int:
        """Write data chunk to upload. Returns bytes written."""
        pass

    @abstractmethod
    async def read_chunk(self, upload_id: str, offset: int, length: int) -> bytes:
        """Read data chunk from upload."""
        pass

    @abstractmethod
    async def set_upload_length(self, upload_id: str, length: int) -> bool:
        """Set deferred upload length. Returns True if successful."""
        pass

    @abstractmethod
    async def delete_upload(self, upload_id: str) -> bool:
        """Delete an upload. Returns True if successful."""
        pass

    @abstractmethod
    async def concatenate_uploads(
        self, final_upload_id: str, partial_upload_ids: List[str]
    ) -> bool:
        """Concatenate partial uploads into final upload."""
        pass

    @abstractmethod
    async def cleanup_expired_uploads(self) -> int:
        """Clean up expired uploads. Returns number of uploads cleaned."""
        pass


class FileStorage(StorageBackend):
    """File system storage backend."""

    def __init__(self, upload_dir: str = "/tmp/tus-uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.info_dir = self.upload_dir / ".info"
        self.info_dir.mkdir(exist_ok=True)

    def _get_upload_path(self, upload_id: str) -> Path:
        """Get file path for upload data."""
        return self.upload_dir / upload_id

    def _get_info_path(self, upload_id: str) -> Path:
        """Get file path for upload metadata."""
        return self.info_dir / f"{upload_id}.info"

    async def create_upload(
        self,
        length: Optional[int] = None,
        metadata: Optional[Dict[str, str]] = None,
        expires_at: Optional[datetime] = None,
        defer_length: bool = False,
        is_partial: bool = False,
        is_final: bool = False,
        partial_uploads: Optional[List[str]] = None,
    ) -> UploadInfo:
        """Create a new upload."""
        upload_id = str(uuid.uuid4()).replace("-", "")
        upload_info = UploadInfo(
            id=upload_id,
            length=length,
            metadata=metadata,
            expires_at=expires_at,
            defer_length=defer_length,
            is_partial=is_partial,
            is_final=is_final,
            partial_uploads=partial_uploads,
        )

        # Save upload info
        await self._save_upload_info(upload_info)

        # Create empty data file if not final upload
        if not is_final:
            upload_path = self._get_upload_path(upload_id)
            async with aiofiles.open(upload_path, "wb"):
                pass  # Create empty file

        return upload_info

    async def get_upload(self, upload_id: str) -> Optional[UploadInfo]:
        """Get upload information."""
        info_path = self._get_info_path(upload_id)
        try:
            async with aiofiles.open(info_path, "r") as f:
                data: Dict[str, Any] = orjson.loads(await f.read())

                # Parse datetime fields
                created_at = None
                expires_at = None
                if data.get("created_at"):
                    created_at = datetime.fromisoformat(data["created_at"])
                if data.get("expires_at"):
                    expires_at = datetime.fromisoformat(data["expires_at"])

                return UploadInfo(
                    id=data["id"],
                    offset=data["offset"],
                    length=data.get("length"),
                    metadata=data.get("metadata", {}),
                    created_at=created_at,
                    expires_at=expires_at,
                    is_partial=data.get("is_partial", False),
                    is_final=data.get("is_final", False),
                    partial_uploads=data.get("partial_uploads", []),
                    defer_length=data.get("defer_length", False),
                )
        except (FileNotFoundError, orjson.JSONDecodeError):
            return None

    async def write_chunk(self, upload_id: str, offset: int, data: bytes) -> int:
        """Write data chunk to upload."""
        upload_path = self._get_upload_path(upload_id)

        # Ensure file exists and is large enough
        if not upload_path.exists():
            # Create empty file if it doesn't exist
            async with aiofiles.open(upload_path, "wb"):
                pass

        # Open in r+b mode and extend file if necessary
        async with aiofiles.open(upload_path, "r+b") as f:
            # Get current file size
            await f.seek(0, 2)  # Seek to end
            file_size = await f.tell()

            # If offset is beyond file size, extend file with zeros
            if offset > file_size:
                await f.write(b"\x00" * (offset - file_size))

            await f.seek(offset)
            bytes_written = await f.write(data)
            await f.flush()

        # Update offset in info
        upload_info = await self.get_upload(upload_id)
        if upload_info:
            upload_info.offset = offset + bytes_written
            await self._save_upload_info(upload_info)

        return bytes_written

    async def read_chunk(self, upload_id: str, offset: int, length: int) -> bytes:
        """Read data chunk from upload."""
        upload_path = self._get_upload_path(upload_id)

        async with aiofiles.open(upload_path, "rb") as f:
            await f.seek(offset)
            return await f.read(length)

    async def set_upload_length(self, upload_id: str, length: int) -> bool:
        """Set deferred upload length."""
        upload_info = await self.get_upload(upload_id)
        if not upload_info or not upload_info.defer_length:
            return False

        upload_info.length = length
        upload_info.defer_length = False
        await self._save_upload_info(upload_info)
        return True

    async def delete_upload(self, upload_id: str) -> bool:
        """Delete an upload."""
        upload_path = self._get_upload_path(upload_id)
        info_path = self._get_info_path(upload_id)

        try:
            if upload_path.exists():
                upload_path.unlink()
            if info_path.exists():
                info_path.unlink()
            return True
        except OSError:
            return False

    async def concatenate_uploads(
        self, final_upload_id: str, partial_upload_ids: List[str]
    ) -> bool:
        """Concatenate partial uploads into final upload."""
        final_path = self._get_upload_path(final_upload_id)

        try:
            async with aiofiles.open(final_path, "wb") as final_file:
                total_offset = 0
                for partial_id in partial_upload_ids:
                    partial_path = self._get_upload_path(partial_id)
                    if partial_path.exists():
                        async with aiofiles.open(partial_path, "rb") as partial_file:
                            while True:
                                chunk = await partial_file.read(8192)
                                if not chunk:
                                    break
                                await final_file.write(chunk)
                                total_offset += len(chunk)

            # Update final upload info
            final_info = await self.get_upload(final_upload_id)
            if final_info:
                final_info.offset = total_offset
                final_info.length = total_offset
                await self._save_upload_info(final_info)
            return True
        except OSError:
            return False

    async def cleanup_expired_uploads(self) -> int:
        """Clean up expired uploads."""
        count = 0
        info_files = []

        try:
            info_files = [f for f in self.info_dir.iterdir() if f.suffix == ".info"]
        except OSError:
            return 0

        for info_file in info_files:
            upload_id = info_file.stem
            upload_info = await self.get_upload(upload_id)

            if upload_info and upload_info.is_expired:
                if await self.delete_upload(upload_id):
                    count += 1

        return count

    async def _save_upload_info(self, upload_info: UploadInfo) -> None:
        """Save upload info to disk."""
        info_path = self._get_info_path(upload_info.id)

        data = {
            "id": upload_info.id,
            "offset": upload_info.offset,
            "length": upload_info.length,
            "metadata": upload_info.metadata,
            "is_partial": upload_info.is_partial,
            "is_final": upload_info.is_final,
            "partial_uploads": upload_info.partial_uploads,
            "defer_length": upload_info.defer_length,
        }

        if upload_info.created_at:
            data["created_at"] = upload_info.created_at.isoformat()
        if upload_info.expires_at:
            data["expires_at"] = upload_info.expires_at.isoformat()

        async with aiofiles.open(info_path, "w") as f:
            encoded_data: bytes = orjson.dumps(data)
            await f.write(encoded_data.decode("utf-8"))
