"""
FastAPI integration for tus-asgi.
"""

from typing import Optional, List, Dict, Any, Tuple, Callable, Awaitable
from fastapi import APIRouter, Request, Response
from fastapi.responses import Response as FastAPIResponse

from ..core import TusASGIApp
from ..config import TusConfig
from ..storage import StorageBackend


class TusFastAPIRouter:
    """FastAPI router for tus protocol endpoints."""

    def __init__(
        self,
        storage: StorageBackend,
        config: Optional[TusConfig] = None,
        prefix: str = "/files",
    ) -> None:
        self.storage = storage
        self.config = config or TusConfig()
        self.config.upload_path = prefix
        self.tus_app = TusASGIApp(storage, self.config)
        self.router = APIRouter(prefix=prefix)

        # Add routes
        self.router.add_api_route(
            "/",
            self._handle_creation,
            methods=["POST", "OPTIONS"],
            response_class=FastAPIResponse,
        )

        self.router.add_api_route(
            "/{upload_id}",
            self._handle_upload,
            methods=["HEAD", "PATCH", "DELETE", "OPTIONS"],
            response_class=FastAPIResponse,
        )

    def get_router(self) -> APIRouter:
        """Get the FastAPI router."""
        return self.router

    async def _handle_creation(self, request: Request) -> Response:
        """Handle upload creation requests."""
        return await self._proxy_to_tus_app(request)

    async def _handle_upload(self, request: Request, upload_id: str) -> Response:
        """Handle upload resource requests."""
        return await self._proxy_to_tus_app(request)

    async def _proxy_to_tus_app(self, request: Request) -> Response:
        """Proxy request to tus ASGI app."""

        # Create custom receive callable for the request body
        body_sent = False

        async def receive() -> Dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                body = await request.body()
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }
            return {"type": "http.disconnect"}

        # Prepare response data
        response_started = False
        status_code = 200
        headers: List[Tuple[bytes, bytes]] = []
        body_parts: List[bytes] = []

        async def send(message: Dict[str, Any]) -> None:
            nonlocal response_started, status_code, headers, body_parts

            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                body_parts.append(message.get("body", b""))

        # Create ASGI scope from FastAPI request
        scope = {
            "type": "http",
            "method": request.method,
            "path": str(request.url.path),
            "query_string": str(request.url.query).encode(),
            "headers": [
                (name.encode().lower(), value.encode())
                for name, value in request.headers.items()
            ],
        }

        # Call tus ASGI app
        await self.tus_app(scope, receive, send)

        # Build response
        response_headers: Dict[str, str] = {}
        for header_pair in headers:
            name = header_pair[0].decode()
            value = header_pair[1].decode()
            response_headers[name] = value

        response_body = b"".join(body_parts)

        return Response(
            content=response_body,
            status_code=status_code,
            headers=response_headers,
        )


def create_tus_router(
    storage: StorageBackend,
    config: Optional[TusConfig] = None,
    prefix: str = "/files",
) -> APIRouter:
    """Create a FastAPI router for tus protocol.

    Args:
        storage: Storage backend implementation
        config: Optional tus configuration
        prefix: URL prefix for upload endpoints

    Returns:
        FastAPI APIRouter configured for tus protocol

    Example:
        ```python
        from fastapi import FastAPI
        from tus_asgi import FileStorage, create_tus_router

        app = FastAPI()
        storage = FileStorage("/tmp/uploads")
        tus_router = create_tus_router(storage, prefix="/uploads")
        app.include_router(tus_router)
        ```
    """
    tus_integration = TusFastAPIRouter(storage, config, prefix)
    return tus_integration.get_router()
