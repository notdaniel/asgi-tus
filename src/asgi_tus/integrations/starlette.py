"""
Starlette integration for asgi-tus.
"""

from typing import Optional, List, Dict, Any, Tuple, Union, Type

from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware import Middleware
from starlette.types import ASGIApp

from ..core import ASGITusApp
from ..config import TusConfig
from ..storage import StorageBackend


class TusStarletteApp:
    """Starlette application wrapper for tus protocol."""

    def __init__(
        self,
        storage: StorageBackend,
        config: Optional[TusConfig] = None,
        middleware: Optional[
            List[Union[Type[Any], Tuple[Type[Any], Dict[str, Any]]]]
        ] = None,
    ) -> None:
        self.storage = storage
        self.config = config or TusConfig()
        self.tus_app = ASGITusApp(storage, self.config)

        # Create Starlette app
        middleware_list: List[Middleware] = []
        if middleware:
            for mw in middleware:
                if isinstance(mw, tuple):
                    mw_cls, mw_kwargs = mw
                    middleware_list.append(Middleware(mw_cls, **mw_kwargs))  # type: ignore[arg-type]
                else:
                    middleware_list.append(Middleware(mw))  # type: ignore[arg-type]

        self.app = Starlette(
            routes=[
                Route(
                    f"{self.config.upload_path}/",
                    self._handle_creation,
                    methods=["POST", "OPTIONS"],
                ),
                Route(
                    f"{self.config.upload_path}/{{upload_id}}",
                    self._handle_upload,
                    methods=["HEAD", "PATCH", "DELETE"],
                ),
            ],
            middleware=middleware_list,
        )

    def get_app(self) -> Starlette:
        """Get the Starlette application."""
        return self.app

    async def _handle_creation(self, request: Request) -> Response:
        """Handle upload creation requests."""
        return await self._proxy_to_tus_app(request)

    async def _handle_upload(self, request: Request) -> Response:
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

        # Create ASGI scope from Starlette request
        scope = dict(request.scope)

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


def create_tus_app(
    storage: StorageBackend,
    config: Optional[TusConfig] = None,
    middleware: Optional[
        List[Union[Type[Any], Tuple[Type[Any], Dict[str, Any]]]]
    ] = None,
) -> Starlette:
    """Create a Starlette app for tus protocol.

    Args:
        storage: Storage backend implementation
        config: Optional tus configuration
        middleware: Optional list of Starlette middleware

    Returns:
        Starlette application configured for tus protocol

    Example:
        ```python
        from starlette.middleware.cors import CORSMiddleware
        from asgi_tus import FileStorage, create_tus_app

        storage = FileStorage("/tmp/uploads")
        middleware = [CORSMiddleware(allow_origins=["*"])]
        app = create_tus_app(storage, middleware=middleware)
        ```
    """
    tus_integration = TusStarletteApp(storage, config, middleware)
    return tus_integration.get_app()


class TusMount:
    """Mount point for tus protocol in existing Starlette apps."""

    def __init__(
        self,
        storage: StorageBackend,
        config: Optional[TusConfig] = None,
        path: str = "/files",
    ) -> None:
        self.storage = storage
        self.config = config or TusConfig()
        self.config.upload_path = ""  # Reset since we're mounting at a path
        self.tus_app = ASGITusApp(storage, self.config)
        self.path = path

    def get_mount(self) -> Mount:
        """Get Starlette Mount for tus protocol.

        Example:
            ```python
            from starlette.applications import Starlette
            from starlette.routing import Mount, Route
            from asgi_tus import FileStorage, TusMount

            storage = FileStorage("/tmp/uploads")
            tus_mount = TusMount(storage, path="/uploads")

            app = Starlette(routes=[
                Route("/", homepage),
                tus_mount.get_mount(),
            ])
            ```
        """
        return Mount(self.path, app=self.tus_app)  # type: ignore[arg-type]
