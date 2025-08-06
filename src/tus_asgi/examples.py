"""
Example applications showing how to use tus-asgi.
"""

from datetime import timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List

from starlette.middleware import Middleware

from .config import TusConfig
from .storage import FileStorage
from .core import TusASGIApp


def create_basic_asgi_app(upload_dir: str = "/tmp/tus-uploads") -> TusASGIApp:
    """Create a basic tus ASGI application.

    Example usage with uvicorn:
        ```python
        from tus_asgi.examples import create_basic_asgi_app

        app = create_basic_asgi_app("/tmp/uploads")

        # Run with: uvicorn module:app --host 0.0.0.0 --port 8000
        ```
    """
    storage = FileStorage(upload_dir)
    config = TusConfig(
        max_size=100 * 1024 * 1024,  # 100MB
        upload_expires=timedelta(hours=24),
        cors_enabled=True,
    )
    return TusASGIApp(storage, config)


def create_fastapi_app(upload_dir: str = "/tmp/tus-uploads") -> Any:
    """Create a FastAPI application with tus support.

    Example usage:
        ```python
        from tus_asgi.examples import create_fastapi_app

        app = create_fastapi_app("/tmp/uploads")

        # Run with: uvicorn module:app --host 0.0.0.0 --port 8000
        ```
    """
    try:
        from fastapi import FastAPI
        from .integrations.fastapi import create_tus_router
    except ImportError:
        raise ImportError("FastAPI is required for this example")

    app = FastAPI(
        title="Tus Upload Server",
        description="Resumable file upload server using tus protocol",
        version="1.0.0",
    )

    storage = FileStorage(upload_dir)
    config = TusConfig(
        max_size=500 * 1024 * 1024,  # 500MB
        upload_expires=timedelta(days=7),
        cors_enabled=True,
    )

    tus_router = create_tus_router(storage, config, prefix="/files")
    app.include_router(tus_router, tags=["uploads"])

    @app.get("/")
    async def root() -> Dict[str, str]:
        return {
            "message": "Tus resumable upload server",
            "upload_endpoint": "/files/",
            "version": "1.0.0",
        }

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "healthy"}

    return app


def create_starlette_app(upload_dir: str = "/tmp/tus-uploads") -> Any:
    """Create a Starlette application with tus support.

    Example usage:
        ```python
        from tus_asgi.examples import create_starlette_app

        app = create_starlette_app("/tmp/uploads")

        # Run with: uvicorn module:app --host 0.0.0.0 --port 8000
        ```
    """
    try:
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import JSONResponse
        from starlette.middleware.cors import CORSMiddleware
        from .integrations.starlette import TusMount
    except ImportError:
        raise ImportError("Starlette is required for this example")

    storage = FileStorage(upload_dir)
    config = TusConfig(
        max_size=500 * 1024 * 1024,  # 500MB
        upload_expires=timedelta(days=7),
        cors_enabled=True,
    )

    async def homepage(request: Any) -> Any:
        return JSONResponse(
            {
                "message": "Tus resumable upload server",
                "upload_endpoint": "/files/",
                "version": "1.0.0",
            }
        )

    async def health(request: Any) -> Any:
        return JSONResponse({"status": "healthy"})

    tus_mount = TusMount(storage, config, path="/files")

    app = Starlette(
        routes=[
            Route("/", homepage),
            Route("/health", health),
            tus_mount.get_mount(),
        ],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["*"],
                allow_headers=["*"],
            )
        ],
    )

    return app


def create_production_fastapi_app(
    upload_dir: str,
    max_size: int = 1024 * 1024 * 1024,  # 1GB
    upload_expires_hours: int = 48,
    cors_origins: Optional[List[str]] = None,
) -> Any:
    """Create a production-ready FastAPI application with tus support.

    Args:
        upload_dir: Directory to store uploads
        max_size: Maximum upload size in bytes
        upload_expires_hours: Hours until uploads expire
        cors_origins: List of allowed CORS origins

    Example usage:
        ```python
        from tus_asgi.examples import create_production_fastapi_app

        app = create_production_fastapi_app(
            upload_dir="/var/uploads",
            max_size=2 * 1024 * 1024 * 1024,  # 2GB
            upload_expires_hours=72,
            cors_origins=["https://myapp.com", "https://admin.myapp.com"]
        )
        ```
    """
    try:
        from fastapi import FastAPI, BackgroundTasks
        from fastapi.middleware.cors import CORSMiddleware
        from .integrations.fastapi import create_tus_router
    except ImportError:
        raise ImportError("FastAPI is required for this example")

    # Ensure upload directory exists
    Path(upload_dir).mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="Production Tus Upload Server",
        description="Production-ready resumable file upload server",
        version="1.0.0",
    )

    # Add CORS middleware
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "HEAD", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )

    storage = FileStorage(upload_dir)
    config = TusConfig(
        max_size=max_size,
        upload_expires=timedelta(hours=upload_expires_hours),
        cors_enabled=not bool(cors_origins),  # Use built-in CORS if no middleware
        cors_origins=set(cors_origins) if cors_origins else None,
    )

    tus_router = create_tus_router(storage, config, prefix="/uploads")
    app.include_router(tus_router, tags=["uploads"])

    @app.get("/")
    async def root() -> Dict[str, Any]:
        return {
            "message": "Production Tus Upload Server",
            "upload_endpoint": "/uploads/",
            "max_upload_size": max_size,
            "upload_expires_hours": upload_expires_hours,
        }

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "healthy", "storage": "file"}

    @app.post("/cleanup")
    async def cleanup_uploads(background_tasks: Any) -> Dict[str, str]:
        """Clean up expired uploads."""
        background_tasks.add_task(storage.cleanup_expired_uploads)
        return {"message": "Cleanup task scheduled"}

    return app


# Example client usage
def example_client_usage() -> str:
    """Example of how to use tus client with the server."""
    client_code = """
    # Example client code using tuspy (pip install tuspy)
    
    from tuspy import TusClient
    
    # Create client
    client = TusClient("http://localhost:8000/files/")
    
    # Upload a file
    uploader = client.uploader(
        file_path="./large_file.zip",
        metadata={
            "filename": "large_file.zip",
            "contentType": "application/zip",
        }
    )
    
    # Upload with progress callback
    def progress_callback(bytes_uploaded: int, bytes_total: int) -> None:
        percentage = (bytes_uploaded / bytes_total) * 100
        print(f"Upload progress: {percentage:.1f}%")
    
    uploader.upload(progress_callback=progress_callback)
    print(f"Upload completed! URL: {uploader.url}")
    
    # JavaScript client example
    /*
    // Using tus-js-client (npm install tus-js-client)
    
    import * as tus from "tus-js-client";
    
    const upload = new tus.Upload(file, {
        endpoint: "http://localhost:8000/files/",
        retryDelays: [0, 3000, 5000, 10000, 20000],
        metadata: {
            filename: file.name,
            filetype: file.type
        },
        onError: function(error) {
            console.log("Failed because: " + error);
        },
        onProgress: function(bytesUploaded, bytesTotal) {
            const percentage = (bytesUploaded / bytesTotal * 100).toFixed(2);
            console.log(bytesUploaded, bytesTotal, percentage + "%");
        },
        onSuccess: function() {
            console.log("Download %s from %s", upload.file.name, upload.url);
        }
    });
    
    upload.start();
    */
    """

    return client_code
