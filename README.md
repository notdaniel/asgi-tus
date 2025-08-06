# asgi-tus

A Python ASGI implementation of the [tus resumable upload protocol](https://tus.io/protocols/resumable-upload/).

## Features

- Full [tus protocol 1.0.0](https://tus.io/protocols/resumable-upload/) compliance
- Support for all standard extensions: `creation`, `creation-with-upload`, `creation-defer-length`, `termination`, `checksum`, `expiration`
- FastAPI and Starlette integrations in addition to pure ASGI
- File storage backend with cleanup support
- CORS support for web clients
- `async`/`await` throughout

## Installation

**Core functionality (ASGI app only):**
```bash
pip install asgi-tus
```

**With FastAPI support:**
```bash
pip install "asgi-tus[fastapi]"
```

**With Starlette support:**
```bash
pip install "asgi-tus[starlette]"
```

**With development server:**
```bash
pip install "asgi-tus[server]"
```

**With everything:**
```bash
pip install "asgi-tus[all]"
```

## Quick Start

### Pure ASGI

*Core functionality with minimal dependencies:*

```python
from asgi_tus import ASGITusApp, FileStorage, TusConfig
from datetime import timedelta

# Configure storage and tus settings
storage = FileStorage("/tmp/uploads")
config = TusConfig(
    max_size=100 * 1024 * 1024,  # 100MB
    upload_expires=timedelta(hours=24),
    cors_enabled=True
)

# Create ASGI app
app = ASGITusApp(storage, config)

# Run with any ASGI server: uvicorn, hypercorn, etc.
# uvicorn main:app --host 0.0.0.0 --port 8000
```

### FastAPI

*Requires: `pip install "asgi-tus[fastapi]"`*

```python
from fastapi import FastAPI
from asgi_tus import FileStorage, TusConfig, create_tus_router
from datetime import timedelta

app = FastAPI()

# Configure storage and tus settings
storage = FileStorage("/tmp/uploads")
config = TusConfig(
    max_size=100 * 1024 * 1024,  # 100MB
    upload_expires=timedelta(hours=24),
    cors_enabled=True
)

# Add tus endpoints
tus_router = create_tus_router(storage, config, prefix="/files")
app.include_router(tus_router)

# Upload endpoint: http://localhost:8000/files/
```

### Starlette

*Requires: `pip install "asgi-tus[starlette]"`*

```python
from starlette.applications import Starlette
from starlette.routing import Route
from asgi_tus import FileStorage, TusConfig, TusMount
from datetime import timedelta

storage = FileStorage("/tmp/uploads")
config = TusConfig(
    max_size=100 * 1024 * 1024,
    upload_expires=timedelta(hours=24),
    cors_enabled=True
)

tus_mount = TusMount(storage, config, path="/files")

app = Starlette(routes=[
    tus_mount.get_mount()
])

# Upload endpoint: http://localhost:8000/files/
```

## Usage

Test the server:

```bash
curl -X OPTIONS http://localhost:8000/files/
```

Upload with a tus client:

```python
# Python client (pip install tuspy)
from tuspy import TusClient

client = TusClient("http://localhost:8000/files/")
uploader = client.uploader("./file.zip")
uploader.upload()
```

```javascript
// JavaScript client (npm install tus-js-client)
import * as tus from "tus-js-client";

const upload = new tus.Upload(file, {
    endpoint: "http://localhost:8000/files/",
    onSuccess: () => console.log("Upload complete!")
});

upload.start();
```

## Configuration

```python
from asgi_tus import TusConfig
from datetime import timedelta

config = TusConfig(
    max_size=1024 * 1024 * 1024,  # 1GB max upload
    upload_expires=timedelta(days=7),  # Files expire after 7 days
    cors_enabled=True,  # Enable CORS
    extensions={  # Supported tus extensions
        "creation",
        "creation-with-upload",
        "creation-defer-length", 
        "termination",
        "checksum",
        "expiration"
    }
)
```

## License

MIT
