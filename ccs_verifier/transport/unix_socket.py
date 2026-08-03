"""
Unix Domain Socket transport — preferred for local out-of-process verification.

Unix sockets provide:
- Lowest latency (~10-50μs round-trip vs ~100-200μs for TCP)
- OS-level access control (socket file permissions)
- No port conflicts
- Atomic connection semantics
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Callable

from ccs_verifier.transport.base import Transport, TransportError

DEFAULT_SOCKET_PATH = "/tmp/ccs-verifier.sock"


class UnixSocketTransport(Transport):
    """Unix domain socket transport for local verifier communication."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path

    async def start_server(self, handler: Callable) -> asyncio.Server:
        """Start Unix socket server."""
        # Remove stale socket file if exists
        sock = Path(self.socket_path)
        if sock.exists():
            sock.unlink()
        # Ensure parent directory exists
        sock.parent.mkdir(parents=True, exist_ok=True)

        server = await asyncio.start_unix_server(
            handler,
            path=self.socket_path,
        )
        # Set socket permissions to owner-only
        os.chmod(self.socket_path, 0o600)
        return server

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to Unix socket server."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path),
                timeout=5.0,
            )
            return reader, writer
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise TransportError(
                f"Cannot connect to verifier at {self.socket_path}: {e}"
            ) from e
        except asyncio.TimeoutError as e:
            raise TransportError(
                f"Connection timeout to {self.socket_path}"
            ) from e

    def describe(self) -> str:
        return f"unix:{self.socket_path}"
