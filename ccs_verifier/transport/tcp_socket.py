"""
TCP Socket transport — for remote or cross-machine verification.

Use when the verifier runs on a different machine or container.
Lower security than Unix sockets (no OS-level access control),
but enables distributed deployment topologies.
"""

from __future__ import annotations

import asyncio
from typing import Callable

from ccs_verifier.transport.base import Transport, TransportError

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50051


class TCPSocketTransport(Transport):
    """TCP socket transport for verifier communication."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port

    async def start_server(self, handler: Callable) -> asyncio.Server:
        """Start TCP server."""
        server = await asyncio.start_server(
            handler,
            host=self.host,
            port=self.port,
        )
        return server

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to TCP server."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5.0,
            )
            return reader, writer
        except (ConnectionRefusedError, OSError) as e:
            raise TransportError(
                f"Cannot connect to verifier at {self.host}:{self.port}: {e}"
            ) from e
        except asyncio.TimeoutError as e:
            raise TransportError(
                f"Connection timeout to {self.host}:{self.port}"
            ) from e

    def describe(self) -> str:
        return f"tcp:{self.host}:{self.port}"
