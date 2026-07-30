"""
CCS Transport — Abstract base for out-of-process communication.

The transport layer is the security boundary between the agent process
and the verifier process. Messages are JSON-serialized and sent over
Unix domain sockets (preferred) or TCP.

Protocol format: length-prefixed JSON messages.
Each message: 4-byte big-endian length + JSON payload (no newline needed).
"""

from __future__ import annotations

import asyncio
import json
import struct
from abc import ABC, abstractmethod
from typing import Any


class TransportError(Exception):
    """Transport-level failure (connection lost, timeout, etc.)."""


class MessageFrame:
    """Length-prefixed JSON message framing for CCS transport.
    
    Wire format: [4-byte uint32 big-endian length][JSON payload bytes]
    This avoids issues with partial reads and message boundaries.
    """
    
    HEADER_SIZE = 4
    MAX_MESSAGE_SIZE = 1 * 1024 * 1024  # 1 MB max
    
    @staticmethod
    def encode(msg: dict[str, Any]) -> bytes:
        """Encode a dict as a length-prefixed JSON message."""
        payload = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(payload) > MessageFrame.MAX_MESSAGE_SIZE:
            raise TransportError(f"Message too large: {len(payload)} bytes")
        header = struct.pack(">I", len(payload))
        return header + payload
    
    @staticmethod
    async def decode(reader: asyncio.StreamReader) -> dict[str, Any]:
        """Read and decode a length-prefixed JSON message from a stream."""
        header = await reader.readexactly(MessageFrame.HEADER_SIZE)
        length = struct.unpack(">I", header)[0]
        if length > MessageFrame.MAX_MESSAGE_SIZE:
            raise TransportError(f"Message too large: {length} bytes")
        payload = await reader.readexactly(length)
        return json.loads(payload.decode("utf-8"))


class Transport(ABC):
    """Abstract transport for CCS verifier client/server communication."""
    
    @abstractmethod
    async def start_server(
        self,
        handler: callable,
    ) -> asyncio.Server:
        """Start a server that accepts connections and dispatches to handler."""
        ...
    
    @abstractmethod
    async def connect(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to a running server. Returns (reader, writer) pair."""
        ...
    
    @abstractmethod
    def describe(self) -> str:
        """Human-readable description of the transport endpoint."""
        ...
