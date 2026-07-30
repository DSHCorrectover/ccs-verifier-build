"""
CCS Transport Layer — Out-of-process communication for verifier.

Two transport options:
- UnixSocketTransport: Low-latency local IPC (preferred)
- TCPSocketTransport: Cross-machine distributed deployment

Protocol: length-prefixed JSON messages over asyncio streams.
"""

from ccs_verifier.transport.base import Transport, MessageFrame, TransportError
from ccs_verifier.transport.unix_socket import UnixSocketTransport
from ccs_verifier.transport.tcp_socket import TCPSocketTransport

__all__ = [
    "Transport",
    "MessageFrame",
    "TransportError",
    "UnixSocketTransport",
    "TCPSocketTransport",
]
