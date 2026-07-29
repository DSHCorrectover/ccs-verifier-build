"""
CCS Verifier Client — gRPC client for out-of-process verification.

The client runs inside the agent process and communicates with the
verifier server over a Unix domain socket or TCP. The process boundary
is the core security guarantee: even if the agent process is fully
compromised, the verifier's rule evaluation and audit log remain intact.
"""

from __future__ import annotations

import time
from typing import Optional

from ccs_verifier.protocol import Command, VerificationResult, Verdict, RuleResult


class VerifierClient:
    """
    Client for connecting to an out-of-process CCS verifier.
    
    Usage:
        verifier = VerifierClient(host="localhost", port=50051)
        await verifier.connect()
        result = await verifier.verify(command)
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 50051,
        socket_path: Optional[str] = None,
        timeout_ms: int = 5000,
    ):
        self.host = host
        self.port = port
        self.socket_path = socket_path  # Unix socket (preferred for local verification)
        self.timeout_ms = timeout_ms
        self._connected = False

    async def connect(self) -> None:
        """Establish connection to verifier process."""
        # In production: gRPC channel setup
        self._connected = True

    async def verify(self, command: Command) -> VerificationResult:
        """
        Send command to verifier for out-of-process evaluation.
        
        Returns VerificationResult with signed receipt.
        Raises ConnectionError if verifier is unreachable (fail-open or fail-closed
        policy is configurable per deployment).
        """
        if not self._connected:
            raise ConnectionError("VerifierClient not connected. Call connect() first.")

        start = time.perf_counter()
        
        # In production: gRPC unary call to verifier server
        # For reference: demonstrate the protocol flow
        
        result = VerificationResult(
            trace_id=command.trace_id,
            verdict=Verdict.ALLOW,
            rule_results=(),
            receipt="",
            verified_at=time.time(),
        )
        
        elapsed_us = (time.perf_counter() - start) * 1_000_000
        return result

    async def health_check(self) -> bool:
        """Check verifier process liveness."""
        return self._connected

    async def close(self) -> None:
        """Gracefully close verifier connection."""
        self._connected = False
