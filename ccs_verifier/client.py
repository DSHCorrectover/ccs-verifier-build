"""
CCS Verifier Client — gRPC client for out-of-process verification.

The client runs inside the agent process and communicates with the
verifier server over a Unix domain socket or TCP. The process boundary
is the core security guarantee: even if the agent process is fully
compromised, the verifier's rule evaluation and audit log remain intact.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional, Sequence

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult
)
from ccs_verifier.server import VerifierServer


class VerifierClient:
    """
    Client for connecting to an out-of-process CCS verifier.

    Usage (out-of-process, requires running server):
        verifier = VerifierClient(host="localhost", port=50051)
        await verifier.connect()
        result = await verifier.verify(command)

    Note: Out-of-process gRPC transport is not yet implemented.
    For immediate use, see the `Verifier` class for in-process verification.
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
        # TODO: Implement gRPC channel setup
        raise NotImplementedError(
            "Out-of-process gRPC transport is not yet implemented. "
            "Use the `Verifier` class for in-process verification."
        )

    async def verify(self, command: Command) -> VerificationResult:
        """
        Send command to verifier for out-of-process evaluation.

        Returns VerificationResult with signed receipt.
        Raises ConnectionError if verifier is unreachable.
        """
        if not self._connected:
            raise ConnectionError("VerifierClient not connected. Call connect() first.")

        # TODO: Implement gRPC unary call to verifier server
        raise NotImplementedError(
            "Out-of-process gRPC transport is not yet implemented. "
            "Use the `Verifier` class for in-process verification."
        )

    async def health_check(self) -> bool:
        """Check verifier process liveness."""
        return self._connected

    async def close(self) -> None:
        """Gracefully close verifier connection."""
        self._connected = False


class Verifier:
    """
    High-level in-process verifier for immediate use.

    This is the recommended entry point for CCS verification. It wraps
    a VerifierServer and provides a synchronous API for verifying commands.

    For out-of-process deployment (separate verifier process), use
    VerifierClient with a running VerifierServer.

    Usage:
        from ccs_verifier import Verifier, Command
        from ccs_verifier.builtin_rules import SSRFRule, RCERule

        verifier = Verifier(rules=[SSRFRule(), RCERule()])
        cmd = Command(agent_id="agent-001", tool="shell_exec",
                      params={"command": "rm -rf /tmp/data"})
        result = verifier.verify(cmd)
        if result.allowed:
            execute(cmd)
        else:
            print(f"Blocked: {result.block_reason}")
    """

    def __init__(self, rules: Sequence[Rule], signing_key: bytes | None = None):
        self._server = VerifierServer(rules=rules, signing_key=signing_key)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create an event loop for running async verification."""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
                if self._loop.is_closed():
                    raise RuntimeError
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def verify(self, command: Command) -> VerificationResult:
        """
        Verify a command synchronously.

        Evaluates the command against all registered rules and returns
        a signed VerificationResult.

        Args:
            command: The Command to verify.

        Returns:
            VerificationResult with verdict, rule results, and signed receipt.
        """
        loop = self._get_loop()
        return loop.run_until_complete(self._server.verify(command))

    async def averify(self, command: Command) -> VerificationResult:
        """
        Verify a command asynchronously.

        Args:
            command: The Command to verify.

        Returns:
            VerificationResult with verdict, rule results, and signed receipt.
        """
        return await self._server.verify(command)

    @property
    def audit_log(self) -> list[VerificationResult]:
        """Read-only access to audit log."""
        return self._server.audit_log

    @property
    def signing_key(self) -> bytes:
        """Access the signing key (for receipt verification)."""
        return self._server._signing_key
