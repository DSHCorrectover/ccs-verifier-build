"""
CCS Verifier Client — Out-of-process verification client.

The client runs inside the agent process and communicates with the
verifier server over Unix domain socket (preferred) or TCP.

Key security property: The process boundary ensures that even if the
agent process is fully compromised (memory corruption, code injection),
the verifier's rule evaluation and audit log remain intact in a separate
process with its own memory space.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional, Sequence

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult
)
from ccs_verifier.transport.base import Transport, MessageFrame, TransportError
from ccs_verifier.transport.unix_socket import UnixSocketTransport
from ccs_verifier.transport.tcp_socket import TCPSocketTransport
from ccs_verifier.server import VerifierServer


class VerifierClient:
    """
    Client for connecting to an out-of-process CCS verifier.

    Usage (Unix socket — default, recommended):
        verifier = VerifierClient()  # uses /tmp/ccs-verifier.sock
        await verifier.connect()
        result = await verifier.verify(command)

    Usage (TCP — for remote verifier):
        verifier = VerifierClient(transport=TCPSocketTransport("10.0.0.1", 50051))
        await verifier.connect()
        result = await verifier.verify(command)
    """

    def __init__(
        self,
        transport: Transport | None = None,
        timeout_ms: int = 5000,
        reconnect: bool = True,
        max_retries: int = 3,
    ):
        self._transport = transport or UnixSocketTransport()
        self.timeout_ms = timeout_ms
        self._reconnect = reconnect
        self._max_retries = max_retries
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Establish connection to verifier process."""
        self._reader, self._writer = await self._transport.connect()
        self._connected = True

    async def _ensure_connected(self) -> None:
        """Ensure connection is alive, reconnect if needed."""
        if self._connected and self._writer and not self._writer.is_closing():
            return
        if not self._reconnect:
            raise TransportError("Not connected and reconnect is disabled")
        await self.connect()

    async def verify(self, command: Command) -> VerificationResult:
        """
        Send command to verifier for out-of-process evaluation.

        Returns VerificationResult with signed receipt.
        Raises TransportError if verifier is unreachable.
        """
        async with self._lock:
            last_error = None
            for attempt in range(self._max_retries + 1):
                try:
                    await self._ensure_connected()
                    assert self._reader and self._writer

                    request = {
                        "type": "verify",
                        "agent_id": command.agent_id,
                        "tool": command.tool,
                        "params": command.params,
                        "timestamp": command.timestamp,
                        "trace_id": command.trace_id,
                    }
                    self._writer.write(MessageFrame.encode(request))
                    await self._writer.drain()

                    response = await asyncio.wait_for(
                        MessageFrame.decode(self._reader),
                        timeout=self.timeout_ms / 1000.0,
                    )

                    # Parse response into VerificationResult
                    rule_results = tuple(
                        RuleResult(
                            rule_name=r["rule_name"],
                            verdict=Verdict(r["verdict"]),
                            reason=r.get("reason", ""),
                            latency_us=r.get("latency_us", 0.0),
                        )
                        for r in response.get("rule_results", [])
                    )

                    return VerificationResult(
                        trace_id=response["trace_id"],
                        verdict=Verdict(response["verdict"]),
                        block_reason=response.get("block_reason", ""),
                        rule_results=rule_results,
                        receipt=response.get("receipt", ""),
                        verified_at=response.get("verified_at", time.time()),
                        tool=response.get("tool", ""),
                        params_hash=response.get("params_hash", ""),
                    )

                except TransportError as e:
                    last_error = e
                    self._connected = False
                    if attempt < self._max_retries:
                        await asyncio.sleep(0.1 * (attempt + 1))
                        continue
                except asyncio.TimeoutError:
                    last_error = TransportError(
                        f"Verification timed out after {self.timeout_ms}ms"
                    )
                    self._connected = False
                    if attempt < self._max_retries:
                        await asyncio.sleep(0.1 * (attempt + 1))
                        continue
                except (ConnectionError, OSError) as e:
                    last_error = TransportError(f"Connection lost: {e}")
                    self._connected = False
                    if attempt < self._max_retries:
                        await asyncio.sleep(0.1 * (attempt + 1))
                        continue

            raise last_error or TransportError("Verification failed after retries")

    async def health_check(self) -> dict:
        """
        Check verifier process liveness and get stats.
        
        Returns dict with status, version, uptime, rules, etc.
        """
        async with self._lock:
            await self._ensure_connected()
            assert self._reader and self._writer

            self._writer.write(MessageFrame.encode({"type": "health"}))
            await self._writer.drain()

            response = await asyncio.wait_for(
                MessageFrame.decode(self._reader),
                timeout=self.timeout_ms / 1000.0,
            )
            return response

    async def list_rules(self) -> list[dict]:
        """Get list of rules loaded in the verifier server."""
        async with self._lock:
            await self._ensure_connected()
            assert self._reader and self._writer

            self._writer.write(MessageFrame.encode({"type": "list_rules"}))
            await self._writer.drain()

            response = await asyncio.wait_for(
                MessageFrame.decode(self._reader),
                timeout=self.timeout_ms / 1000.0,
            )
            return response.get("rules", [])

    async def close(self) -> None:
        """Close the verifier connection."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._connected = False
        self._reader = None
        self._writer = None


class Verifier:
    """
    High-level verifier with auto-detection of out-of-process vs in-process.

    If a running verifier server is detected, uses out-of-process verification
    (strongest security). Otherwise, falls back to in-process verification.

    Usage:
        # Auto-detect (recommended)
        verifier = Verifier(rules=[SSRFRule(), RCERule()])
        result = verifier.verify(command)  # sync API

        # Force out-of-process
        verifier = Verifier(rules=[SSRFRule()], mode="out-of-process")
        
        # Force in-process
        verifier = Verifier(rules=[SSRFRule()], mode="in-process")
    """

    def __init__(
        self,
        rules: Sequence[Rule],
        signing_key: bytes | None = None,
        transport: Transport | None = None,
        mode: str = "auto",
        timeout_ms: int = 5000,
    ):
        """
        Args:
            rules: Verification rules to apply.
            signing_key: HMAC signing key (server-only, for in-process mode).
            transport: Transport for out-of-process mode.
            mode: "auto" (try OOP first, fallback to in-process),
                  "out-of-process" (require server),
                  "in-process" (no server needed).
            timeout_ms: Timeout for out-of-process verification.
        """
        self._rules = list(rules)
        self._mode = mode
        self._transport = transport
        self._timeout_ms = timeout_ms
        self._client: VerifierClient | None = None
        self._server: VerifierServer | None = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._oop_available = False

        if mode == "in-process":
            self._server = VerifierServer(rules=rules, signing_key=signing_key)
        elif mode == "out-of-process":
            self._client = VerifierClient(transport=transport, timeout_ms=timeout_ms)
        # "auto" is resolved lazily on first verify()

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
                if self._loop.is_closed():
                    raise RuntimeError
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def _resolve_mode(self) -> None:
        """Resolve 'auto' mode by probing for a running server."""
        if self._mode != "auto":
            return
        
        client = VerifierClient(transport=self._transport, timeout_ms=1000)
        loop = self._get_loop()
        try:
            loop.run_until_complete(client.connect())
            self._client = client
            self._oop_available = True
            self._mode = "out-of-process"
        except (TransportError, Exception):
            # No server running — fall back to in-process
            self._server = VerifierServer(rules=self._rules)
            self._oop_available = False
            self._mode = "in-process"

    def verify(self, command: Command) -> VerificationResult:
        """
        Verify a command synchronously.
        
        In auto mode, first call will probe for a running verifier server.
        If found, uses out-of-process verification (strongest isolation).
        If not found, falls back to in-process verification.
        """
        if self._mode == "auto":
            self._resolve_mode()

        loop = self._get_loop()
        if self._client and self._mode == "out-of-process":
            return loop.run_until_complete(self._client.verify(command))
        else:
            return loop.run_until_complete(self._server.verify(command))

    async def averify(self, command: Command) -> VerificationResult:
        """Verify a command asynchronously."""
        if self._mode == "auto":
            self._resolve_mode()

        if self._client and self._mode == "out-of-process":
            return await self._client.verify(command)
        else:
            return await self._server.verify(command)

    async def health_check(self) -> dict:
        """Get verifier health status."""
        if self._client and self._oop_available:
            return await self._client.health_check()
        elif self._server:
            return self._server.stats
        raise RuntimeError("No verifier available")

    async def close(self) -> None:
        """Close client connection if out-of-process."""
        if self._client:
            await self._client.close()

    @property
    def mode(self) -> str:
        """Current operating mode ('in-process' or 'out-of-process')."""
        return self._mode

    @property
    def audit_log(self) -> list[VerificationResult]:
        """Read-only access to audit log (in-process only)."""
        if self._server:
            return self._server.audit_log
        return []

    @property
    def signing_key(self) -> bytes:
        """Access the signing key (in-process only)."""
        if self._server:
            return self._server._signing_key
        raise RuntimeError("Signing key not available in out-of-process mode")
