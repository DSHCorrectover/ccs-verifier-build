"""
CCS Verifier Server — Out-of-process verification engine.

Runs in a separate process from the agent. Evaluates commands against
registered rules and returns signed verification results.

Key property: The verifier process has its own memory space, file descriptors,
and crash domain. A segfault in the agent does not corrupt the audit log.

Transport: Unix domain socket (default) or TCP. Protocol: length-prefixed JSON.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Sequence

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult, DimensionError, sign_receipt
)
from ccs_verifier.transport.base import Transport, MessageFrame, TransportError
from ccs_verifier.transport.unix_socket import UnixSocketTransport

logger = logging.getLogger("ccs_verifier.server")


class VerifierServer:
    """
    Out-of-process verification server.

    Lifecycle:
        server = VerifierServer(rules=[SSRFRule(), RCERule()])
        await server.start()  # Unix socket (default)
        # OR
        await server.start(transport=TCPSocketTransport(port=50051))
    """

    def __init__(
        self,
        rules: Sequence[Rule],
        signing_key: bytes | None = None,
        max_audit_log: int = 100_000,
    ):
        self.rules = list(rules)
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._audit_log: list[VerificationResult] = []
        self._max_audit_log = max_audit_log
        self._server: asyncio.Server | None = None
        self._transport: Transport | None = None
        self._started_at: float = 0
        self._request_count: int = 0
        self._deny_count: int = 0

    async def verify(self, command: Command) -> VerificationResult:
        """Evaluate command against all registered rules."""
        rule_results: list[RuleResult] = []
        final_verdict = Verdict.ALLOW
        block_reason = ""
        error_code = DimensionError.default()  # default -32000

        for rule in self.rules:
            t0 = time.perf_counter()
            result = rule.evaluate(command)
            latency_us = (time.perf_counter() - t0) * 1_000_000
            result = RuleResult(
                rule_name=result.rule_name,
                verdict=result.verdict,
                reason=result.reason,
                latency_us=latency_us,
                error_code=result.error_code,  # propagate from rule
            )
            rule_results.append(result)

            if result.verdict == Verdict.DENY:
                final_verdict = Verdict.DENY
                block_reason = result.reason
                error_code = result.error_code  # carry the triggering dimension's code
                break
            elif result.verdict == Verdict.ESCALATE and final_verdict != Verdict.DENY:
                final_verdict = Verdict.ESCALATE
                block_reason = result.reason
                # ESCALATE keeps default error_code (insufficient info to classify)

        now = time.time()
        rule_summary = "|".join(
            f"{r.rule_name}={r.verdict.value}" for r in rule_results
        )
        receipt = sign_receipt(
            trace_id=command.trace_id,
            verdict=final_verdict,
            timestamp=now,
            secret=self._signing_key,
            tool=command.tool,
            params_hash=command.params_hash(),
            rule_summary=rule_summary,
        )

        verification = VerificationResult(
            trace_id=command.trace_id,
            verdict=final_verdict,
            block_reason=block_reason,
            rule_results=tuple(rule_results),
            receipt=receipt,
            verified_at=now,
            tool=command.tool,
            params_hash=command.params_hash(),
            error_code=error_code,
        )

        self._audit_log.append(verification)
        # Trim audit log if too large (keep most recent)
        if len(self._audit_log) > self._max_audit_log:
            self._audit_log = self._audit_log[-self._max_audit_log:]

        self._request_count += 1
        if final_verdict == Verdict.DENY:
            self._deny_count += 1

        return verification

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection."""
        peer = writer.get_extra_info("peername", "unknown")
        logger.debug(f"New connection from {peer}")

        try:
            while True:
                try:
                    msg = await MessageFrame.decode(reader)
                except (asyncio.IncompleteReadError, ConnectionError):
                    break  # Client disconnected

                msg_type = msg.get("type", "")

                if msg_type == "verify":
                    command = Command(
                        agent_id=msg["agent_id"],
                        tool=msg["tool"],
                        params=msg["params"],
                        timestamp=msg.get("timestamp", time.time()),
                        trace_id=msg.get("trace_id", ""),
                    )
                    result = await self.verify(command)
                    response = {
                        "type": "result",
                        "trace_id": result.trace_id,
                        "verdict": result.verdict.value,
                        "block_reason": result.block_reason,
                        "rule_results": [
                            {
                                "rule_name": r.rule_name,
                                "verdict": r.verdict.value,
                                "reason": r.reason,
                                "latency_us": round(r.latency_us, 2),
                                "error_code": r.error_code,
                            }
                            for r in result.rule_results
                        ],
                        "receipt": result.receipt,
                        "verified_at": result.verified_at,
                        "tool": result.tool,
                        "params_hash": result.params_hash,
                        "error_code": result.error_code,
                    }

                elif msg_type == "health":
                    response = {
                        "type": "health",
                        "status": "ok",
                        "version": "0.4.1",
                        "uptime_s": round(time.time() - self._started_at, 1),
                        "rules": [r.name for r in self.rules],
                        "requests": self._request_count,
                        "denies": self._deny_count,
                    }

                elif msg_type == "list_rules":
                    response = {
                        "type": "list_rules",
                        "rules": [
                            {"name": r.name, "type": type(r).__name__}
                            for r in self.rules
                        ],
                    }

                else:
                    response = {
                        "type": "error",
                        "message": f"Unknown message type: {msg_type}",
                    }

                writer.write(MessageFrame.encode(response))
                await writer.drain()

        except Exception as e:
            logger.error(f"Error handling connection from {peer}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"Connection closed from {peer}")

    async def start(
        self,
        transport: Transport | None = None,
    ) -> None:
        """
        Start the verifier server.

        Args:
            transport: Transport to use. Defaults to UnixSocketTransport().
        """
        self._transport = transport or UnixSocketTransport()
        self._started_at = time.time()
        self._server = await self._transport.start_server(self._handle_connection)

        # For TCP, get the actual port
        if hasattr(self._server, 'sockets') and self._server.sockets:
            addr = self._server.sockets[0].getsockname()
            if isinstance(addr, tuple):
                self._transport = type(self._transport)(addr[0], addr[1]) if hasattr(self._transport, 'host') else self._transport

        logger.info(
            f"CCS Verifier Server started on {self._transport.describe()} "
            f"with {len(self.rules)} rules"
        )

    async def stop(self) -> None:
        """Stop the server and clean up."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("CCS Verifier Server stopped")

    async def serve_forever(self) -> None:
        """Run server until cancelled."""
        if not self._server:
            raise RuntimeError("Server not started. Call start() first.")
        async with self._server:
            await self._server.serve_forever()

    @property
    def audit_log(self) -> list[VerificationResult]:
        """Read-only access to audit log."""
        return list(self._audit_log)

    @property
    def stats(self) -> dict:
        """Server statistics."""
        return {
            "uptime_s": round(time.time() - self._started_at, 1) if self._started_at else 0,
            "requests": self._request_count,
            "denies": self._deny_count,
            "rules": len(self.rules),
            "transport": self._transport.describe() if self._transport else "none",
        }
