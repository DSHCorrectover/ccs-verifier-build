"""
CCS Verifier Server — Out-of-process verification engine.

Runs in a separate process from the agent. Evaluates commands against
registered rules and returns signed verification results.

Key property: The verifier process has its own memory space, file descriptors,
and crash domain. A segfault in the agent does not corrupt the audit log.

Receipt levels:
- L0 (default): HMAC-SHA256 receipt with 6 covered fields
- L1: Ed25519 signed receipt with 30 fields (CAID-compatible)

Transport: Unix domain socket (default) or TCP. Protocol: length-prefixed JSON.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Optional, Sequence

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult, DimensionError, sign_receipt
)
from ccs_verifier.ccs_verifier_l1 import (
    L1Receipt, L1ReceiptBuilder,
    generate_ed25519_key, get_public_key, public_key_fingerprint,
    compute_args_digest, compute_request_hash, compute_response_hash, compute_hash,
)
from ccs_verifier.transport.base import Transport, MessageFrame, TransportError
from ccs_verifier.transport.unix_socket import UnixSocketTransport

logger = logging.getLogger("ccs_verifier.server")

VERSION = "1.1.20"


class VerifierServer:
    """
    Out-of-process verification server.

    Supports two receipt modes:
    - L0 (default): HMAC-SHA256 signed receipts (backward compatible with v0.x)
    - L1: Ed25519 signed receipts with 29 fields (CAID-compatible)

    Lifecycle:
        server = VerifierServer(rules=[SSRFRule(), RCERule()])
        await server.start()  # Unix socket (default)
        # OR
        await server.start(transport=TCPSocketTransport(port=50051))

    L1 mode:
        from ccs_verifier import generate_ed25519_key
        key = generate_ed25519_key()
        server = VerifierServer(rules=[...], l1_signing_key=key)
    """

    def __init__(
        self,
        rules: Sequence[Rule],
        signing_key: bytes | None = None,
        l1_signing_key: bytes | None = None,
        max_audit_log: int = 100_000,
        verifier_source_class: str = "ccs_verifier.server.VerifierServer",
        deployment_mode: str = "in-process",
        issuer: str = "ccs-verifier",
        audience: str = "",
        clock_skew_bound: float = 5.0,
    ):
        self.rules = list(rules)
        # L0 HMAC signing key (backward compatible)
        self._signing_key = signing_key or secrets.token_bytes(32)
        # L1 Ed25519 signing key (optional — enables L1 mode)
        self._l1_signing_key: Optional[bytes] = l1_signing_key
        self._l1_public_key: Optional[bytes] = None
        self._l1_key_fingerprint: str = ""
        if self._l1_signing_key is not None:
            self._l1_public_key = get_public_key(self._l1_signing_key)
            self._l1_key_fingerprint = public_key_fingerprint(self._l1_public_key)

        self._audit_log: list[VerificationResult] = []
        self._max_audit_log = max_audit_log
        self._server: asyncio.Server | None = None
        self._transport: Transport | None = None
        self._started_at: float = 0
        self._request_count: int = 0
        self._deny_count: int = 0
        self._sequence: int = 0

        # Verifier identity metadata (for L1 receipts)
        self._verifier_source_class = verifier_source_class
        self._deployment_mode = deployment_mode
        self._issuer = issuer
        self._audience = audience
        self._clock_skew_bound = clock_skew_bound

        # Rule version for L1 receipts
        self._rule_version = "1.1.20"

        # Config hash (based on rule set)
        self._config_hash = compute_hash({
            "rules": [type(r).__name__ for r in self.rules],
            "version": VERSION,
        })

    @property
    def l1_enabled(self) -> bool:
        """Whether L1 Ed25519 receipt mode is enabled."""
        return self._l1_signing_key is not None

    @property
    def l1_public_key(self) -> Optional[bytes]:
        """The Ed25519 public key for L1 receipt verification."""
        return self._l1_public_key

    @property
    def l1_key_fingerprint(self) -> str:
        """Fingerprint of the L1 signing public key."""
        return self._l1_key_fingerprint

    async def verify(self, command: Command) -> VerificationResult:
        """Evaluate command against all registered rules."""
        rule_results: list[RuleResult] = []
        final_verdict = Verdict.ALLOW
        block_reason = ""
        error_code = DimensionError.default()  # default -32000

        t_start = time.perf_counter()

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

        total_latency_us = (time.perf_counter() - t_start) * 1_000_000
        now = time.time()
        rule_summary = "|".join(
            f"{r.rule_name}={r.verdict.value}" for r in rule_results
        )

        # L0 receipt (HMAC-SHA256) — always present for backward compatibility
        receipt = sign_receipt(
            trace_id=command.trace_id,
            verdict=final_verdict,
            timestamp=now,
            secret=self._signing_key,
            tool=command.tool,
            params_hash=command.params_hash(),
            rule_summary=rule_summary,
        )

        # L1 receipt (Ed25519) — if L1 mode is enabled
        l1_receipt_data: dict = {}
        if self._l1_signing_key is not None:
            self._sequence += 1
            request_data = {
                "agent_id": command.agent_id,
                "tool": command.tool,
                "params": command.params,
                "timestamp": command.timestamp,
                "trace_id": command.trace_id,
            }
            response_data = {
                "verdict": final_verdict.value,
                "rule_results": [r.rule_name for r in rule_results],
                "block_reason": block_reason,
            }
            runtime_context = {
                "python_version": "3.x",
                "mode": self._deployment_mode,
            }

            # CAID-compatible action
            action = f"ccs.verify.{final_verdict.value}"

            # Time bounds
            issuance_bound = now - self._clock_skew_bound
            expiry_bound = now + 300.0  # 5 minute default validity

            builder = (
                L1ReceiptBuilder(command.trace_id, final_verdict)
                .tool(command.tool)
                .params_hash(command.params_hash())
                .args_digest(command.params)
                .rule_summary(rule_summary)
                .rule_version(self._rule_version)
                .request_hash(request_data)
                .response_hash(response_data)
                .runtime_context(runtime_context)
                .config_hash({"rules": self._config_hash})
                .verifier_source_class(self._verifier_source_class)
                .deployment_mode(self._deployment_mode)
                .issuer(self._issuer)
                .audience(self._audience or command.agent_id)
                .sequence(self._sequence)
                .time_bounds(
                    issued_at=issuance_bound,
                    expiry=expiry_bound,
                    clock_skew=self._clock_skew_bound,
                )
                .action(action)
                .latency_us(total_latency_us)
            )

            if command.trace_id:
                # Use trace_id as nonce if no explicit nonce provided
                builder.nonce(command.trace_id[:16])

            l1_receipt = builder.build(self._l1_signing_key)
            l1_receipt_data = l1_receipt.to_dict()

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

        # Attach L1 receipt data as an attribute (for L1 mode)
        # Use object.__setattr__ because VerificationResult is a frozen dataclass
        if l1_receipt_data:
            object.__setattr__(verification, 'l1_receipt', l1_receipt_data)

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
                    # Include L1 receipt if available
                    if hasattr(result, "l1_receipt") and result.l1_receipt:
                        response["l1_receipt"] = result.l1_receipt

                elif msg_type == "health":
                    response = {
                        "type": "health",
                        "status": "ok",
                        "version": VERSION,
                        "uptime_s": round(time.time() - self._started_at, 1),
                        "rules": [r.name for r in self.rules],
                        "requests": self._request_count,
                        "denies": self._deny_count,
                        "l1_enabled": self.l1_enabled,
                        "l1_key_fingerprint": self._l1_key_fingerprint,
                    }

                elif msg_type == "list_rules":
                    response = {
                        "type": "list_rules",
                        "rules": [
                            {"name": r.name, "type": type(r).__name__}
                            for r in self.rules
                        ],
                    }

                elif msg_type == "get_l1_public_key":
                    if self._l1_public_key:
                        response = {
                            "type": "l1_public_key",
                            "public_key": self._l1_public_key.hex(),
                            "fingerprint": self._l1_key_fingerprint,
                            "algorithm": "Ed25519",
                        }
                    else:
                        response = {
                            "type": "error",
                            "message": "L1 mode not enabled",
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
            f"CCS Verifier Server v{VERSION} started on {self._transport.describe()} "
            f"with {len(self.rules)} rules "
            f"(L1 {'enabled' if self.l1_enabled else 'disabled'})"
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
            "version": VERSION,
            "uptime_s": round(time.time() - self._started_at, 1) if self._started_at else 0,
            "requests": self._request_count,
            "denies": self._deny_count,
            "rules": len(self.rules),
            "transport": self._transport.describe() if self._transport else "none",
            "l1_enabled": self.l1_enabled,
            "l1_key_fingerprint": self._l1_key_fingerprint,
        }
