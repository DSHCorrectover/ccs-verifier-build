"""
CCS Verifier Server — Out-of-process verification engine.

Runs in a separate process from the agent. Evaluates commands against
registered rules and returns signed verification results.

Key property: The verifier process has its own memory space, file descriptors,
and crash domain. A segfault in the agent does not corrupt the audit log.
"""

from __future__ import annotations

import time
import secrets
from typing import Sequence

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult, sign_receipt
)


class VerifierServer:
    """
    Out-of-process verification server.

    Lifecycle:
        server = VerifierServer(rules=[SSRFRule(), RCERule()])
        await server.start(port=50051)
        # Listens for gRPC requests from VerifierClient
    """

    def __init__(self, rules: Sequence[Rule], signing_key: bytes | None = None):
        self.rules = list(rules)
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._audit_log: list[VerificationResult] = []

    async def verify(self, command: Command) -> VerificationResult:
        """Evaluate command against all registered rules."""
        rule_results: list[RuleResult] = []
        final_verdict = Verdict.ALLOW
        block_reason = ""

        for rule in self.rules:
            t0 = time.perf_counter()
            result = rule.evaluate(command)
            latency_us = (time.perf_counter() - t0) * 1_000_000
            result = RuleResult(
                rule_name=result.rule_name,
                verdict=result.verdict,
                reason=result.reason,
                latency_us=latency_us,
            )
            rule_results.append(result)

            # DENY takes precedence; ESCALATE is second
            if result.verdict == Verdict.DENY:
                final_verdict = Verdict.DENY
                block_reason = result.reason
                break
            elif result.verdict == Verdict.ESCALATE and final_verdict != Verdict.DENY:
                final_verdict = Verdict.ESCALATE
                block_reason = result.reason

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
        )

        # Append to in-process audit log (separate from agent's log)
        self._audit_log.append(verification)
        return verification

    async def start(self, host: str = "0.0.0.0", port: int = 50051) -> None:
        """Start gRPC server. In production: asyncio gRPC server setup."""
        pass

    @property
    def audit_log(self) -> list[VerificationResult]:
        """Read-only access to audit log (for export to SIEM, etc.)."""
        return list(self._audit_log)
