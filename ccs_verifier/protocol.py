"""
CCS Protocol — Core data structures for out-of-process verification.

Key design decision: Commands are serialized across a process boundary,
ensuring the verifier cannot be subverted by agent-process memory corruption.
"""

from __future__ import annotations

import time
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class Command:
    """Immutable command representation for cross-process verification."""
    agent_id: str
    tool: str
    params: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    trace_id: str = field(default_factory=lambda: hashlib.sha256(
        f"{time.time_ns()}".encode()
    ).hexdigest()[:16])

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for signature verification."""
        return json.dumps({
            "agent_id": self.agent_id,
            "tool": self.tool,
            "params": self.params,
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
        }, sort_keys=True, separators=(",", ":")).encode()

    def params_hash(self) -> str:
        """SHA-256 hash of canonical params for receipt binding."""
        return hashlib.sha256(
            json.dumps(self.params, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:16]


@dataclass(frozen=True)
class RuleResult:
    """Result from a single rule evaluation."""
    rule_name: str
    verdict: Verdict
    reason: str = ""
    latency_us: float = 0.0


@dataclass(frozen=True)
class VerificationResult:
    """
    Final verification decision with audit receipt.

    The receipt is an HMAC-SHA256 signature over the full verification context
    (trace_id, verdict, timestamp, tool, params_hash, rule_summary),
    providing tamper-evident audit trail even if the agent process is compromised.
    """
    trace_id: str
    verdict: Verdict
    block_reason: str = ""
    rule_results: tuple[RuleResult, ...] = ()
    receipt: str = ""
    verified_at: float = field(default_factory=time.time)
    tool: str = ""
    params_hash: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    @property
    def total_latency_us(self) -> float:
        return sum(r.latency_us for r in self.rule_results)


@runtime_checkable
class Rule(Protocol):
    """
    Pluggable verification rule interface.

    Implementations detect specific threat classes:
    - SSRF: URL scheme/host validation
    - RCE: Shell injection patterns
    - Credential leak: Secret pattern matching
    - Path traversal: Directory escape detection
    """

    @property
    def name(self) -> str: ...

    def evaluate(self, command: Command) -> RuleResult: ...


def sign_receipt(
    trace_id: str,
    verdict: Verdict,
    timestamp: float,
    secret: bytes,
    tool: str = "",
    params_hash: str = "",
    rule_summary: str = "",
) -> str:
    """
    Generate HMAC-SHA256 receipt for tamper-evident audit.

    Covers: trace_id, verdict, timestamp, tool name, params hash,
    and a summary of rule evaluations. This ensures the receipt
    binds to the full verification context, not just the verdict.
    """
    payload = f"{trace_id}:{verdict.value}:{timestamp}:{tool}:{params_hash}:{rule_summary}".encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()[:32]
