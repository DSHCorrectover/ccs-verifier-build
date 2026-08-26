"""
Correctover License Gate — community vs enterprise tiering.

Community edition (no license key):
  - Runtime rules: SSRF, RCE, CredentialLeak (5 rules remain open in builtin_rules)
  - Text rules: OutputInjection, PIILeak, UnsafeOutput, HallucinationMarkers
  - Max 50 traces per invocation
  - SARIF format disabled

Enterprise edition (CORRECTOVER_LICENSE_KEY env var):
  - All 116 detection rules including semantic path analysis
  - CredentialLeakTextRule (9 high-fidelity secret patterns)
  - ToolPoisoningRule, RugPullRule
  - Unlimited traces
  - SARIF output
  - No telemetry
"""
from __future__ import annotations

import os
import hashlib
import time


# Enterprise keys are hashed; plaintext keys never stored in source.
# Format: CO-LIVE-<32 hex chars>
# To issue a key, compute: hashlib.sha256(("correctover:" + plaintext).encode()).hexdigest()[:32]
_VALID_KEY_HASHES = frozenset({
    # No live keys yet. Add hashes when enterprise deals close.
    # Example: "a1b2c3d4e5f6..." (sha256 of "correctover:CO-LIVE-xxxx"[:32])
})

# Trial keys expire after a set date
_TRIAL_KEY_HASHES: dict[str, float] = {
    # hash -> expiry unix timestamp
}


def _hash_key(key: str) -> str:
    return hashlib.sha256(f"correctover:{key}".encode()).hexdigest()[:32]


def get_license_key() -> str:
    return os.environ.get("CORRECTOVER_LICENSE_KEY", "").strip()


def is_licensed() -> bool:
    """Return True if a valid enterprise/trial license is present."""
    key = get_license_key()
    if not key:
        return False
    h = _hash_key(key)
    if h in _VALID_KEY_HASHES:
        return True
    if h in _TRIAL_KEY_HASHES:
        return time.time() < _TRIAL_KEY_HASHES[h]
    return False


def community_trace_limit() -> int:
    return 0 if is_licensed() else 50


def community_rules_enabled() -> set[str]:
    """Rules available in community edition."""
    if is_licensed():
        return {"all"}
    return {
        "ssrf", "rce", "credential_leak",
        "output_injection", "pii_leak", "unsafe_output",
        "hallucination_markers",
    }


def enterprise_only_rules() -> set[str]:
    """Rules that require a license."""
    return {
        "semantic",           # SemanticPathAnalyzer — the core moat
        "tool_poisoning",     # MCP tool description poisoning
        "rug_pull",           # Post-approval behavior change
        "credential_text",    # High-fidelity secret patterns in output text
    }


def sarif_allowed() -> bool:
    return is_licensed()
