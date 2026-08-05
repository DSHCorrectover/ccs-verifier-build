"""
CCS Verifier — Level 1 Receipt Module

Implements Iman Schrock's composition review v0.1 requirements for
cryptographic binding of the full verification evidence chain.

Key upgrades from Level 0 (HMAC-SHA256) to Level 1 (Ed25519):
  1.  request_hash          — SHA-256 of canonical command request
  2.  response_hash         — SHA-256 of canonical verification response
  3.  runtime_context_hash  — SHA-256 of runtime environment state
  4.  config_hash           — SHA-256 of verifier configuration
  5.  action                — CAID-compatible action category
  6.  issuer                — Signing entity identifier
  7.  audience              — Intended recipient identifier
  8.  nonce                 — Anti-replay random nonce
  9.  sequence              — Monotonic sequence number
  10. issuance / expiry     — Temporal validity window
  11. clock_skew_bounds     — Clock skew tolerance
  12. Ed25519 signature     — Public-key signature replacing HMAC
  13. verifier identity     — Signed source class + deployment mode

Design principles:
  - Deterministic canonical JSON for signature stability
  - Backward-compatible: L0 sign_receipt() unchanged
  - Performance target: < 1ms for full L1 receipt generation
  - Self-contained verification: public key embedded in receipt

Author: CCS Verifier Team
Version: 0.5.0-l1-preview
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional, Sequence

# ---------------------------------------------------------------------------
# Ed25519 — prefer cryptography library, fall back to pure-Python
# ---------------------------------------------------------------------------

_USE_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    _USE_CRYPTOGRAPHY = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReceiptLevel(Enum):
    """Receipt security level."""
    LEVEL_0 = 0   # HMAC-SHA256 (legacy)
    LEVEL_1 = 1   # Ed25519 + full evidence chain


class CAIDAction(Enum):
    """
    CAID-compatible action categories.

    Maps MCP / CCS tool invocations to a standardized action taxonomy
    that is interoperable with the Content Authenticity Initiative's
    action vocabulary and EMILIA action descriptors.
    """
    FILE_READ       = "file.read"
    FILE_WRITE      = "file.write"
    FILE_DELETE     = "file.delete"
    SHELL_EXEC      = "shell.execute"
    NETWORK_REQUEST = "network.request"
    DATA_QUERY      = "data.query"
    DATA_MUTATE     = "data.mutate"
    MODEL_INVOKE    = "model.invoke"
    SYSTEM_CONFIG   = "system.config"
    PROCESS_SPAWN   = "process.spawn"
    CRYPTO_SIGN     = "crypto.sign"
    CRYPTO_VERIFY   = "crypto.verify"
    MESSAGE_SEND    = "message.send"
    UNKNOWN         = "unknown"


class DeploymentMode(Enum):
    """Verifier deployment topology."""
    IN_PROCESS      = "in-process"
    OUT_OF_PROCESS  = "out-of-process"
    REMOTE          = "remote"


# ---------------------------------------------------------------------------
# CAID Action Mapping
# ---------------------------------------------------------------------------

# Tool name prefix → CAID action mapping.
# Checked in order: exact match first, then prefix match.
_TOOL_ACTION_MAP: dict[str, CAIDAction] = {
    # Shell / command execution
    "shell":            CAIDAction.SHELL_EXEC,
    "bash":             CAIDAction.SHELL_EXEC,
    "exec":             CAIDAction.SHELL_EXEC,
    "subprocess":       CAIDAction.PROCESS_SPAWN,
    "terminal":         CAIDAction.SHELL_EXEC,

    # File operations
    "read_file":        CAIDAction.FILE_READ,
    "write_file":       CAIDAction.FILE_WRITE,
    "edit_file":        CAIDAction.FILE_WRITE,
    "delete_file":      CAIDAction.FILE_DELETE,
    "list_directory":   CAIDAction.FILE_READ,
    "file_read":        CAIDAction.FILE_READ,
    "file_write":       CAIDAction.FILE_WRITE,

    # Network
    "fetch_web":        CAIDAction.NETWORK_REQUEST,
    "search_web":       CAIDAction.NETWORK_REQUEST,
    "http_request":     CAIDAction.NETWORK_REQUEST,
    "http_get":         CAIDAction.NETWORK_REQUEST,
    "http_post":        CAIDAction.NETWORK_REQUEST,
    "url_fetch":        CAIDAction.NETWORK_REQUEST,

    # Data / database
    "sql_query":        CAIDAction.DATA_QUERY,
    "sql_exec":         CAIDAction.DATA_MUTATE,
    "db_query":         CAIDAction.DATA_QUERY,
    "redis_get":        CAIDAction.DATA_QUERY,
    "redis_set":        CAIDAction.DATA_MUTATE,

    # Model / AI
    "llm_call":         CAIDAction.MODEL_INVOKE,
    "model_inference":  CAIDAction.MODEL_INVOKE,
    "embed":            CAIDAction.MODEL_INVOKE,

    # System
    "set_env":          CAIDAction.SYSTEM_CONFIG,
    "get_env":          CAIDAction.SYSTEM_CONFIG,
    "kill_process":     CAIDAction.PROCESS_SPAWN,

    # Messaging
    "send_email":       CAIDAction.MESSAGE_SEND,
    "send_message":     CAIDAction.MESSAGE_SEND,
    "notify":           CAIDAction.MESSAGE_SEND,

    # Crypto
    "sign_data":        CAIDAction.CRYPTO_SIGN,
    "verify_signature": CAIDAction.CRYPTO_VERIFY,
}

# MCP-style tool name prefixes (e.g., "mcp__filesystem__read_file")
_MCP_PREFIX_MAP: list[tuple[str, CAIDAction]] = [
    ("mcp__filesystem__read",   CAIDAction.FILE_READ),
    ("mcp__filesystem__write",  CAIDAction.FILE_WRITE),
    ("mcp__filesystem__edit",   CAIDAction.FILE_WRITE),
    ("mcp__filesystem__delete", CAIDAction.FILE_DELETE),
    ("mcp__filesystem__list",   CAIDAction.FILE_READ),
    ("mcp__shell__",            CAIDAction.SHELL_EXEC),
    ("mcp__bash__",             CAIDAction.SHELL_EXEC),
    ("mcp__fetch__",            CAIDAction.NETWORK_REQUEST),
    ("mcp__search__",           CAIDAction.NETWORK_REQUEST),
    ("mcp__http__",             CAIDAction.NETWORK_REQUEST),
    ("mcp__db__query",          CAIDAction.DATA_QUERY),
    ("mcp__db__exec",           CAIDAction.DATA_MUTATE),
    ("mcp__llm__",              CAIDAction.MODEL_INVOKE),
    ("mcp__email__",            CAIDAction.MESSAGE_SEND),
]


def map_tool_to_action(tool: str) -> CAIDAction:
    """
    Map a tool name to a CAID-compatible action category.

    Resolution order:
      1. Exact match in _TOOL_ACTION_MAP
      2. MCP prefix match in _MCP_PREFIX_MAP
      3. Heuristic: contains 'read' → FILE_READ, 'write' → FILE_WRITE, etc.
      4. Fallback: UNKNOWN
    """
    if not tool:
        return CAIDAction.UNKNOWN

    tool_lower = tool.lower()

    # 1. Exact match
    if tool_lower in _TOOL_ACTION_MAP:
        return _TOOL_ACTION_MAP[tool_lower]

    # 2. MCP prefix match
    for prefix, action in _MCP_PREFIX_MAP:
        if tool_lower.startswith(prefix):
            return action

    # 3. Heuristic fallback
    if any(kw in tool_lower for kw in ("read", "get", "list", "show", "view", "cat")):
        return CAIDAction.FILE_READ
    if any(kw in tool_lower for kw in ("write", "create", "edit", "update", "put", "set")):
        return CAIDAction.FILE_WRITE
    if any(kw in tool_lower for kw in ("delete", "remove", "rm", "drop")):
        return CAIDAction.FILE_DELETE
    if any(kw in tool_lower for kw in ("exec", "run", "shell", "bash", "cmd")):
        return CAIDAction.SHELL_EXEC
    if any(kw in tool_lower for kw in ("fetch", "http", "url", "request", "curl", "wget")):
        return CAIDAction.NETWORK_REQUEST
    if any(kw in tool_lower for kw in ("query", "select", "search")):
        return CAIDAction.DATA_QUERY
    if any(kw in tool_lower for kw in ("insert", "update", "delete", "mutate")):
        return CAIDAction.DATA_MUTATE
    if any(kw in tool_lower for kw in ("model", "llm", "infer", "embed", "generate")):
        return CAIDAction.MODEL_INVOKE
    if any(kw in tool_lower for kw in ("send", "email", "message", "notify", "publish")):
        return CAIDAction.MESSAGE_SEND

    return CAIDAction.UNKNOWN


# ---------------------------------------------------------------------------
# Hashing utilities
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    """Full SHA-256 hex digest (64 chars)."""
    return hashlib.sha256(data).hexdigest()


def _short_hash(data: bytes, length: int = 16) -> str:
    """Truncated SHA-256 hex for compact receipt fields."""
    return hashlib.sha256(data).hexdigest()[:length]


def compute_request_hash(
    agent_id: str,
    tool: str,
    params: dict[str, Any],
    timestamp: float,
    trace_id: str,
) -> str:
    """SHA-256 hash of the complete request payload."""
    payload = {
        "agent_id": agent_id,
        "tool": tool,
        "params": params,
        "timestamp": timestamp,
        "trace_id": trace_id,
    }
    return _sha256_hex(_canonical_json(payload))


def compute_response_hash(
    verdict: str,
    block_reason: str,
    rule_results: list[dict],
    verified_at: float,
    error_code: int,
) -> str:
    """SHA-256 hash of the complete verification response."""
    payload = {
        "verdict": verdict,
        "block_reason": block_reason,
        "rule_results": rule_results,
        "verified_at": verified_at,
        "error_code": error_code,
    }
    return _sha256_hex(_canonical_json(payload))


def compute_runtime_context_hash(
    python_version: str,
    platform_info: str,
    pid: int,
    hostname: str,
    cwd: str,
    extra: Optional[dict] = None,
) -> str:
    """SHA-256 hash of the runtime environment state."""
    payload = {
        "python_version": python_version,
        "platform": platform_info,
        "pid": pid,
        "hostname": hostname,
        "cwd": cwd,
        "extra": extra or {},
    }
    return _sha256_hex(_canonical_json(payload))


def compute_config_hash(
    rules: list[str],
    deployment_mode: str,
    verifier_version: str,
    max_audit_log: int,
    extra: Optional[dict] = None,
) -> str:
    """SHA-256 hash of the verifier configuration."""
    payload = {
        "rules": sorted(rules),
        "deployment_mode": deployment_mode,
        "verifier_version": verifier_version,
        "max_audit_log": max_audit_log,
        "extra": extra or {},
    }
    return _sha256_hex(_canonical_json(payload))


def capture_runtime_context() -> dict[str, Any]:
    """Capture current runtime environment state."""
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "pid": os.getpid(),
        "hostname": platform.node(),
        "cwd": os.getcwd(),
    }


# ---------------------------------------------------------------------------
# Ed25519 Signer
# ---------------------------------------------------------------------------

class Ed25519Signer:
    """
    Ed25519 signing key manager.

    Wraps the cryptography library's Ed25519 implementation.
    Generates keypair on construction if not provided.
    """

    def __init__(self, private_key_bytes: Optional[bytes] = None):
        """
        Args:
            private_key_bytes: 32-byte Ed25519 seed. If None, generates new keypair.
        """
        if not _USE_CRYPTOGRAPHY:
            raise RuntimeError(
                "cryptography library not available. Install with: pip install cryptography"
            )

        if private_key_bytes is not None:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()

    # -- Signing --

    def sign(self, data: bytes) -> bytes:
        """Sign data with Ed25519. Returns 64-byte signature."""
        return self._private_key.sign(data)

    def sign_hex(self, data: bytes) -> str:
        """Sign data and return hex-encoded signature."""
        return self.sign(data).hex()

    # -- Key export --

    def get_private_key_bytes(self) -> bytes:
        """Export 32-byte private key seed."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def get_private_key_hex(self) -> str:
        """Export private key as hex string."""
        return self.get_private_key_bytes().hex()

    def get_public_key_bytes(self) -> bytes:
        """Export 32-byte public key."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_public_key_hex(self) -> str:
        """Export public key as hex string."""
        return self.get_public_key_bytes().hex()

    @property
    def public_key(self):
        """Underlying Ed25519PublicKey object."""
        return self._public_key


def verify_ed25519_signature(
    public_key_hex: str,
    data: bytes,
    signature_hex: str,
) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        public_key_hex: Hex-encoded 32-byte public key.
        data: Original signed data bytes.
        signature_hex: Hex-encoded 64-byte signature.

    Returns:
        True if signature is valid, False otherwise.
    """
    if not _USE_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library not available")

    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, data)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# L1 Receipt Data Structure
# ---------------------------------------------------------------------------

@dataclass
class L1Receipt:
    """
    Level 1 cryptographic receipt with full evidence chain.

    Contains all 13 fields required by Iman Schrock's composition review v0.1,
    plus backward-compatible L0 fields.
    """

    # --- Receipt metadata ---
    receipt_level: int = 1
    receipt_version: str = "1.0"

    # --- L0 fields (backward compatible) ---
    trace_id: str = ""
    verdict: str = ""
    timestamp: str = ""          # ISO 8601
    tool: str = ""
    params_hash: str = ""        # Short hash for L0 compat

    # --- L1: Cryptographic binding (fields 1-4) ---
    request_hash: str = ""           # [1] Full request content hash
    response_hash: str = ""          # [2] Response integrity hash
    runtime_context_hash: str = ""   # [3] Runtime environment hash
    config_hash: str = ""            # [4] Verifier config hash

    # --- L1: CAID action (field 5) ---
    action: str = ""                 # [5] CAID-compatible action

    # --- L1: Identity & routing (fields 6-7) ---
    issuer: str = ""                 # [6] Signing entity
    audience: str = ""               # [7] Intended recipient

    # --- L1: Anti-replay (fields 8-9) ---
    nonce: str = ""                  # [8] Random nonce
    sequence: int = 0                # [9] Monotonic sequence

    # --- L1: Temporal validity (fields 10-11) ---
    issuance: str = ""               # [10] ISO 8601 issue time
    expiry: str = ""                 # [10] ISO 8601 expiry time
    clock_skew_bounds: dict = field(  # [11] Clock skew tolerance
        default_factory=lambda: {"min_skew_s": -30, "max_skew_s": 30}
    )

    # --- L1: Verifier identity (field 13) ---
    verifier_source_class: str = ""       # [13] Source class name
    verifier_deployment_mode: str = ""    # [13] Deployment topology
    verifier_version: str = ""            # [13] Verifier version

    # --- L1: Signature (field 12) ---
    signature_algorithm: str = "Ed25519"
    public_key: str = ""            # [12] Hex-encoded Ed25519 public key
    signature: str = ""             # [12] Hex-encoded Ed25519 signature

    # --- L0 backward compat: HMAC (optional, for dual-mode) ---
    hmac: str = ""                  # L0 HMAC if dual-signing

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def signing_payload(self) -> bytes:
        """
        Compute the canonical bytes that the Ed25519 signature covers.

        The signature is computed over the entire receipt EXCLUDING the
        `signature` field itself, ensuring any tampering with any field
        invalidates the signature.
        """
        d = self.to_dict()
        d.pop("signature", None)
        return _canonical_json(d)

    def verify_signature(self) -> bool:
        """
        Verify this receipt's Ed25519 signature using the embedded public key.

        Returns:
            True if the signature is valid.
        """
        if not self.signature or not self.public_key:
            return False
        return verify_ed25519_signature(
            self.public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_temporal(self, now: Optional[float] = None) -> bool:
        """
        Check that the receipt is within its temporal validity window,
        accounting for clock skew tolerance.

        Args:
            now: Current Unix timestamp. Defaults to time.time().

        Returns:
            True if within validity window (including skew tolerance).
        """
        if now is None:
            now = time.time()

        min_skew = self.clock_skew_bounds.get("min_skew_s", -30)
        max_skew = self.clock_skew_bounds.get("max_skew_s", 30)

        try:
            from datetime import datetime, timezone
            issuance_dt = datetime.fromisoformat(self.issuance.replace("Z", "+00:00"))
            expiry_dt = datetime.fromisoformat(self.expiry.replace("Z", "+00:00"))
            issuance_ts = issuance_dt.timestamp()
            expiry_ts = expiry_dt.timestamp()
        except Exception:
            return False

        return (issuance_ts + min_skew) <= now <= (expiry_ts + max_skew)


# ---------------------------------------------------------------------------
# L1 Receipt Builder
# ---------------------------------------------------------------------------

class L1ReceiptBuilder:
    """
    Builds Level 1 receipts with Ed25519 signatures.

    Usage:
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:v0.5.0",
            audience="agent:default",
            verifier_source_class="VerifierServer",
            verifier_deployment_mode=DeploymentMode.IN_PROCESS,
            verifier_version="0.5.0",
            rules=["ssrf_protection", "rce_protection"],
        )
        receipt = builder.build(command, verification_result, signing_key=old_hmac_key)
    """

    def __init__(
        self,
        signer: Ed25519Signer,
        issuer: str = "ccs-verifier",
        audience: str = "agent:default",
        verifier_source_class: str = "VerifierServer",
        verifier_deployment_mode: DeploymentMode = DeploymentMode.IN_PROCESS,
        verifier_version: str = "0.5.0",
        rules: Optional[list[str]] = None,
        max_audit_log: int = 100_000,
        validity_seconds: int = 300,
        clock_skew_bounds: Optional[dict] = None,
        config_extra: Optional[dict] = None,
    ):
        self._signer = signer
        self._issuer = issuer
        self._audience = audience
        self._verifier_source_class = verifier_source_class
        self._verifier_deployment_mode = verifier_deployment_mode.value
        self._verifier_version = verifier_version
        self._rules = rules or []
        self._max_audit_log = max_audit_log
        self._validity_seconds = validity_seconds
        self._clock_skew_bounds = clock_skew_bounds or {"min_skew_s": -30, "max_skew_s": 30}
        self._config_extra = config_extra or {}
        self._sequence: int = 0

        # Pre-compute config hash (stable across receipts)
        self._config_hash = compute_config_hash(
            rules=self._rules,
            deployment_mode=self._verifier_deployment_mode,
            verifier_version=self._verifier_version,
            max_audit_log=self._max_audit_log,
            extra=self._config_extra,
        )

    @property
    def config_hash(self) -> str:
        """Pre-computed verifier config hash."""
        return self._config_hash

    @property
    def public_key_hex(self) -> str:
        """Ed25519 public key (hex)."""
        return self._signer.get_public_key_hex()

    def build(
        self,
        # Command / request info
        agent_id: str,
        tool: str,
        params: dict[str, Any],
        trace_id: str,
        request_timestamp: float,
        # Verification result info
        verdict: str,
        block_reason: str = "",
        rule_results: Optional[list[dict]] = None,
        verified_at: Optional[float] = None,
        error_code: int = -32000,
        # Optional: HMAC key for dual-mode (L0 + L1)
        hmac_key: Optional[bytes] = None,
        # Optional: override runtime context
        runtime_context: Optional[dict] = None,
    ) -> L1Receipt:
        """
        Build a complete Level 1 receipt.

        Args:
            agent_id: Agent identifier.
            tool: Tool name invoked.
            params: Tool parameters dict.
            trace_id: Request trace ID.
            request_timestamp: Original request timestamp.
            verdict: Verification verdict ("allow"/"deny"/"escalate").
            block_reason: Reason for denial if any.
            rule_results: List of rule result dicts.
            verified_at: Verification timestamp. Defaults to now.
            error_code: Dimension error code.
            hmac_key: Optional HMAC key for dual L0+L1 signing.
            runtime_context: Optional pre-captured runtime context.

        Returns:
            L1Receipt with Ed25519 signature.
        """
        rule_results = rule_results or []
        verified_at = verified_at if verified_at is not None else time.time()

        # --- Compute hashes ---
        req_hash = compute_request_hash(
            agent_id, tool, params, request_timestamp, trace_id,
        )
        resp_hash = compute_response_hash(
            verdict, block_reason, rule_results, verified_at, error_code,
        )

        rt_ctx = runtime_context or capture_runtime_context()
        rt_hash = compute_runtime_context_hash(
            rt_ctx["python_version"],
            rt_ctx["platform"],
            rt_ctx["pid"],
            rt_ctx["hostname"],
            rt_ctx["cwd"],
            rt_ctx.get("extra"),
        )

        # --- CAID action mapping ---
        action = map_tool_to_action(tool).value

        # --- Temporal bounds ---
        from datetime import datetime, timezone, timedelta
        issuance_dt = datetime.fromtimestamp(verified_at, tz=timezone.utc)
        expiry_dt = issuance_dt + timedelta(seconds=self._validity_seconds)

        # --- Sequence & nonce ---
        self._sequence += 1
        nonce = secrets.token_hex(16)  # 128-bit nonce

        # --- Params hash (L0 compat, short) ---
        params_hash = _short_hash(_canonical_json(params))

        # --- Build receipt ---
        receipt = L1Receipt(
            receipt_level=1,
            receipt_version="1.0",
            trace_id=trace_id,
            verdict=verdict,
            timestamp=issuance_dt.isoformat(),
            tool=tool,
            params_hash=params_hash,
            request_hash=req_hash,
            response_hash=resp_hash,
            runtime_context_hash=rt_hash,
            config_hash=self._config_hash,
            action=action,
            issuer=self._issuer,
            audience=self._audience,
            nonce=nonce,
            sequence=self._sequence,
            issuance=issuance_dt.isoformat(),
            expiry=expiry_dt.isoformat(),
            clock_skew_bounds=dict(self._clock_skew_bounds),
            verifier_source_class=self._verifier_source_class,
            verifier_deployment_mode=self._verifier_deployment_mode,
            verifier_version=self._verifier_version,
            signature_algorithm="Ed25519",
            public_key=self._signer.get_public_key_hex(),
            signature="",  # placeholder, filled below
        )

        # --- L0 HMAC (computed BEFORE signing for dual-mode binding) ---
        if hmac_key is not None:
            l0_payload = f"{trace_id}:{verdict}:{verified_at}:{tool}:{params_hash}".encode()
            receipt.hmac = hmac.new(hmac_key, l0_payload, hashlib.sha256).hexdigest()[:32]

        # --- Ed25519 signature over full receipt (excl. signature field) ---
        signing_payload = receipt.signing_payload()
        receipt.signature = self._signer.sign_hex(signing_payload)

        return receipt

    def reset_sequence(self) -> None:
        """Reset the sequence counter (for testing)."""
        self._sequence = 0


# ---------------------------------------------------------------------------
# Verification utilities
# ---------------------------------------------------------------------------

def verify_l1_receipt(receipt: L1Receipt) -> dict[str, bool]:
    """
    Perform full verification of an L1 receipt.

    Checks:
      1. Ed25519 signature validity
      2. Temporal validity (within issuance/expiry + clock skew)
      3. Receipt level is 1
      4. All required fields are present

    Returns:
        Dict of check name → bool.
    """
    results = {}

    # 1. Signature verification
    results["signature_valid"] = receipt.verify_signature()

    # 2. Temporal validity
    results["temporal_valid"] = receipt.verify_temporal()

    # 3. Receipt level
    results["receipt_level_1"] = receipt.receipt_level == 1

    # 4. Required fields present
    required_fields = [
        "trace_id", "verdict", "timestamp", "tool", "params_hash",
        "request_hash", "response_hash", "runtime_context_hash", "config_hash",
        "action", "issuer", "audience", "nonce", "sequence",
        "issuance", "expiry", "clock_skew_bounds",
        "verifier_source_class", "verifier_deployment_mode", "verifier_version",
        "signature_algorithm", "public_key", "signature",
    ]
    d = receipt.to_dict()
    results["all_fields_present"] = all(
        d.get(f) not in ("", None, 0) or f in ("sequence",)
        for f in required_fields
    )
    # sequence can be 0 on first receipt, so check separately
    results["sequence_valid"] = isinstance(receipt.sequence, int) and receipt.sequence >= 0

    # 5. Signature algorithm
    results["ed25519_algorithm"] = receipt.signature_algorithm == "Ed25519"

    results["all_pass"] = all(results.values())

    return results


def serialize_receipt(receipt: L1Receipt) -> str:
    """Serialize receipt to compact JSON string."""
    return json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":"))


def deserialize_receipt(json_str: str) -> L1Receipt:
    """Deserialize receipt from JSON string."""
    d = json.loads(json_str)
    return L1Receipt(**d)


# ---------------------------------------------------------------------------
# Backward compatibility: L0 sign_receipt (unchanged from v0.4.1)
# ---------------------------------------------------------------------------

def sign_receipt_l0(
    trace_id: str,
    verdict: str,
    timestamp: float,
    secret: bytes,
    tool: str = "",
    params_hash: str = "",
    rule_summary: str = "",
) -> str:
    """
    L0 HMAC-SHA256 receipt (legacy, unchanged from v0.4.1).

    Kept for backward compatibility. New code should use L1ReceiptBuilder.
    """
    payload = f"{trace_id}:{verdict}:{timestamp}:{tool}:{params_hash}:{rule_summary}".encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    # Enums
    "ReceiptLevel",
    "CAIDAction",
    "DeploymentMode",
    # Core classes
    "L1Receipt",
    "L1ReceiptBuilder",
    "Ed25519Signer",
    # Action mapping
    "map_tool_to_action",
    # Hash utilities
    "compute_request_hash",
    "compute_response_hash",
    "compute_runtime_context_hash",
    "compute_config_hash",
    "capture_runtime_context",
    # Verification
    "verify_ed25519_signature",
    "verify_l1_receipt",
    "serialize_receipt",
    "deserialize_receipt",
    # Backward compat
    "sign_receipt_l0",
]

__version__ = "0.5.0-l1-preview"
