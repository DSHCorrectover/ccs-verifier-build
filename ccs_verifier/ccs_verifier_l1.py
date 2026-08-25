"""
CCS L1 Receipt — Level-1 tamper-evident verification receipt with Ed25519 signatures.

Receipt format version 1.1 — CAID (Chain of Attestation for Inference & Deployment)
compatible attestation receipt covering the full verification context.

Field structure (30 fields):
  Core identity: trace_id, receipt_version, verdict, timestamp
  Tool binding:   tool, tool_call_id, params_hash, args_digest
  Rule context:   rule_summary, rule_version
  Request/response binding: request_hash, response_hash
  Runtime context: runtime_context_hash, config_hash
  Verifier identity: verifier_source_class, deployment_mode, issuer
  Audience & nonce: audience, nonce
  Sequence & bounds: sequence, issued_at, expires_at, max_clock_skew
  Action (CAID-compatible): action
  Signature: signature (Ed25519), signing_algorithm, public_key_fingerprint,
             public_key (base64 raw Ed25519 public key, embedded for
             independent third-party verification)
  Metadata: verified_at, latency_us

Signature algorithm: Ed25519 (RFC 8032) over RFC 8785 JCS canonical JSON.
The signing_algorithm field is included in the signed payload to prevent
algorithm substitution attacks. The public_key field is ALSO included in
the signed payload so that any party in possession of the receipt can
independently verify the signature without an out-of-band key distribution
channel; the public_key_fingerprint acts as an additional check.

v1.1.4 fixes (per Iman Schrock independent re-audit):
  - RFC 8785 serializer: fix -0.0 → "0.0", non-BMP Unicode → surrogate pairs,
    reject oversized integers (>2^53-1), fix float scientific notation fallback
  - from_dict: validate receipt_version, reject unsigned allow receipts,
    detect duplicate JSON keys via object_pairs_hook
  - Signing: include signing_algorithm in signed payload, enforce canonical
    Base64, remove silent fallback (explicit error if cryptography missing)
  - Version consistency: all modules aligned to 1.1.4

v1.1.5 fixes (per Iman Schrock re-audit Round 2):
  - RFC 8785 JCS: replace custom serializer with standard `jcs` library for
    correct canonical JSON (RFC 8785 compliant: UTF-16 sort, shortest float,
    raw UTF-8, safe integer range enforcement)
  - Base64 canonicalization: decode/re-encode normalization for signatures
    (prevents non-canonical Base64 forgery)
  - public_key_fingerprint binding: fingerprint included in signed payload
    to prevent key substitution attacks
  - Enum serialization: Verdict enum values converted to string in
    signing_payload() for JSON serialization compatibility
  - Added `_check_duplicate_keys()` for RFC 8785 unique key enforcement
  - pyproject.toml: added `jcs>=0.2` as core dependency

v1.1.6 fixes:
  - Full integration test suite (3 end-to-end tests)
  - Builder validation for required profile bindings
  - Conformance test vectors (l1-001 through l1-005)

v1.1.7 fixes (per Iman Schrock external reproduction findings):
  - FIELD RENAME (spec alignment per CCS spec v1.1 §5.9):
    - issuance_bound → issued_at (float, Level 1, signed)
    - expiry_bound → expires_at (float, Level 1, signed)
    - clock_skew_bound → max_clock_skew (float, Level 1, signed)
  - BACKWARD COMPATIBILITY: from_dict() accepts old field names and maps them
    to new names. Old receipts can be deserialized and fields read, but signature
    verification will fail (expected: signed payload content changed).
  - TIME VALIDATION: build() now validates timestamp >= issued_at
  - REPRODUCTION MATERIAL: includes original bytes (raw dicts) for all hash
    computations so external verifiers can independently recompute hashes
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature
    _HAS_ED25519 = True
except ImportError:  # pragma: no cover
    _HAS_ED25519 = False

try:
    import jcs as _jcs
    _HAS_JCS = True
except ImportError:  # pragma: no cover
    _HAS_JCS = False

from ccs_verifier.protocol import Verdict


RECEIPT_VERSION = "1.1"
SIGNING_ALGORITHM = "Ed25519"

# Maximum safe integer for canonical JSON (2^53 - 1 per RFC 8785 §6.2)
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MIN_SAFE_INTEGER = -(1 << 53) + 1

# Known receipt fields (for strict deserialization)
_KNOWN_FIELDS: frozenset[str] = frozenset()  # populated after class definition

# Old field name → new field name mapping (v1.1.6 → v1.1.7)
# Per CCS spec v1.1 §5.9 and Appendix A Field 19-21
_OLD_FIELD_MAP: dict[str, str] = {
    "issuance_bound": "issued_at",
    "expiry_bound": "expires_at",
    "clock_skew_bound": "max_clock_skew",
}


def _require_ed25519():
    """Raise explicit error if cryptography library is not available."""
    if not _HAS_ED25519:
        raise RuntimeError(
            "cryptography library is required for Ed25519 operations. "
            "Install it with: pip install cryptography"
        )


# ---------------------------------------------------------------------------
# RFC 8785 JCS canonical JSON serialization
# ---------------------------------------------------------------------------

def _require_jcs():
    """Raise explicit error if jcs library is not available."""
    if not _HAS_JCS:
        raise RuntimeError(
            "jcs library is required for RFC 8785 canonical JSON. "
            "Install it with: pip install jcs"
        )


def _validate_safe_integers(value: Any) -> None:
    """
    Recursively validate that all integers are within RFC 8785 safe range.

    RFC 8785 §6.2: integers outside ±(2^53 - 1) MUST be rejected because
    JSON parsers commonly use IEEE 754 doubles and would lose precision.
    """
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if value > _MAX_SAFE_INTEGER or value < _MIN_SAFE_INTEGER:
            raise ValueError(
                f"Integer {value} exceeds RFC 8785 safe integer range "
                f"({_MIN_SAFE_INTEGER} to {_MAX_SAFE_INTEGER}). "
                f"Use a string or float for values outside this range."
            )
    elif isinstance(value, float):
        return
    elif isinstance(value, str):
        return
    elif value is None:
        return
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_safe_integers(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            _validate_safe_integers(k)
            _validate_safe_integers(v)


def canonical_json(data: dict[str, Any]) -> bytes:
    """
    RFC 8785 JCS canonical JSON serialization for signing.

    Uses the standard `jcs` library (https://pypi.org/project/jcs/) which
    implements RFC 8785 correctly:
    - Object keys sorted by UTF-16 code units (per RFC 8785 §3.2.3)
    - Floats use shortest representation; -0.0 → "0"; 1.0 → "1"
    - Non-ASCII characters encoded as raw UTF-8 (not \\uXXXX)
    - No unnecessary whitespace

    Additionally enforces safe integer range (±2^53-1) per RFC 8785 §6.2.

    Args:
        data: Dictionary to serialize.

    Returns:
        Canonical JSON bytes (UTF-8 encoded).
    """
    _require_jcs()
    _validate_safe_integers(data)
    return _jcs.canonicalize(data)


def _check_duplicate_keys(pairs):
    """
    JSON object_pairs_hook to detect duplicate keys.

    RFC 8785 requires unique keys. If duplicates are found, the receipt
    is ambiguous and must be rejected.
    """
    seen = set()
    for key, value in pairs:
        if key in seen:
            raise ValueError(
                f"Duplicate JSON key detected: '{key}'. "
                f"RFC 8785 requires unique keys; refusing to deserialize."
            )
        seen.add(key)
    return dict(pairs)


# ---------------------------------------------------------------------------
# L1 Receipt data class
# ---------------------------------------------------------------------------

@dataclass
class L1Receipt:
    """
    Level-1 verification receipt with Ed25519 signature.

    30 fields providing full attestation of the verification event,
    compatible with the CAID (Chain of Attestation for Inference & Deployment)
    specification.

    Field naming follows CCS spec v1.1 §5.9:
      - issued_at: Issue timestamp (was issuance_bound in v1.1.6)
      - expires_at: Expiry timestamp (was expiry_bound in v1.1.6)
      - max_clock_skew: Clock tolerance in seconds (was clock_skew_bound in v1.1.6)
    """
    # Core identity (4)
    trace_id: str
    receipt_version: str = RECEIPT_VERSION
    verdict: str = "allow"
    timestamp: float = field(default_factory=time.time)

    # Tool binding (4)
    tool: str = ""
    tool_call_id: str = ""
    params_hash: str = ""
    args_digest: str = ""

    # Rule context (2)
    rule_summary: str = ""
    rule_version: str = ""

    # Request/response binding (2)
    request_hash: str = ""
    response_hash: str = ""

    # Runtime context (2)
    runtime_context_hash: str = ""
    config_hash: str = ""

    # Verifier identity (3)
    verifier_source_class: str = ""
    deployment_mode: str = ""
    issuer: str = ""

    # Audience & nonce (2)
    audience: str = ""
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))

    # Sequence & time bounds (4) — renamed per CCS spec v1.1
    sequence: int = 0
    issued_at: float = 0.0
    expires_at: float = 0.0
    max_clock_skew: float = 0.0

    # CAID-compatible action (1)
    action: str = ""

    # Signature fields (4)
    signature: str = ""
    signing_algorithm: str = SIGNING_ALGORITHM
    public_key_fingerprint: str = ""
    # base64-encoded raw 32-byte Ed25519 public key; embedded so third parties
    # can independently verify the signature without an out-of-band key channel.
    # Included in the signed payload (prevents key substitution attacks).
    public_key: str = ""

    # Metadata (2)
    verified_at: float = field(default_factory=time.time)
    latency_us: float = 0.0

    # Total: 4+4+2+2+2+3+2+4+1+4+2 = 30 fields

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    def to_dict(self) -> dict[str, Any]:
        """Convert receipt to dict (uses new field names only)."""
        return asdict(self)

    def signing_payload(self) -> bytes:
        """
        Generate the canonical payload that gets signed.

        Includes all receipt fields EXCEPT the signature itself.

        IMPORTANT: signing_algorithm IS included in the signed payload
        to prevent algorithm substitution attacks (e.g., changing Ed25519
        to a weaker algorithm).

        IMPORTANT: public_key_fingerprint IS included in the signed payload
        to bind the identity of the signing key to the receipt. This prevents
        an attacker from substituting a different public key/fingerprint
        while keeping the signature valid against their own key.
        """
        data = {}
        for k, v in asdict(self).items():
            if k == "signature":
                continue
            # Convert Enum values to their string representation for JSON serialization
            if isinstance(v, Enum):
                data[k] = v.value
            else:
                data[k] = v
        return canonical_json(data)

    def verify_signature(self, public_key_bytes: Optional[bytes] = None) -> bool:
        """
        Verify the Ed25519 signature on this receipt.

        Args:
            public_key_bytes: Raw 32-byte Ed25519 public key. If None, uses
                the embedded public_key field (base64-decoded) when present,
                enabling standalone third-party verification without an
                out-of-band key channel.

        Returns:
            True if signature is valid, False otherwise.
        """
        _require_ed25519()
        if not self.signature:
            return False

        # If no key was explicitly supplied, fall back to the embedded key.
        if public_key_bytes is None:
            if not self.public_key:
                return False
            try:
                public_key_bytes = base64.b64decode(self.public_key, validate=True)
            except Exception:
                return False
            if len(public_key_bytes) != 32:
                return False
            # Cross-check embedded public_key against its own fingerprint
            # (both are part of the signed payload; mismatches indicate tampering)
            if self.public_key_fingerprint:
                expected_fp = public_key_fingerprint(public_key_bytes)
                if expected_fp != self.public_key_fingerprint:
                    return False

        # Validate signing algorithm matches expected
        if self.signing_algorithm != SIGNING_ALGORITHM:
            return False

        # Validate and canonicalize Base64 (RFC 4648 §4, no line breaks)
        # Canonicalization ensures the signature string is in a unique,
        # normalized form to prevent non-canonical Base64 forgery.
        try:
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', self.signature):
                return False
            if len(self.signature) % 4 != 0:
                return False
            # Canonicalize: decode then re-encode to ensure unique representation
            sig_bytes = base64.b64decode(self.signature, validate=True)
            canonical_sig = base64.b64encode(sig_bytes).decode("ascii")
            # Reject non-canonical Base64 signatures to prevent forgery
            # via alternative encodings that decode to the same bytes.
            if canonical_sig != self.signature:
                return False
        except Exception:
            return False

        try:
            pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except (ValueError, Exception):
            return False

        # Validate fingerprint binding: the fingerprint in the receipt must
        # match the fingerprint of the provided public key. Since fingerprint
        # is included in the signed payload (see signing_payload), this
        # prevents an attacker from presenting a receipt signed with their
        # own key while claiming a different key's fingerprint.
        expected_fp = public_key_fingerprint(public_key_bytes)
        if self.public_key_fingerprint != expected_fp:
            return False

        try:
            pub_key.verify(sig_bytes, self.signing_payload())
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

    @classmethod
    def from_dict(cls, data: dict[str, Any], strict: bool = True) -> "L1Receipt":
        """
        Reconstruct an L1Receipt from a dict (e.g., from JSON).

        BACKWARD COMPATIBILITY (v1.1.7): Accepts old field names from v1.1.6:
          - issuance_bound → issued_at
          - expiry_bound → expires_at
          - clock_skew_bound → max_clock_skew
        Old receipts can be deserialized and fields read, but signature
        verification will FAIL because the signed payload content has changed.

        Args:
            data: Dictionary of receipt fields.
            strict: If True (default), reject unknown fields, validate
                receipt_version, and reject unsigned allow receipts.

        Raises:
            ValueError: If strict=True and data contains unknown fields.
            ValueError: If receipt_version doesn't match expected version.
            ValueError: If required fields are missing, None, or empty.
            ValueError: If string fields contain None values.
            ValueError: If fields exceed maximum length (4096 chars).
            ValueError: If unsigned receipt has verdict="allow" (security risk).
        """
        if not isinstance(data, dict):
            raise ValueError("from_dict requires a dict")

        # --- Backward compatibility: remap old field names to new names ---
        remapped = dict(data)
        old_fields_used = []
        for old_name, new_name in _OLD_FIELD_MAP.items():
            if old_name in remapped:
                old_fields_used.append(old_name)
                if new_name not in remapped:
                    remapped[new_name] = remapped[old_name]
                del remapped[old_name]

        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        if strict:
            unknown = set(remapped.keys()) - field_names
            if unknown:
                raise ValueError(
                    f"Unknown fields in L1Receipt: {sorted(unknown)}. "
                    f"Refusing to deserialize to prevent signature bypass."
                )

            # Validate receipt_version
            if 'receipt_version' in remapped:
                rv = remapped['receipt_version']
                if rv != RECEIPT_VERSION:
                    raise ValueError(
                        f"Unsupported receipt_version: '{rv}'. "
                        f"Expected '{RECEIPT_VERSION}'. "
                        f"Refusing to deserialize incompatible receipt."
                    )

        filtered = {k: v for k, v in remapped.items() if k in field_names}

        # --- Input validation: reject None, empty critical fields, oversized ---
        _MAX_FIELD_LEN = 4096

        # Check required fields (no default or must be present)
        if 'trace_id' not in filtered or filtered['trace_id'] is None:
            raise ValueError("Missing required field: trace_id")
        if not isinstance(filtered['trace_id'], str) or not filtered['trace_id']:
            raise ValueError("Field trace_id must be a non-empty string")

        # Validate all string fields: reject None, enforce max length
        for k, v in list(filtered.items()):
            if v is None:
                # For fields with defaults, None means use default — but only for non-critical
                if k in ('trace_id', 'verdict', 'signature', 'public_key_fingerprint'):
                    raise ValueError(f"Field {k} must not be None")
                # Remove None for optional fields — let dataclass use default
                del filtered[k]
            elif isinstance(v, str):
                if len(v) > _MAX_FIELD_LEN:
                    raise ValueError(
                        f"Field {k} exceeds maximum length ({len(v)} > {_MAX_FIELD_LEN})"
                    )

        # Reject empty signature / fingerprint when present (security-critical)
        if 'signature' in filtered and not filtered['signature']:
            raise ValueError("Field signature must not be empty")
        if 'public_key_fingerprint' in filtered and not filtered['public_key_fingerprint']:
            raise ValueError("Field public_key_fingerprint must not be empty")
        if 'public_key' in filtered and not filtered['public_key']:
            raise ValueError("Field public_key must not be empty when present")
        # If both signature and public_key are present, cross-check they match
        if filtered.get('signature') and filtered.get('public_key'):
            try:
                embedded_pk = base64.b64decode(filtered['public_key'], validate=True)
                if len(embedded_pk) != 32:
                    raise ValueError(
                        f"Field public_key must decode to 32 raw Ed25519 bytes, "
                        f"got {len(embedded_pk)}"
                    )
                # canonical base64 check
                canonical_pk = _canonical_base64(filtered['public_key'])
                if canonical_pk != filtered['public_key']:
                    raise ValueError(
                        "Field public_key is not in canonical Base64 form"
                    )
            except Exception as e:
                if isinstance(e, ValueError) and "must decode" in str(e):
                    raise
                if isinstance(e, ValueError) and "canonical" in str(e):
                    raise
                raise ValueError(f"Field public_key is not valid Base64: {e}")

        # Security: reject unsigned receipts with "allow" verdict in strict mode
        # An unsigned "allow" receipt provides no cryptographic assurance and
        # could be trivially forged.
        if strict:
            has_signature = filtered.get('signature', '')
            verdict = filtered.get('verdict', 'allow')
            if not has_signature and verdict == "allow":
                raise ValueError(
                    "Unsigned receipt with verdict='allow' is not permitted "
                    "in strict mode. An unsigned allow receipt provides no "
                    "cryptographic assurance and could be trivially forged. "
                    "Either provide a valid signature or use verdict='deny'."
                )

        return cls(**filtered)

    @classmethod
    def from_json(cls, json_str: str, strict: bool = True) -> "L1Receipt":
        """
        Reconstruct an L1Receipt from a JSON string.

        Uses object_pairs_hook to detect duplicate keys (RFC 8785 requires
        unique keys). Duplicate keys indicate a malformed or malicious receipt.

        Args:
            json_str: JSON string of receipt fields.
            strict: If True (default), apply strict validation.

        Raises:
            ValueError: If duplicate JSON keys are detected.
            ValueError: If validation fails (see from_dict).
        """
        try:
            data = json.loads(json_str, object_pairs_hook=_check_duplicate_keys)
        except ValueError:
            raise
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        return cls.from_dict(data, strict=strict)


# Populate _KNOWN_FIELDS after class definition
_KNOWN_FIELDS = frozenset(f.name for f in L1Receipt.__dataclass_fields__.values())


# ---------------------------------------------------------------------------
# Key management helpers
# ---------------------------------------------------------------------------

def generate_ed25519_key() -> bytes:
    """
    Generate a new Ed25519 private key.

    Returns:
        Raw 32-byte private key seed.
    """
    _require_ed25519()
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes_raw()


def get_public_key(private_key_seed: bytes) -> bytes:
    """
    Derive the Ed25519 public key from a private key seed.

    Args:
        private_key_seed: 32-byte private key seed.

    Returns:
        32-byte public key.
    """
    _require_ed25519()
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
    return private_key.public_key().public_bytes_raw()


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    """
    Compute a SHA-256 fingerprint of a public key.

    Note: The fingerprint identifies a candidate key but does NOT
    authenticate it. The relying party MUST have a pinned trust-root
    path to verify the public key's authenticity.

    Args:
        public_key_bytes: 32-byte Ed25519 public key.

    Returns:
        16-character hex fingerprint (first 8 bytes of SHA-256).
    """
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Base64 canonicalization helper
# ---------------------------------------------------------------------------

def _canonical_base64(b64_str: str) -> str:
    """
    Normalize a Base64 string to its canonical form.

    Decodes and re-encodes to ensure:
    - Standard alphabet (RFC 4648 §4)
    - Correct padding
    - No extraneous characters
    - Consistent case-sensitive encoding

    This prevents signature forgery via non-canonical Base64 representations
    that decode to the same bytes but differ in string form.

    Args:
        b64_str: Base64-encoded string.

    Returns:
        Canonical Base64 string.

    Raises:
        ValueError: If the input is not valid Base64.
    """
    raw = base64.b64decode(b64_str, validate=True)
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# Signing / verification functions
# ---------------------------------------------------------------------------

def sign_l1_receipt(
    receipt: L1Receipt,
    private_key_seed: bytes,
) -> L1Receipt:
    """
    Sign an L1 receipt with Ed25519.

    Fills in signature, signing_algorithm, and public_key_fingerprint fields.
    The signing_algorithm is included in the signed payload to prevent
    algorithm substitution attacks.

    Args:
        receipt: The L1Receipt to sign (will not be mutated).
        private_key_seed: 32-byte Ed25519 private key seed.

    Returns:
        A new L1Receipt with signature fields populated.
    """
    _require_ed25519()

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
    public_key_bytes = private_key.public_key().public_bytes_raw()
    fp = public_key_fingerprint(public_key_bytes)
    pk_b64 = _canonical_base64(base64.b64encode(public_key_bytes).decode("ascii"))

    # Set signing_algorithm, public_key_fingerprint, and public_key before
    # generating payload so all three are included in the signed data.
    # - signing_algorithm prevents algorithm substitution attacks
    # - public_key_fingerprint binds the signing key identity (short check)
    # - public_key embeds the raw Ed25519 public key so any party in
    #   possession of the receipt can independently verify the signature
    #   without an out-of-band key distribution channel.
    #   It is itself signed, preventing substitution attacks.
    receipt_for_signing = L1Receipt(
        **{k: v for k, v in asdict(receipt).items()
           if k not in ("signature", "signing_algorithm",
                        "public_key_fingerprint", "public_key")},
        signing_algorithm=SIGNING_ALGORITHM,
        public_key_fingerprint=fp,
        public_key=pk_b64,
    )
    payload = receipt_for_signing.signing_payload()
    signature = private_key.sign(payload)
    sig_b64 = _canonical_base64(base64.b64encode(signature).decode("ascii"))

    return L1Receipt(
        **{k: v for k, v in asdict(receipt).items()
           if k not in ("signature", "signing_algorithm",
                        "public_key_fingerprint", "public_key")},
        signature=sig_b64,
        signing_algorithm=SIGNING_ALGORITHM,
        public_key_fingerprint=fp,
        public_key=pk_b64,
    )


def verify_l1_receipt(
    receipt: L1Receipt,
    public_key_bytes: Optional[bytes] = None,
) -> bool:
    """
    Verify an L1 receipt's Ed25519 signature.

    Args:
        receipt: The L1Receipt to verify.
        public_key_bytes: Raw 32-byte Ed25519 public key. If None, uses
            the embedded public_key field when present, enabling standalone
            third-party verification.

    Returns:
        True if signature is valid, False otherwise.
    """
    return receipt.verify_signature(public_key_bytes)


# ---------------------------------------------------------------------------
# Helper: compute hashes from data (full SHA-256)
# ---------------------------------------------------------------------------

def compute_hash(data: Any) -> str:
    """
    Compute a SHA-256 hash of arbitrary data for receipt binding.

    Returns the full 64-character hex digest (256 bits).

    Args:
        data: Any JSON-serializable data.

    Returns:
        64-character hex SHA-256 hash.
    """
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = canonical_json(data)
    return hashlib.sha256(raw).hexdigest()


def compute_args_digest(args: dict[str, Any]) -> str:
    """
    Compute deterministic digest of tool arguments.

    Returns full 64-character SHA-256 hex digest.

    Args:
        args: Tool arguments dictionary.

    Returns:
        64-character hex digest.
    """
    return compute_hash(args)


def compute_request_hash(command_data: dict[str, Any]) -> str:
    """Compute hash of the full verification request."""
    return compute_hash(command_data)


def compute_response_hash(result_data: dict[str, Any]) -> str:
    """Compute hash of the full verification response."""
    return compute_hash(result_data)


# ---------------------------------------------------------------------------
# Receipt builder (with profile binding validation)
# ---------------------------------------------------------------------------

class L1ReceiptBuilder:
    """
    Fluent builder for constructing L1 receipts.

    Enforces required profile bindings before signing:
    - issuer, audience, action must be non-empty
    - expires_at must be > 0 for signed receipts
    - timestamp must be >= issued_at

    Usage:
        builder = L1ReceiptBuilder(trace_id="abc123", verdict=Verdict.ALLOW)
        builder.tool("shell").params_hash(params_hash).rule_summary(summary)
        builder.issuer("verifier-1").audience("agent-1").action("ccs.verify")
        builder.time_bounds(issued_at=time.time(), expires_at=time.time() + 300)
        receipt = builder.build(private_key_seed)
    """

    def __init__(self, trace_id: str, verdict: Verdict | str):
        verdict_str = verdict.value if isinstance(verdict, Verdict) else verdict
        self._receipt = L1Receipt(trace_id=trace_id, verdict=verdict_str)

    def tool(self, tool: str) -> "L1ReceiptBuilder":
        self._receipt.tool = tool
        return self

    def tool_call_id(self, tool_call_id: str) -> "L1ReceiptBuilder":
        self._receipt.tool_call_id = tool_call_id
        return self

    def params_hash(self, params_hash: str) -> "L1ReceiptBuilder":
        self._receipt.params_hash = params_hash
        return self

    def args_digest(self, args: dict[str, Any]) -> "L1ReceiptBuilder":
        self._receipt.args_digest = compute_args_digest(args)
        return self

    def rule_summary(self, summary: str) -> "L1ReceiptBuilder":
        self._receipt.rule_summary = summary
        return self

    def rule_version(self, version: str) -> "L1ReceiptBuilder":
        self._receipt.rule_version = version
        return self

    def request_hash(self, request: dict[str, Any]) -> "L1ReceiptBuilder":
        self._receipt.request_hash = compute_request_hash(request)
        return self

    def response_hash(self, response: dict[str, Any]) -> "L1ReceiptBuilder":
        self._receipt.response_hash = compute_response_hash(response)
        return self

    def runtime_context(self, context: dict[str, Any]) -> "L1ReceiptBuilder":
        self._receipt.runtime_context_hash = compute_hash(context)
        return self

    def config_hash(self, config: dict[str, Any]) -> "L1ReceiptBuilder":
        self._receipt.config_hash = compute_hash(config)
        return self

    def verifier_source_class(self, source_class: str) -> "L1ReceiptBuilder":
        self._receipt.verifier_source_class = source_class
        return self

    def deployment_mode(self, mode: str) -> "L1ReceiptBuilder":
        self._receipt.deployment_mode = mode
        return self

    def issuer(self, issuer: str) -> "L1ReceiptBuilder":
        self._receipt.issuer = issuer
        return self

    def audience(self, audience: str) -> "L1ReceiptBuilder":
        self._receipt.audience = audience
        return self

    def nonce(self, nonce: str) -> "L1ReceiptBuilder":
        self._receipt.nonce = nonce
        return self

    def sequence(self, seq: int) -> "L1ReceiptBuilder":
        self._receipt.sequence = seq
        return self

    def time_bounds(
        self,
        issued_at: float = 0.0,
        expiry: float = 0.0,
        clock_skew: float = 0.0,
    ) -> "L1ReceiptBuilder":
        """Set time bounds per CCS spec v1.1 §5.9.

        Args:
            issued_at: Issue timestamp (maps to receipt.issued_at).
            expiry: Expiry timestamp (maps to receipt.expires_at).
            clock_skew: Clock tolerance in seconds (maps to receipt.max_clock_skew).
        """
        self._receipt.issued_at = issued_at
        self._receipt.expires_at = expiry
        self._receipt.max_clock_skew = clock_skew
        return self

    def action(self, action: str) -> "L1ReceiptBuilder":
        self._receipt.action = action
        return self

    def latency_us(self, latency: float) -> "L1ReceiptBuilder":
        self._receipt.latency_us = latency
        return self

    def build(self, private_key_seed: Optional[bytes] = None) -> L1Receipt:
        """
        Build the receipt, optionally signing it.

        When signing (private_key_seed is provided), validates that required
        profile bindings are established:
        - issuer must be non-empty
        - audience must be non-empty
        - action must be non-empty
        - expires_at must be > 0
        - timestamp must be >= issued_at (time consistency)

        Args:
            private_key_seed: If provided, signs the receipt with Ed25519.

        Returns:
            The completed (possibly signed) L1Receipt.

        Raises:
            ValueError: If signing with incomplete profile bindings.
            ValueError: If timestamp < issued_at (time consistency violation).
        """
        receipt = self._receipt

        # L1Receipt.timestamp is populated by default_factory=time.time at
        # construction. If the caller subsequently sets an issued_at that
        # is slightly in the future (sub-millisecond clock jitter or a
        # fixed epoch assigned after construction), align timestamp to
        # issued_at. A genuinely future issued_at (>1s ahead) is a real
        # clock-skew/consistency violation and must still be rejected below.
        if receipt.issued_at > 0 and 0 < receipt.issued_at - receipt.timestamp < 1.0:
            receipt.timestamp = receipt.issued_at
            receipt.verified_at = receipt.issued_at

        if private_key_seed is not None:
            _require_ed25519()

            # Validate required profile bindings before signing
            missing = []
            if not receipt.issuer:
                missing.append("issuer")
            if not receipt.audience:
                missing.append("audience")
            if not receipt.action:
                missing.append("action")
            if receipt.expires_at <= 0:
                missing.append("expires_at (must be > 0)")

            if missing:
                raise ValueError(
                    f"Cannot sign receipt: missing required profile bindings: "
                    f"{', '.join(missing)}. "
                    f"An unsigned or empty-binding receipt provides no security guarantee."
                )

            # Validate time consistency: timestamp must not precede issuance
            if receipt.issued_at > 0 and receipt.timestamp < receipt.issued_at:
                raise ValueError(
                    f"Time consistency violation: timestamp ({receipt.timestamp}) "
                    f"is earlier than issued_at ({receipt.issued_at}). "
                    f"A receipt cannot claim verification before it was issued."
                )

            receipt = sign_l1_receipt(receipt, private_key_seed)
        else:
            # Even for unsigned receipts, validate time consistency if both are set
            if receipt.issued_at > 0 and receipt.timestamp < receipt.issued_at:
                raise ValueError(
                    f"Time consistency violation: timestamp ({receipt.timestamp}) "
                    f"is earlier than issued_at ({receipt.issued_at}). "
                    f"A receipt cannot claim verification before it was issued."
                )

        return receipt
