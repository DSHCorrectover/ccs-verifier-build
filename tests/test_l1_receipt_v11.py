"""
CCS Verifier L1 Receipt — Test Suite

Covers the two architectural improvements from autogen#7265:
  1. rule_version — "Pin the rule, not just the action"
  2. tool_call_id + args_digest — Approval-execution cryptographic binding

Also covers:
  - VERIFIED vs ACCEPTED two-stage trust model (Iman audit, 2026-08-15)
  - Reference-signed canonical vector reproducibility
  - Serialization round-trip
  - Tamper detection on all new fields
  - Backward compatibility

Run: python3 -m pytest tests/test_l1_receipt_v11.py -v
"""

import hashlib
import json
import time
import sys
import os
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ccs_verifier.ccs_verifier_l1 import (
    L1Receipt,
    L1ReceiptBuilder,
    Verdict,
    sign_l1_receipt,
    verify_l1_receipt,
    generate_ed25519_key,
    get_public_key,
    public_key_fingerprint,
    canonical_json,
    compute_hash,
    compute_args_digest,
)
from ccs_verifier.trust import (
    TrustAnchor,
    evaluate_trust,
    load_reference_anchor,
    load_reference_private_seed,
)


VECTOR_DIR = Path(__file__).resolve().parent / "conformance-vectors"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _key_pair():
    seed = generate_ed25519_key()
    pub = get_public_key(seed)
    return seed, pub


def _build_unsigned(
    trace_id="trc_test_001",
    verdict=Verdict.ALLOW,
    tool="shell",
    params=None,
    rule_summary="test",
    rule_version="",
    tool_call_id=None,
    args_digest=None,
    issuer="ccs-verifier/test",
    audience="agent:test",
    action="shell.execute",
):
    if params is None:
        params = {"command": "echo hello"}
    b = L1ReceiptBuilder(trace_id=trace_id, verdict=verdict)
    b.tool(tool)
    if tool_call_id is not None:
        b.tool_call_id(tool_call_id)
    b.params_hash(compute_hash(params)[:16])
    if args_digest is not None:
        # explicit override
        b._receipt.args_digest = args_digest
    else:
        b.args_digest(params)
    b.rule_summary(rule_summary)
    if rule_version:
        b.rule_version(rule_version)
    b.request_hash({"k": "v"})
    b.response_hash({"ok": True})
    b.runtime_context({"os": "linux"})
    b.config_hash({"mode": "enforce"})
    b.verifier_source_class("VerifierServer")
    b.deployment_mode("in-process")
    b.issuer(issuer)
    b.audience(audience)
    b.nonce(f"nonce-{trace_id}")
    b.sequence(1)
    now = time.time()
    b.time_bounds(issued_at=now, expiry=now + 300)
    b.action(action)
    b.latency_us(50)
    return b.build()


def _build_signed(**kw):
    seed = kw.pop("seed", None)
    if seed is None:
        seed, _ = _key_pair()
    receipt = _build_unsigned(**kw)
    return sign_l1_receipt(receipt, seed)


# ---------------------------------------------------------------------------
# 1. rule_version field
# ---------------------------------------------------------------------------

class TestRuleVersion:
    def test_default_empty(self):
        r = _build_unsigned()
        assert r.rule_version == ""

    def test_written(self):
        r = _build_unsigned(rule_version="v2.1.0")
        assert r.rule_version == "v2.1.0"

    def test_affects_signature(self):
        seed, _ = _key_pair()
        a = _build_signed(rule_version="v1.0.0", seed=seed)
        b = _build_signed(rule_version="v2.0.0", seed=seed)
        assert a.signature != b.signature

    def test_in_signing_payload(self):
        r = _build_signed(rule_version="v3.0.0")
        d = r.to_dict()
        assert d["rule_version"] == "v3.0.0"
        assert verify_l1_receipt(r) is True

    def test_tamper_breaks_signature(self):
        r = _build_signed(rule_version="v1.0.0")
        assert r.verify_signature() is True
        r.rule_version = "v9.9.9"
        assert r.verify_signature() is False


# ---------------------------------------------------------------------------
# 2. tool_call_id field
# ---------------------------------------------------------------------------

class TestToolCallId:
    def test_explicit_value(self):
        r = _build_unsigned(tool_call_id="call_abc123")
        assert r.tool_call_id == "call_abc123"

    def test_affects_signature(self):
        seed, _ = _key_pair()
        a = _build_signed(tool_call_id="call_a", seed=seed, trace_id="t1")
        b = _build_signed(tool_call_id="call_b", seed=seed, trace_id="t1")
        assert a.signature != b.signature

    def test_tamper_breaks_signature(self):
        r = _build_signed(tool_call_id="call_xyz")
        assert r.verify_signature() is True
        r.tool_call_id = "tampered"
        assert r.verify_signature() is False


# ---------------------------------------------------------------------------
# 3. args_digest field
# ---------------------------------------------------------------------------

class TestArgsDigest:
    def test_auto_computed(self):
        params = {"command": "echo test", "timeout": 30}
        r = _build_unsigned(params=params)
        assert r.args_digest != ""
        expected = hashlib.sha256(canonical_json(params)).hexdigest()
        assert r.args_digest == expected

    def test_different_params_different_digest(self):
        a = _build_unsigned(params={"command": "echo a"})
        b = _build_unsigned(params={"command": "echo b"})
        assert a.args_digest != b.args_digest

    def test_tamper_breaks_signature(self):
        r = _build_signed(params={"command": "echo safe"})
        assert r.verify_signature() is True
        r.args_digest = "0" * 64
        assert r.verify_signature() is False

    def test_64_hex_chars(self):
        r = _build_unsigned(params={"k": "v"})
        assert len(r.args_digest) == 64
        int(r.args_digest, 16)


# ---------------------------------------------------------------------------
# 4. Serialization round-trip
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_dict_roundtrip_preserves_fields(self):
        r = _build_signed(
            rule_version="v2.0.0",
            tool_call_id="call_rt",
            params={"command": "echo hi"},
        )
        d = r.to_dict()
        restored = L1Receipt.from_dict(d, strict=True)
        assert restored.rule_version == "v2.0.0"
        assert restored.tool_call_id == "call_rt"
        assert restored.verify_signature() is True

    def test_json_roundtrip(self):
        r = _build_signed(rule_version="v1.0.0", tool_call_id="call_j")
        s = json.dumps(r.to_dict(), sort_keys=True)
        restored = L1Receipt.from_json(s)
        assert restored.rule_version == "v1.0.0"
        assert restored.verify_signature() is True

    def test_unknown_fields_rejected_in_strict_mode(self):
        r = _build_signed()
        d = r.to_dict()
        d["unexpected_field"] = "x"
        with pytest.raises(ValueError):
            L1Receipt.from_dict(d, strict=True)


# ---------------------------------------------------------------------------
# 5. Backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_receipt_valid_without_new_fields(self):
        b = L1ReceiptBuilder(trace_id="trc_bc", verdict=Verdict.ALLOW)
        b.tool("shell").params_hash("abc")
        b.issuer("ccs-verifier/test").audience("agent").action("shell.exec")
        now = time.time()
        b.time_bounds(issued_at=now, expiry=now + 60)
        seed, _ = _key_pair()
        r = b.build(seed)
        assert r.verify_signature() is True
        assert r.rule_version == ""
        assert r.tool_call_id == ""

    def test_unsigned_receipt_has_empty_signature(self):
        r = _build_unsigned()
        assert r.signature == ""
        assert r.public_key == ""


# ---------------------------------------------------------------------------
# 6. VERIFIED vs ACCEPTED two-stage trust (Iman audit)
# ---------------------------------------------------------------------------

class TestTrustModel:
    def test_reference_anchor_loads(self):
        anchor = load_reference_anchor()
        assert anchor.issuer == "ccs-verifier/reference"
        assert len(anchor.public_key_bytes) == 32
        assert len(anchor.public_key_fingerprint_sha256_16) == 16

    def test_self_signed_spoofed_issuer_verified_but_not_accepted(self):
        """Attacker key with spoofed issuer string: VERIFIED, not ACCEPTED."""
        attacker_seed, _ = _key_pair()
        r = _build_unsigned(
            issuer="ccs-verifier/reference",  # spoofed
            audience="emilia-gate",
            rule_summary="attacker_spoof",
        )
        signed = sign_l1_receipt(r, attacker_seed)
        assert signed.verify_signature() is True
        decision = evaluate_trust(signed, [load_reference_anchor()])
        assert decision.verified is True
        assert decision.accepted is False
        assert decision.reason in ("fingerprint_mismatch", "public_key_mismatch")

    def test_correctly_signed_receipt_is_verified_and_accepted(self):
        seed, pub = _key_pair()
        anchor = TrustAnchor(
            issuer="ccs-verifier/test",
            public_key_raw_b64=__import__("base64").b64encode(pub).decode(),
            public_key_fingerprint_sha256_16=hashlib.sha256(pub).hexdigest()[:16],
        )
        r = _build_unsigned(
            issuer="ccs-verifier/test",
            audience="emilia-gate",
            rule_summary="trusted_path",
        )
        signed = sign_l1_receipt(r, seed)
        decision = evaluate_trust(signed, [anchor])
        assert decision.verified is True
        assert decision.accepted is True
        assert decision.reason == "ok"

    def test_no_anchor_for_issuer_is_not_accepted(self):
        seed, _ = _key_pair()
        r = _build_unsigned(issuer="unknown-issuer", audience="x", rule_summary="u")
        signed = sign_l1_receipt(r, seed)
        decision = evaluate_trust(signed, [load_reference_anchor()])
        assert decision.verified is True
        assert decision.accepted is False
        assert decision.reason.startswith("no_pinned_anchor_for_issuer:")

    def test_tampered_receipt_fails_verification(self):
        seed, pub = _key_pair()
        anchor = TrustAnchor(
            issuer="ccs-verifier/test",
            public_key_raw_b64=__import__("base64").b64encode(pub).decode(),
            public_key_fingerprint_sha256_16=hashlib.sha256(pub).hexdigest()[:16],
        )
        r = _build_unsigned(issuer="ccs-verifier/test", audience="x", rule_summary="t")
        signed = sign_l1_receipt(r, seed)
        signed.verdict = "deny"
        decision = evaluate_trust(signed, [anchor])
        assert decision.verified is False
        assert decision.accepted is False
        assert decision.reason == "signature_failed"


# ---------------------------------------------------------------------------
# 7. Reference-signed canonical vector reproducibility
# ---------------------------------------------------------------------------

class TestReferenceVector:
    """The reference-signed vector shipped in tests/conformance-vectors/
    MUST be reproducible from the public deterministic seed. This lets an
    auditor verify the vector without trusting the package author's word.
    """

    def _build_reference_signed(self):
        seed = load_reference_private_seed()
        # Fixed fields so the receipt is byte-deterministic.
        b = L1ReceiptBuilder(trace_id="ref-vector-001", verdict=Verdict.ALLOW)
        b.tool("shell")
        b.params_hash("refvec001")
        b.args_digest({"command": "echo reference"})
        b.rule_summary("reference_vector")
        b.rule_version("1.1.20")
        b.request_hash({"ref": 1})
        b.response_hash({"ok": True})
        b.runtime_context({"dist": "reference"})
        b.config_hash({"mode": "reference"})
        b.verifier_source_class("VerifierServer")
        b.deployment_mode("in-process")
        b.issuer("ccs-verifier/reference")
        b.audience("public")
        b.nonce("reference-nonce-001")
        b.sequence(0)
        # Fixed epoch: 2030-01-01T00:00:00Z (far-future to avoid expiry)
        ts = 1893456000.0
        b.action("shell.execute")
        b.latency_us(0)
        r = b.build()
        r.issued_at = ts
        r.expires_at = ts + 300
        r.max_clock_skew = 0.0
        r.timestamp = ts
        r.verified_at = ts
        r = sign_l1_receipt(r, seed)
        return r

    def test_reference_seed_matches_reference_anchor(self):
        seed = load_reference_private_seed()
        pub = get_public_key(seed)
        anchor = load_reference_anchor()
        assert pub == anchor.public_key_bytes
        assert public_key_fingerprint(pub) == anchor.public_key_fingerprint_sha256_16

    def test_reference_receipt_is_verified_and_accepted(self):
        r = self._build_reference_signed()
        assert r.verify_signature() is True
        decision = evaluate_trust(r, [load_reference_anchor()])
        assert decision.verified is True
        assert decision.accepted is True
        assert decision.reason == "ok"

    def test_reference_vector_matches_shipped_file(self):
        shipped_path = VECTOR_DIR / "reference-signed-001.json"
        assert shipped_path.exists(), (
            "reference-signed-001.json is missing from conformance-vectors/"
        )
        with open(shipped_path) as f:
            shipped = json.load(f)
        # The shipped file must contain the same receipt we build from the seed.
        rebuilt = self._build_reference_signed().to_dict()
        assert rebuilt == shipped["receipt"], (
            "Reference vector is not reproducible from the public seed."
        )
        # Cross-check the declared fingerprint.
        anchor = load_reference_anchor()
        assert shipped["public_key_fingerprint_sha256_16"] == \
            anchor.public_key_fingerprint_sha256_16

    def test_reference_vector_is_deterministic(self):
        """Building the same receipt twice must produce identical bytes."""
        r1 = self._build_reference_signed().to_dict()
        r2 = self._build_reference_signed().to_dict()
        assert r1 == r2


# ---------------------------------------------------------------------------
# 8. Field count contract
# ---------------------------------------------------------------------------

class TestFieldContract:
    def test_l1_receipt_has_30_fields(self):
        assert len(L1Receipt.__dataclass_fields__) == 30
