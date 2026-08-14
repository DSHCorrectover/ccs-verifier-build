"""
Tests for the two-stage VERIFIED vs ACCEPTED trust model.

These tests encode the audit finding from Iman Schrock (2026-08-15):
a self-signed receipt with an unknown key and spoofed issuer string
must be VERIFIED (signature internally consistent) but NOT ACCEPTED
(issuer identity not pinned).
"""
import base64
import hashlib
import os
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccs_verifier.ccs_verifier_l1 import (
    L1Receipt,
    L1ReceiptBuilder,
    Verdict,
    sign_l1_receipt,
)
from ccs_verifier.trust import (
    TrustAnchor,
    evaluate_trust,
    load_reference_anchor,
)


def _key_pair():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


def _build_receipt(issuer: str, audience: str, rule_summary: str) -> L1Receipt:
    now = time.time()
    b = L1ReceiptBuilder(trace_id=f"trust-{rule_summary}", verdict=Verdict.ALLOW)
    b.tool("bash")
    b.tool_call_id(f"call-trust-{rule_summary}")
    b.params_hash("abc")
    b.args_digest({"command": "echo hi"})
    b.rule_summary(rule_summary)
    b.rule_version("1.1.12")
    b.request_hash({"k": "v"})
    b.response_hash({"ok": True})
    b.runtime_context({"os": "linux"})
    b.config_hash({"mode": "enforce"})
    b.verifier_source_class("VerifierServer")
    b.deployment_mode("in-process")
    b.issuer(issuer)
    b.audience(audience)
    b.nonce(f"nonce-{rule_summary}")
    b.sequence(1)
    b.time_bounds(issued_at=now, expiry=now + 60)
    b.action("shell.execute")
    b.latency_us(50)
    receipt = b.build()
    return receipt


def _anchor_for(issuer: str, pub: bytes) -> TrustAnchor:
    return TrustAnchor(
        issuer=issuer,
        public_key_raw_b64=base64.b64encode(pub).decode("ascii"),
        public_key_fingerprint_sha256_16=hashlib.sha256(pub).hexdigest()[:16],
    )


def test_reference_anchor_loads():
    anchor = load_reference_anchor()
    assert anchor.issuer == "ccs-verifier/reference"
    assert len(anchor.public_key_bytes) == 32
    assert len(anchor.public_key_fingerprint_sha256_16) == 16


def test_self_signed_spoofed_issuer_verified_but_not_accepted():
    """Attacker-generated key with spoofed issuer must NOT be accepted."""
    attacker_seed, attacker_pub = _key_pair()
    receipt = _build_receipt(
        issuer="ccs-verifier/reference",  # spoofed
        audience="emilia-gate",
        rule_summary="attacker_spoof",
    )
    signed = sign_l1_receipt(receipt, attacker_seed)
    # Stage 1: signature still verifies against embedded attacker key.
    assert signed.verify_signature() is True
    # Stage 2: not accepted against pinned reference anchor.
    decision = evaluate_trust(signed, [load_reference_anchor()])
    assert decision.verified is True
    assert decision.accepted is False
    assert decision.reason in ("fingerprint_mismatch", "public_key_mismatch")


def test_correctly_signed_receipt_is_verified_and_accepted():
    seed, pub = _key_pair()
    anchor = _anchor_for("ccs-verifier/test", pub)
    receipt = _build_receipt("ccs-verifier/test", "emilia-gate", "trusted_path")
    signed = sign_l1_receipt(receipt, seed)
    decision = evaluate_trust(signed, [anchor])
    assert decision.verified is True
    assert decision.accepted is True
    assert decision.reason == "ok"


def test_no_anchor_for_issuer_is_not_accepted():
    seed, _ = _key_pair()
    receipt = _build_receipt("some-other-issuer", "emilia-gate", "unknown")
    signed = sign_l1_receipt(receipt, seed)
    decision = evaluate_trust(signed, [load_reference_anchor()])
    assert decision.verified is True
    assert decision.accepted is False
    assert decision.reason.startswith("no_pinned_anchor_for_issuer:")


def test_tampered_receipt_fails_verification():
    seed, pub = _key_pair()
    anchor = _anchor_for("ccs-verifier/test", pub)
    receipt = _build_receipt("ccs-verifier/test", "emilia-gate", "tamper")
    signed = sign_l1_receipt(receipt, seed)
    signed.verdict = "deny"  # tamper
    decision = evaluate_trust(signed, [anchor])
    assert decision.verified is False
    assert decision.accepted is False
    assert decision.reason == "signature_failed"
