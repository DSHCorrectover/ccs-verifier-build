"""
CCS Verifier v1.1.7 — Full Test Suite (9 unit + 3 integration = 12 tests)

Unit Tests (9):
  1. Sign and verify with new field names
  2. Tamper detection (modify any field → sig breaks)
  3. Wrong key rejection (fingerprint mismatch)
  4. Empty signature rejection
  5. Serialization round-trip (new field names in output)
  6. Canonical Base64 passes
  7. Non-canonical Base64 rejected
  8. Backward compat: old field names receipt can be deserialized
  9. Backward compat: old field names receipt sig verification behavior

Integration Tests (3):
  1. Full lifecycle: build → sign → verify → serialize → restore → re-verify
  2. Builder → sign → verify → tamper → detect
  3. Time boundary validation: timestamp < issued_at must reject

Run: python3 -m pytest tests/test_v117_full.py -v --rootdir=. --import-mode=importlib
"""

import base64
import json
import time
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ccs_verifier.ccs_verifier_l1 import (
    L1Receipt,
    L1ReceiptBuilder,
    generate_ed25519_key,
    get_public_key,
    public_key_fingerprint,
    sign_l1_receipt,
    verify_l1_receipt,
    compute_hash,
    RECEIPT_VERSION,
    SIGNING_ALGORITHM,
)
from ccs_verifier.protocol import Verdict


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def key_pair():
    """Generate a fresh Ed25519 key pair."""
    private_key = generate_ed25519_key()
    public_key = get_public_key(private_key)
    return private_key, public_key


def _build_receipt() -> L1Receipt:
    """Build a minimal unsigned receipt with new field names."""
    now = time.time()
    builder = L1ReceiptBuilder(trace_id="test-trace-v117", verdict=Verdict.ALLOW)
    builder.tool("shell")
    builder.rule_summary("test_rule")
    builder.rule_version("v1.1.7")
    builder.issuer("test-verifier")
    builder.audience("test-agent")
    builder.action("shell.execute")
    builder.time_bounds(issued_at=now, expiry=now + 300)
    builder._receipt.timestamp = now
    return builder.build()


# ===========================================================================
# UNIT TESTS (9)
# ===========================================================================

class TestUnitTests:
    """9 unit tests for v1.1.7 field rename + backward compat."""

    def test_01_sign_and_verify_new_fields(self, key_pair):
        """1. Sign and verify with new field names (issued_at, expires_at, max_clock_skew)."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        assert signed.signature != ""
        assert signed.signing_algorithm == SIGNING_ALGORITHM
        assert signed.issued_at > 0
        assert signed.expires_at > signed.issued_at
        assert signed.verify_signature(public_key) is True

    def test_02_tamper_detection(self, key_pair):
        """2. Tampering any field after signing must break signature."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)
        assert signed.verify_signature(public_key) is True

        signed.verdict = "deny"
        assert signed.verify_signature(public_key) is False

    def test_03_wrong_key_rejected(self, key_pair):
        """3. Verifying with a different key must fail (fingerprint mismatch)."""
        private_key, _ = key_pair
        _, other_public_key = make_key_pair()
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)
        assert signed.verify_signature(other_public_key) is False

    def test_04_empty_signature_rejected(self, key_pair):
        """4. A receipt with no signature must not verify."""
        _, public_key = key_pair
        receipt = _build_receipt()
        receipt.signature = ""
        assert receipt.verify_signature(public_key) is False

    def test_05_serialization_uses_new_names(self, key_pair):
        """5. to_dict() output must use new field names only."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        d = signed.to_dict()
        assert "issued_at" in d
        assert "expires_at" in d
        assert "max_clock_skew" in d
        assert "issuance_bound" not in d
        assert "expiry_bound" not in d
        assert "clock_skew_bound" not in d

        restored = L1Receipt.from_dict(d)
        assert restored.verify_signature(public_key) is True

    def test_06_canonical_base64_passes(self, key_pair):
        """6. Canonical Base64 signature must pass verification."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        sig_bytes = base64.b64decode(signed.signature)
        canonical = base64.b64encode(sig_bytes).decode("ascii")
        assert signed.signature == canonical
        assert signed.verify_signature(public_key) is True

    def test_07_non_canonical_base64_rejected(self, key_pair):
        """7. Non-canonical Base64 signature must be rejected."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        sig = signed.signature
        assert sig.endswith("==") and len(sig) == 88

        b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last_char = sig[85]
        ov = b64_alphabet.index(last_char)
        real_bits = ov & 0x30
        alt_pad = (ov & 0x0F) ^ 0x01
        alt_val = real_bits | alt_pad
        if alt_val == ov:
            alt_val = real_bits | ((ov & 0x03) + 1) % 16
        nc_sig = sig[:85] + b64_alphabet[alt_val] + "=="

        assert nc_sig != sig
        assert base64.b64decode(nc_sig) == base64.b64decode(sig)

        fields = {k: v for k, v in signed.to_dict().items() if k != "signature"}
        nc_receipt = L1Receipt(**fields, signature=nc_sig)
        assert nc_receipt.verify_signature(public_key) is False

    def test_08_backward_compat_old_fields_deserialize(self, key_pair):
        """8. Old field names (issuance_bound, expiry_bound, clock_skew_bound)
        can be deserialized and fields are correctly mapped."""
        now = time.time()
        old_dict = {
            "trace_id": "old-trace-001",
            "receipt_version": "1.1",
            "verdict": "deny",
            "timestamp": now,
            "tool": "shell",
            "tool_call_id": "", "params_hash": "", "args_digest": "",
            "rule_summary": "test", "rule_version": "v1.1.6",
            "request_hash": "", "response_hash": "",
            "runtime_context_hash": "", "config_hash": "",
            "verifier_source_class": "", "deployment_mode": "",
            "issuer": "test-verifier", "audience": "test-agent",
            "nonce": "old-nonce-123", "sequence": 0,
            "issuance_bound": now,
            "expiry_bound": now + 300,
            "clock_skew_bound": 5.0,
            "action": "shell.execute",
            "signing_algorithm": "Ed25519",
            "public_key_fingerprint": "0" * 16,
            "verified_at": now, "latency_us": 0.0,
        }
        restored = L1Receipt.from_dict(old_dict, strict=False)
        assert restored.issued_at == now
        assert restored.expires_at == now + 300
        assert restored.max_clock_skew == 5.0
        # Output uses new names only
        d = restored.to_dict()
        assert "issued_at" in d
        assert "expires_at" in d
        assert "max_clock_skew" in d
        assert "issuance_bound" not in d

    def test_09_backward_compat_sig_behavior(self, key_pair):
        """9. A receipt signed with v1.1.7 fields, when field values change,
        signature verification fails. Old→new field name remap is transparent."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)
        assert signed.verify_signature(public_key) is True

        # Remap to old names and back: should still verify (transparent remap)
        d = signed.to_dict()
        d["issuance_bound"] = d.pop("issued_at")
        d["expiry_bound"] = d.pop("expires_at")
        d["clock_skew_bound"] = d.pop("max_clock_skew")
        restored = L1Receipt.from_dict(d, strict=False)
        assert restored.verify_signature(public_key) is True

        # But changing a value breaks signature
        d2 = signed.to_dict()
        d2["expires_at"] = 0.0
        tampered = L1Receipt.from_dict(d2)
        assert tampered.verify_signature(public_key) is False


def make_key_pair():
    """Helper for test_03."""
    pk = generate_ed25519_key()
    pub = get_public_key(pk)
    return pk, pub


# ===========================================================================
# INTEGRATION TESTS (3)
# ===========================================================================

class TestIntegrationTests:
    """3 integration tests for v1.1.7."""

    def test_10_full_lifecycle(self, key_pair):
        """Integration 1: Full lifecycle with new field names."""
        private_key, public_key = key_pair
        now = time.time()

        builder = L1ReceiptBuilder(trace_id="integ-v117-001", verdict=Verdict.ALLOW)
        builder.tool("shell")
        builder.tool_call_id("call_integ_v117")
        builder.params_hash(compute_hash({"command": "ls -la"}))
        builder.args_digest({"command": "ls -la"})
        builder.rule_summary("ssrf_protection,rce_protection")
        builder.rule_version("v1.1.7")
        builder.request_hash({"agent_id": "agent-1", "tool": "shell", "params": {"command": "ls -la"}})
        builder.response_hash({"verdict": "allow", "latency_us": 1200})
        builder.runtime_context({"os": "linux", "python": "3.11"})
        builder.config_hash({"rules": ["ssrf", "rce"], "mode": "enforce"})
        builder.verifier_source_class("VerifierServer")
        builder.deployment_mode("in-process")
        builder.issuer("ccs-verifier:v1.1.7")
        builder.audience("agent-primary")
        builder.nonce("integ-nonce-v117")
        builder.sequence(42)
        builder.time_bounds(issued_at=now, expiry=now + 600)
        builder.action("shell.execute")
        builder.latency_us(1200)
        builder._receipt.timestamp = now
        receipt = builder.build()

        signed = sign_l1_receipt(receipt, private_key)
        assert signed.signature != ""
        assert signed.verify_signature(public_key) is True

        receipt_dict = signed.to_dict()
        assert "issued_at" in receipt_dict
        assert "expires_at" in receipt_dict
        assert "max_clock_skew" in receipt_dict
        json_str = json.dumps(receipt_dict, ensure_ascii=False)

        restored = L1Receipt.from_json(json_str)
        assert restored.issued_at == now
        assert restored.expires_at == now + 600
        assert restored.verify_signature(public_key) is True

    def test_11_builder_sign_verify_tamper_detect(self, key_pair):
        """Integration 2: Builder → sign → verify → tamper → detect."""
        private_key, public_key = key_pair
        now = time.time()

        tamper_fields = {
            "trace_id": "tampered-trace",
            "verdict": "allow",
            "tool": "shell_exec",
            "rule_version": "v9.9.9",
            "action": "unknown",
            "issuer": "evil-issuer",
            "audience": "evil-audience",
            "issued_at": now + 9999,
            "expires_at": now + 1,
            "max_clock_skew": 999.0,
        }

        for field_name, tamper_value in tamper_fields.items():
            b = L1ReceiptBuilder(trace_id="integ-v117-002", verdict=Verdict.DENY)
            b.tool("http_fetch")
            b.rule_summary("ssrf_protection")
            b.rule_version("v1.1.7")
            b.issuer("ccs-verifier:v1.1.7")
            b.audience("agent-secondary")
            b.action("http.fetch")
            b.time_bounds(issued_at=now, expiry=now + 300)
            b._receipt.timestamp = now
            receipt = b.build()
            signed = sign_l1_receipt(receipt, private_key)
            assert signed.verify_signature(public_key) is True

            setattr(signed, field_name, tamper_value)
            assert signed.verify_signature(public_key) is False, \
                f"Tampering {field_name} should break verification"

    def test_12_time_boundary_validation(self, key_pair):
        """Integration 3: timestamp < issued_at must be rejected."""
        private_key, _ = key_pair
        now = time.time()

        builder = L1ReceiptBuilder(trace_id="integ-v117-003", verdict=Verdict.ALLOW)
        builder.tool("shell")
        builder.issuer("test-verifier")
        builder.audience("test-agent")
        builder.action("shell.execute")
        builder.time_bounds(issued_at=now + 100, expiry=now + 300)
        builder._receipt.timestamp = now

        with pytest.raises(ValueError, match="Time consistency violation"):
            builder.build(private_key)

        builder2 = L1ReceiptBuilder(trace_id="integ-v117-004", verdict=Verdict.ALLOW)
        builder2.tool("shell")
        builder2.issuer("test-verifier")
        builder2.audience("test-agent")
        builder2.action("shell.execute")
        builder2.time_bounds(issued_at=now + 100, expiry=now + 300)
        builder2._receipt.timestamp = now

        with pytest.raises(ValueError, match="Time consistency violation"):
            builder2.build()
