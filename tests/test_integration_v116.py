"""
CCS Verifier v1.1.6 — Integration Tests (3 end-to-end tests)

End-to-end verification flow tests:
  1. Full lifecycle: build → sign → verify → serialize → restore → re-verify
  2. Builder → Server verification pipeline
  3. Non-canonical Base64 rejection in a full pipeline (end-to-end)

Run: python3 -m pytest tests/test_integration_v116.py -v
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


@pytest.fixture
def key_pair():
    """Generate a fresh Ed25519 key pair."""
    private_key = generate_ed25519_key()
    public_key = get_public_key(private_key)
    return private_key, public_key


# ---------------------------------------------------------------------------
# Integration Test 1: Full lifecycle
# ---------------------------------------------------------------------------

class TestFullLifecycle:
    """
    End-to-end: build receipt with all fields → sign → verify →
    serialize to JSON → restore from JSON → re-verify.
    """

    def test_full_lifecycle_sign_verify_serialize_restore(self, key_pair):
        """
        Complete lifecycle: builder creates receipt, sign it, verify,
        serialize to JSON, restore from JSON, verify again.
        """
        private_key, public_key = key_pair

        # Step 1: Build receipt with full context
        builder = L1ReceiptBuilder(trace_id="integ-trace-001", verdict=Verdict.ALLOW)
        builder.tool("shell")
        builder.tool_call_id("call_integ_001")
        builder.params_hash(compute_hash({"command": "ls -la"}))
        builder.args_digest({"command": "ls -la"})
        builder.rule_summary("ssrf_protection,rce_protection")
        builder.rule_version("v1.1.6")
        builder.request_hash({"agent_id": "agent-1", "tool": "shell", "params": {"command": "ls -la"}})
        builder.response_hash({"verdict": "allow", "latency_us": 1200})
        builder.runtime_context({"os": "linux", "python": "3.11"})
        builder.config_hash({"rules": ["ssrf", "rce"], "mode": "enforce"})
        builder.verifier_source_class("VerifierServer")
        builder.deployment_mode("in-process")
        builder.issuer("ccs-verifier:v1.1.6")
        builder.audience("agent-primary")
        builder.nonce("integ-nonce-abc123")
        builder.sequence(42)
        builder.time_bounds(expiry=time.time() + 600)
        builder.action("shell.execute")
        builder.latency_us(1200)
        receipt = builder.build()

        # Step 2: Sign
        signed = sign_l1_receipt(receipt, private_key)
        assert signed.signature != ""
        assert signed.signing_algorithm == "Ed25519"
        assert signed.public_key_fingerprint == public_key_fingerprint(public_key)

        # Step 3: Verify
        assert signed.verify_signature(public_key) is True

        # Step 4: Serialize to JSON
        receipt_dict = signed.to_dict()
        json_str = json.dumps(receipt_dict, ensure_ascii=False)

        # Step 5: Restore from JSON
        restored = L1Receipt.from_json(json_str)
        assert restored.trace_id == "integ-trace-001"
        assert restored.rule_version == "v1.1.6"
        assert restored.signature == signed.signature

        # Step 6: Re-verify restored receipt
        assert restored.verify_signature(public_key) is True


# ---------------------------------------------------------------------------
# Integration Test 2: Builder + verify_l1_receipt function
# ---------------------------------------------------------------------------

def _build_receipt_for_tamper() -> L1Receipt:
    """Build a receipt for tamper testing with deterministic fields."""
    builder = L1ReceiptBuilder(trace_id="integ-trace-002", verdict=Verdict.DENY)
    builder.tool("http_fetch")
    builder.rule_summary("ssrf_protection")
    builder.rule_version("v1.1.6")
    builder.issuer("ccs-verifier:v1.1.6")
    builder.audience("agent-secondary")
    builder.action("http.fetch")
    builder.time_bounds(expiry=time.time() + 300)
    return builder.build()


class TestBuilderToVerification:
    """
    End-to-end: use L1ReceiptBuilder → sign_l1_receipt → verify_l1_receipt
    (the module-level function, not the method).
    Also test: tamper detection on multiple fields.
    """

    def test_builder_sign_verify_tamper_detect(self, key_pair):
        """
        Build → sign → verify via module-level function.
        Then tamper each security-critical field and confirm detection.
        """
        private_key, public_key = key_pair

        # Build and sign
        builder = L1ReceiptBuilder(trace_id="integ-trace-002", verdict=Verdict.DENY)
        builder.tool("http_fetch")
        builder.rule_summary("ssrf_protection")
        builder.rule_version("v1.1.6")
        builder.issuer("ccs-verifier:v1.1.6")
        builder.audience("agent-secondary")
        builder.action("http.fetch")
        builder.time_bounds(expiry=time.time() + 300)
        receipt = builder.build()

        signed = sign_l1_receipt(receipt, private_key)

        # Verify via module-level function
        assert verify_l1_receipt(signed, public_key) is True

        # Tamper detection: each field modification must break verification
        tamper_fields = {
            "trace_id": "tampered-trace",
            "verdict": "allow",  # Changed from "deny"
            "tool": "shell_exec",
            "rule_version": "v9.9.9",
            "action": "unknown",
            "issuer": "evil-issuer",
            "audience": "evil-audience",
        }

        for field_name, tamper_value in tamper_fields.items():
            # Create a fresh signed receipt for each tamper test
            fresh_receipt = _build_receipt_for_tamper()
            fresh_signed = sign_l1_receipt(fresh_receipt, private_key)
            assert fresh_signed.verify_signature(public_key) is True

            setattr(fresh_signed, field_name, tamper_value)
            assert fresh_signed.verify_signature(public_key) is False, \
                f"Tampering {field_name} should break verification"


# ---------------------------------------------------------------------------
# Integration Test 3: Non-canonical Base64 rejection end-to-end
# ---------------------------------------------------------------------------

class TestNonCanonicalEndToEnd:
    """
    End-to-end: construct a valid receipt, forge a non-canonical Base64
    variant of the signature, and confirm the full pipeline rejects it.
    This simulates an attacker who intercepts a valid receipt and modifies
    the unused pad bits in the Base64 encoding.
    """

    def test_attacker_forged_non_canonical_rejected(self, key_pair):
        """
        Simulate an attacker modifying unused pad bits in the Base64
        signature. The full verification pipeline must reject this.
        """
        private_key, public_key = key_pair

        # Step 1: Victim creates and signs a receipt
        builder = L1ReceiptBuilder(trace_id="integ-trace-003", verdict=Verdict.ALLOW)
        builder.tool("file_read")
        builder.rule_summary("rce_protection")
        builder.rule_version("v1.1.6")
        builder.issuer("ccs-verifier:v1.1.6")
        builder.audience("agent-victim")
        builder.action("file.read")
        builder.time_bounds(expiry=time.time() + 300)
        receipt = builder.build()
        signed = sign_l1_receipt(receipt, private_key)

        # Step 2: Victim's receipt verifies correctly
        assert signed.verify_signature(public_key) is True

        # Step 3: Attacker intercepts and modifies unused pad bits
        sig = signed.signature
        assert len(sig) == 88 and sig.endswith("==")

        b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last_char = sig[85]
        last_val = b64_alphabet.index(last_char)
        real_bits = last_val & 0x30
        # Flip the lowest unused pad bit
        alt_val = real_bits | ((last_val & 0x0F) ^ 0x01)
        if alt_val == last_val:
            alt_val = real_bits | ((last_val & 0x03) + 1) % 16
        alt_char = b64_alphabet[alt_val]
        forged_sig = sig[:85] + alt_char + "=="

        # Verify the forged string is different but decodes to same bytes
        assert forged_sig != sig
        assert base64.b64decode(forged_sig) == base64.b64decode(sig)

        # Step 4: Attacker constructs a receipt with the forged signature
        forged_fields = {k: v for k, v in signed.to_dict().items() if k != "signature"}
        forged_receipt = L1Receipt(**forged_fields, signature=forged_sig)

        # Step 5: The full pipeline MUST reject the forged receipt
        assert forged_receipt.verify_signature(public_key) is False, \
            "SECURITY: Non-canonical Base64 signature must be rejected!"

        # Step 6: Also test via module-level verify function
        assert verify_l1_receipt(forged_receipt, public_key) is False, \
            "SECURITY: Module-level verify must also reject non-canonical sig!"
