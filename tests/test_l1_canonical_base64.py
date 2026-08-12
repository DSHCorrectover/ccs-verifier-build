"""
CCS Verifier v1.1.6 — L1 Receipt Unit Tests + Canonical Base64 Regression

Regression test for the last blocker from Iman's re-audit:
  L1Receipt.verify_signature() must reject non-canonical Base64 signatures
  (where unused pad bits differ but decoded bytes are identical).

Test breakdown:
  - 6 unit tests: core L1Receipt sign/verify lifecycle
  - 3 regression tests: canonical Base64 enforcement (the blocker fix)

Run: python3 -m pytest tests/test_l1_canonical_base64.py -v
"""

import base64
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
    """Build a minimal unsigned receipt."""
    builder = L1ReceiptBuilder(trace_id="test-trace-001", verdict=Verdict.ALLOW)
    builder.tool("shell")
    builder.rule_summary("test_rule")
    builder.rule_version("v1.0.0")
    builder.issuer("test-verifier")
    builder.audience("test-agent")
    builder.action("shell.execute")
    builder.time_bounds(expiry=time.time() + 300)
    return builder.build()


# ---------------------------------------------------------------------------
# Unit Tests (6)
# ---------------------------------------------------------------------------

class TestL1ReceiptUnit:
    """Core L1Receipt unit tests: sign, verify, serialize, tamper-detect."""

    def test_sign_and_verify(self, key_pair):
        """A properly signed receipt should verify successfully."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        assert signed.signature != ""
        assert signed.signing_algorithm == SIGNING_ALGORITHM
        assert signed.public_key_fingerprint != ""
        assert signed.verify_signature(public_key) is True

    def test_tampered_verdict_fails_verification(self, key_pair):
        """Modifying verdict after signing must break signature."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)
        assert signed.verify_signature(public_key) is True

        signed.verdict = "deny"
        assert signed.verify_signature(public_key) is False

    def test_tampered_trace_id_fails_verification(self, key_pair):
        """Modifying trace_id after signing must break signature."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)
        assert signed.verify_signature(public_key) is True

        signed.trace_id = "tampered-trace-id"
        assert signed.verify_signature(public_key) is False

    def test_wrong_public_key_fails(self, key_pair):
        """Verifying with a different public key must fail (fingerprint mismatch)."""
        private_key, _ = key_pair
        other_private_key = generate_ed25519_key()
        other_public_key = get_public_key(other_private_key)

        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        assert signed.verify_signature(other_public_key) is False

    def test_empty_signature_returns_false(self, key_pair):
        """A receipt with no signature should not verify."""
        _, public_key = key_pair
        receipt = _build_receipt()
        receipt.signature = ""
        assert receipt.verify_signature(public_key) is False

    def test_from_dict_roundtrip(self, key_pair):
        """Receipt serialized to dict and restored should still verify."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        d = signed.to_dict()
        restored = L1Receipt.from_dict(d)
        assert restored.verify_signature(public_key) is True


# ---------------------------------------------------------------------------
# Regression Tests (3) — Canonical Base64 Enforcement
# ---------------------------------------------------------------------------

class TestCanonicalBase64Regression:
    """
    Regression for Iman's audit blocker: non-canonical Base64 signatures
    must be rejected.

    For Ed25519 (64-byte signatures), Base64 produces exactly 88 characters
    (64 bytes → 85.33 chars → 86 chars + "==" padding). The last encoded
    character before "==" encodes 2 bits of data + 4 unused pad bits.

    Characters with the same low 2 bits but different pad bits decode to
    the same 64 bytes:
      'Q' = 16 = 010000 (canonical: pad bits = 00000)
      'R' = 17 = 010001 (non-canonical: pad bits = 00001)
      'I' = 8  = 001000 (non-canonical: pad bits = 00000... wait, same pad)
      'S' = 18 = 010010 (non-canonical: pad bits = 00010)
    """

    def _make_non_canonical_receipt(self, signed_receipt: L1Receipt) -> L1Receipt:
        """
        Create a receipt with a non-canonical Base64 signature that decodes
        to the exact same 64 Ed25519 signature bytes.

        Modifies the unused pad bits in the last Base64 character before '=='.
        """
        sig = signed_receipt.signature
        assert sig.endswith("=="), f"Expected '==' padding, got: {sig[-4:]}"
        assert len(sig) == 88, f"Expected 88-char Base64 for 64-byte sig, got {len(sig)}"

        # The 86th character (index 85) is the last char before padding.
        # It encodes 2 real bits + 4 unused pad bits.
        # Standard Base64 alphabet: A=0..Z=25, a=26..z=51, 0=52..9=61, +=62, /=63
        b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last_char = sig[85]
        original_value = b64_chars.index(last_char)

        # The 2 real bits are in positions 4-5 (bits 4 and 5).
        # We change the 4 pad bits (bits 0-3) to create a non-canonical encoding.
        real_bits = original_value & 0x30  # bits 4-5
        new_pad_bits = (original_value & 0x0F) ^ 0x01  # flip lowest pad bit
        new_value = real_bits | (new_pad_bits & 0x0F)

        # Ensure we actually changed the character
        if new_value == original_value:
            new_value = real_bits | ((new_pad_bits + 1) & 0x0F)

        new_last_char = b64_chars[new_value]
        non_canonical_sig = sig[:85] + new_last_char + "=="

        # Verify it's actually different but decodes to the same bytes
        assert non_canonical_sig != sig, "Non-canonical sig should differ from original"
        assert base64.b64decode(non_canonical_sig) == base64.b64decode(sig), \
            "Both must decode to the same bytes"

        # Build a receipt with the non-canonical signature
        fields = {k: v for k, v in signed_receipt.to_dict().items() if k != "signature"}
        return L1Receipt(**fields, signature=non_canonical_sig)

    def test_canonical_signature_passes(self, key_pair):
        """The canonical (standard) Base64 signature must pass verification."""
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        # Verify the signature IS canonical
        sig_bytes = base64.b64decode(signed.signature)
        canonical = base64.b64encode(sig_bytes).decode("ascii")
        assert signed.signature == canonical, "sign_l1_receipt must produce canonical Base64"

        assert signed.verify_signature(public_key) is True

    def test_non_canonical_signature_rejected(self, key_pair):
        """
        REGRESSION: A non-canonical Base64 string that decodes to the same
        64-byte Ed25519 signature MUST be rejected (return False).

        This is the fix for Iman's last blocker from the v1.1.5 re-audit.
        """
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        # Confirm the canonical version passes
        assert signed.verify_signature(public_key) is True

        # Create non-canonical version
        nc_receipt = self._make_non_canonical_receipt(signed)

        # THE FIX: non-canonical must be rejected
        assert nc_receipt.verify_signature(public_key) is False, \
            "Non-canonical Base64 signature must be rejected!"

    def test_two_different_b64_strings_same_bytes_only_canonical_passes(self, key_pair):
        """
        REGRESSION (explicit): Two different Base64 strings decode to the
        same 64-byte Ed25519 signature. Only the canonical one passes.

        This directly tests the requirement from the bug report.
        """
        private_key, public_key = key_pair
        receipt = _build_receipt()
        signed = sign_l1_receipt(receipt, private_key)

        sig_bytes = base64.b64decode(signed.signature)
        assert len(sig_bytes) == 64, "Ed25519 signature must be 64 bytes"

        # Canonical re-encoding
        canonical_sig = base64.b64encode(sig_bytes).decode("ascii")
        assert signed.signature == canonical_sig

        # Construct a different Base64 string that decodes to the same bytes
        # by flipping unused pad bits in the last character before "=="
        b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last_char_idx = b64_alphabet.index(canonical_sig[85])
        # Flip the lowest pad bit
        alt_char_idx = last_char_idx ^ 1
        # Clear pad bits and set new ones to ensure it's different
        real_bits = last_char_idx & 0x30
        alt_pad = (last_char_idx & 0x03) ^ 0x01  # flip lowest pad bit
        alt_char_idx = real_bits | alt_pad
        if alt_char_idx == last_char_idx:
            alt_char_idx = real_bits | ((last_char_idx & 0x03) + 1) % 16
        alt_last_char = b64_alphabet[alt_char_idx]
        non_canonical_sig = canonical_sig[:85] + alt_last_char + "=="

        # Precondition: two different strings, same decoded bytes
        assert non_canonical_sig != canonical_sig
        assert base64.b64decode(non_canonical_sig) == base64.b64decode(canonical_sig)

        # Build receipt with canonical signature
        base_fields = {k: v for k, v in signed.to_dict().items() if k != "signature"}
        canonical_receipt = L1Receipt(**base_fields, signature=canonical_sig)

        # Build receipt with non-canonical signature
        non_canonical_receipt = L1Receipt(**base_fields, signature=non_canonical_sig)

        # Only canonical passes
        assert canonical_receipt.verify_signature(public_key) is True, \
            "Canonical Base64 must pass"
        assert non_canonical_receipt.verify_signature(public_key) is False, \
            "Non-canonical Base64 must be rejected"
