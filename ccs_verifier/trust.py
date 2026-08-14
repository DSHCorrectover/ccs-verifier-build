"""
CCS Trust Anchor — VERIFIED vs ACCEPTED two-stage trust model.

Background (raised in independent audit by Iman Schrock, 2026-08-15):

  Embedding the Ed25519 public key inside a signed receipt makes the
  receipt self-consistent: any party in possession of the receipt can
  check that the signature verifies against the embedded key. But it
  does NOT, on its own, authenticate the *issuer identity*. Anyone can
  generate a fresh Ed25519 keypair, set issuer="ccs-verifier" and
  audience="...", sign an allow verdict, and produce a receipt whose
  verify_signature() returns True. That is the correct cryptographic
  behavior of a self-attesting signature.

  The relying party is therefore responsible for binding the embedded
  key (or its public_key_fingerprint) to a trusted issuer — either an
  out-of-band pinned key or an entry in an authenticated registry.

This module formalises that two-stage outcome:

  VERIFIED  = signature is cryptographically valid against the embedded
              or explicitly-supplied key.
  ACCEPTED  = VERIFIED AND the key matches a configured trust anchor
              for the declared `issuer`.

A receipt that is VERIFIED but not ACCEPTED MUST be treated the same
as a receipt that failed signature verification for any enforcement
decision; it can still be logged for telemetry.

The reference distribution ships a non-deployment trust anchor under
ccs_verifier/reference_issuer.json. Production deployments MUST rotate
and pin their own signing key; the shipped reference key identifies
upstream reference builds and bundled test vectors only.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Optional


REFERENCE_ISSUER_FILE = os.path.join(os.path.dirname(__file__), "reference_issuer.json")


@dataclass(frozen=True)
class TrustAnchor:
    """A pinned Ed25519 public key for a declared issuer."""
    issuer: str
    public_key_raw_b64: str
    public_key_fingerprint_sha256_16: str

    @property
    def public_key_bytes(self) -> bytes:
        return base64.b64decode(self.public_key_raw_b64, validate=True)


def load_reference_anchor() -> TrustAnchor:
    """Load the reference-distribution trust anchor (NOT for production deployments)."""
    with open(REFERENCE_ISSUER_FILE, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return TrustAnchor(
        issuer=doc["issuer"],
        public_key_raw_b64=doc["public_key_raw_b64"],
        public_key_fingerprint_sha256_16=doc["public_key_fingerprint_sha256_16"],
    )


@dataclass(frozen=True)
class TrustDecision:
    """
    Result of the two-stage trust check.

      verified: signature passed cryptographic verification.
      accepted: signature passed AND signing key matches a pinned
                anchor for the declared issuer.
      reason:   Machine-readable explanation when not accepted.
    """
    verified: bool
    accepted: bool
    reason: str = ""

    def __bool__(self) -> bool:
        """Enforcement decisions MUST use `accepted`, not truthiness."""
        return self.accepted


def evaluate_trust(receipt, anchors) -> TrustDecision:
    """
    Evaluate a receipt against a set of trusted anchors.

    Args:
      receipt: A L1Receipt (or object with .issuer, .public_key,
               .public_key_fingerprint and .verify_signature()).
      anchors: Iterable of TrustAnchor. The first anchor whose issuer
               matches receipt.issuer is used for the pin check.

    Returns:
      TrustDecision. Caller MUST gate enforcement on .accepted.
    """
    # Stage 1: cryptographic self-consistency (uses embedded key).
    if not receipt.verify_signature():
        return TrustDecision(verified=False, accepted=False,
                             reason="signature_failed")

    # Stage 2: bind the signing key to a trusted issuer anchor.
    pinned = None
    for a in anchors:
        if a.issuer == receipt.issuer:
            pinned = a
            break

    if pinned is None:
        return TrustDecision(
            verified=True, accepted=False,
            reason=f"no_pinned_anchor_for_issuer:{receipt.issuer}",
        )

    if receipt.public_key_fingerprint != pinned.public_key_fingerprint_sha256_16:
        return TrustDecision(
            verified=True, accepted=False,
            reason="fingerprint_mismatch",
        )

    try:
        embedded_bytes = base64.b64decode(receipt.public_key, validate=True)
    except Exception:
        return TrustDecision(verified=True, accepted=False,
                             reason="embedded_key_decode_failed")

    if embedded_bytes != pinned.public_key_bytes:
        return TrustDecision(verified=True, accepted=False,
                             reason="public_key_mismatch")

    return TrustDecision(verified=True, accepted=True, reason="ok")
