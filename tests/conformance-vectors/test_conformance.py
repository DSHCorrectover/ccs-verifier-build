"""
CCS Conformance Test Runner
============================
Pytest-based runner for all 17 conformance vectors.

Categories:
  - L0 basic receipt (2): HMAC-SHA256 generation & tamper detection
  - L1 Ed25519 receipt (2): full build + verify
  - L1 fail/tamper (3): signature invalidation on field tampering
  - Tamper detection (3): action/nonce/public_key tampering
  - Anti-replay (3): nonce uniqueness, expiry, clock skew
  - CAID action mapping (4): exact, MCP prefix, heuristic, fallback
"""

import json
import os
import sys
import time
import hmac
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

# Add project root to path so ccs_verifier_l1 is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ccs_verifier_l1 import (
    Ed25519Signer,
    L1ReceiptBuilder,
    CAIDAction,
    map_tool_to_action,
    sign_receipt_l0,
    verify_l1_receipt,
    DeploymentMode,
)

VECTORS_DIR = Path(__file__).resolve().parent


def _load(name: str) -> dict:
    with open(VECTORS_DIR / name) as f:
        return json.load(f)


# ── L0 Basic Receipt ────────────────────────────────────────────────

class TestL0BasicReceipt:
    def test_l0_001_valid_receipt(self):
        """L0-001: valid HMAC-SHA256 receipt."""
        v = _load("l0-001.json")
        inp = v["input"]
        secret = bytes.fromhex(inp["secret_hex"])
        receipt = sign_receipt_l0(
            trace_id=inp["trace_id"],
            verdict=inp["verdict"],
            timestamp=inp["timestamp"],
            secret=secret,
            tool=inp["tool"],
            params_hash=inp["params_hash"],
            rule_summary=inp["rule_summary"],
        )
        assert len(receipt) == v["expected_output"]["receipt_length"]
        assert v["expected_output"]["pass"] is True

        # Verify deterministic: same inputs → same receipt
        receipt2 = sign_receipt_l0(
            trace_id=inp["trace_id"],
            verdict=inp["verdict"],
            timestamp=inp["timestamp"],
            secret=secret,
            tool=inp["tool"],
            params_hash=inp["params_hash"],
            rule_summary=inp["rule_summary"],
        )
        assert receipt == receipt2

    def test_l0_002_tampered_verdict_mismatch(self):
        """L0-002: tampered verdict produces different receipt."""
        v = _load("l0-002.json")
        inp = v["input"]
        secret = bytes.fromhex(inp["secret_hex"])

        # Original receipt
        receipt_original = sign_receipt_l0(
            trace_id=inp["trace_id"],
            verdict=inp["verdict"],
            timestamp=inp["timestamp"],
            secret=secret,
            tool=inp["tool"],
            params_hash=inp["params_hash"],
            rule_summary=inp["rule_summary"],
        )
        # Tampered receipt (different verdict)
        receipt_tampered = sign_receipt_l0(
            trace_id=inp["trace_id"],
            verdict=inp["tampered_verdict"],
            timestamp=inp["timestamp"],
            secret=secret,
            tool=inp["tool"],
            params_hash=inp["params_hash"],
            rule_summary=inp["rule_summary"],
        )
        assert receipt_original != receipt_tampered
        assert v["expected_output"]["pass"] is False


# ── L1 Ed25519 Receipt ──────────────────────────────────────────────

class TestL1Ed25519Receipt:
    def _build_l1(self, inp: dict, **overrides):
        """Helper: build an L1 receipt from vector input."""
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:conformance-test",
            audience=inp.get("agent_id", "agent:test"),
            verifier_source_class="VerifierServer",
            verifier_deployment_mode=DeploymentMode.IN_PROCESS,
            verifier_version="0.5.0-l1",
        )
        builder.reset_sequence()
        kw = dict(
            agent_id=inp["agent_id"],
            tool=inp["tool"],
            params=inp["params"],
            trace_id=inp["trace_id"],
            request_timestamp=inp["request_timestamp"],
            verdict=inp["verdict"],
            block_reason=inp.get("block_reason", ""),
            rule_results=inp.get("rule_results", []),
            verified_at=inp.get("verified_at", time.time()),
            error_code=inp.get("error_code", -32000),
        )
        # Handle clock skew bounds override
        if "clock_skew_bounds" in inp:
            builder._clock_skew_bounds = inp["clock_skew_bounds"]
        if "validity_seconds" in inp:
            builder._validity_seconds = inp["validity_seconds"]
        kw.update(overrides)
        return builder.build(**kw)

    def test_l1_001_full_build_verify(self):
        """L1-001: Ed25519 receipt build + verify, expect all_pass=True."""
        v = _load("l1-001.json")
        receipt = self._build_l1(v["input"])
        result = verify_l1_receipt(receipt)
        assert result["signature_valid"] is True
        assert result["receipt_level_1"] is True
        assert result["ed25519_algorithm"] is True
        assert result["all_fields_present"] is True
        assert v["expected_output"]["pass"] is True

    def test_l1_002_deny_verdict_valid(self):
        """L1-002: deny verdict still produces valid receipt."""
        v = _load("l1-002.json")
        receipt = self._build_l1(v["input"])
        result = verify_l1_receipt(receipt)
        assert result["signature_valid"] is True
        assert receipt.verdict == "deny"
        assert v["expected_output"]["pass"] is True


# ── L1 Fail / Tamper ────────────────────────────────────────────────

class TestL1FailTamper:
    def _build_and_tamper(self, vec_name: str):
        """Build receipt, tamper specified field, verify failure."""
        v = _load(vec_name)
        inp = v["input"]
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:conformance-test",
            audience=inp["agent_id"],
        )
        builder.reset_sequence()
        receipt = builder.build(
            agent_id=inp["agent_id"],
            tool=inp["tool"],
            params=inp["params"],
            trace_id=inp["trace_id"],
            request_timestamp=inp["request_timestamp"],
            verdict=inp["verdict"],
            block_reason=inp.get("block_reason", ""),
            rule_results=inp.get("rule_results", []),
            verified_at=inp.get("verified_at", time.time()),
            error_code=inp.get("error_code", -32000),
        )
        # Tamper the specified field
        field = inp["tamper_field"]
        value = inp["tamper_value"]
        setattr(receipt, field, value)
        return receipt, v

    def test_l1_003_tamper_verdict(self):
        """L1-003: tampered verdict → signature invalid."""
        receipt, v = self._build_and_tamper("l1-003.json")
        assert receipt.verify_signature() is False
        assert v["expected_output"]["signature_valid"] is False

    def test_l1_004_tamper_trace_id(self):
        """L1-004: tampered trace_id → signature invalid."""
        receipt, v = self._build_and_tamper("l1-004.json")
        assert receipt.verify_signature() is False
        assert v["expected_output"]["signature_valid"] is False

    def test_l1_005_tamper_request_hash(self):
        """L1-005: tampered request_hash → signature invalid."""
        receipt, v = self._build_and_tamper("l1-005.json")
        assert receipt.verify_signature() is False
        assert v["expected_output"]["signature_valid"] is False


# ── Tamper Detection ────────────────────────────────────────────────

class TestTamperDetection:
    def _build_and_tamper(self, vec_name: str):
        v = _load(vec_name)
        inp = v["input"]
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:conformance-test",
            audience=inp["agent_id"],
        )
        builder.reset_sequence()
        receipt = builder.build(
            agent_id=inp["agent_id"],
            tool=inp["tool"],
            params=inp["params"],
            trace_id=inp["trace_id"],
            request_timestamp=inp["request_timestamp"],
            verdict=inp["verdict"],
            block_reason=inp.get("block_reason", ""),
            rule_results=inp.get("rule_results", []),
            verified_at=inp.get("verified_at", time.time()),
            error_code=inp.get("error_code", -32000),
        )
        field = inp["tamper_field"]
        value = inp["tamper_value"]
        setattr(receipt, field, value)
        return receipt, v

    def test_tamper_001_action_field(self):
        """TAMPER-001: tampered action → signature invalid."""
        receipt, v = self._build_and_tamper("tamper-001.json")
        assert receipt.verify_signature() is False

    def test_tamper_002_nonce_field(self):
        """TAMPER-002: tampered nonce → signature invalid."""
        receipt, v = self._build_and_tamper("tamper-002.json")
        assert receipt.verify_signature() is False

    def test_tamper_003_public_key(self):
        """TAMPER-003: tampered public_key → signature invalid."""
        receipt, v = self._build_and_tamper("tamper-003.json")
        assert receipt.verify_signature() is False


# ── Anti-Replay ─────────────────────────────────────────────────────

class TestAntiReplay:
    def test_replay_001_unique_nonce(self):
        """REPLAY-001: two receipts get unique nonces & monotonic sequence."""
        v = _load("replay-001.json")
        inp = v["input"]
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:conformance-test",
            audience=inp["agent_id"],
        )
        builder.reset_sequence()
        common = dict(
            agent_id=inp["agent_id"],
            tool=inp["tool"],
            params=inp["params"],
            trace_id=inp["trace_id"],
            request_timestamp=inp["request_timestamp"],
            verdict=inp["verdict"],
            block_reason=inp.get("block_reason", ""),
            rule_results=inp.get("rule_results", []),
            verified_at=inp.get("verified_at", time.time()),
            error_code=inp.get("error_code", -32000),
        )
        r1 = builder.build(**common)
        r2 = builder.build(**common)
        assert r1.nonce != r2.nonce, "nonces must be unique"
        assert r2.sequence > r1.sequence, "sequence must be monotonic"
        assert v["expected_output"]["unique_nonce_per_receipt"] is True
        assert v["expected_output"]["sequence_monotonic"] is True

    def test_replay_002_expired_receipt(self):
        """REPLAY-002: expired receipt beyond clock skew → temporal_valid=False."""
        v = _load("replay-002.json")
        inp = v["input"]
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:conformance-test",
            audience=inp["agent_id"],
            validity_seconds=inp.get("validity_seconds", 300),
            clock_skew_bounds=inp.get("clock_skew_bounds"),
        )
        builder.reset_sequence()
        receipt = builder.build(
            agent_id=inp["agent_id"],
            tool=inp["tool"],
            params=inp["params"],
            trace_id=inp["trace_id"],
            request_timestamp=inp["request_timestamp"],
            verdict=inp["verdict"],
            block_reason=inp.get("block_reason", ""),
            rule_results=inp.get("rule_results", []),
            verified_at=inp["verified_at"],
            error_code=inp.get("error_code", -32000),
        )
        # Verify at a time well past expiry + skew
        result = receipt.verify_temporal(now=inp["verify_at_time"])
        assert result is False
        assert v["expected_output"]["temporal_valid"] is False

    def test_replay_003_within_clock_skew(self):
        """REPLAY-003: slightly expired but within skew → temporal_valid=True."""
        v = _load("replay-003.json")
        inp = v["input"]
        signer = Ed25519Signer()
        builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier:conformance-test",
            audience=inp["agent_id"],
            validity_seconds=inp.get("validity_seconds", 300),
            clock_skew_bounds=inp.get("clock_skew_bounds"),
        )
        builder.reset_sequence()
        receipt = builder.build(
            agent_id=inp["agent_id"],
            tool=inp["tool"],
            params=inp["params"],
            trace_id=inp["trace_id"],
            request_timestamp=inp["request_timestamp"],
            verdict=inp["verdict"],
            block_reason=inp.get("block_reason", ""),
            rule_results=inp.get("rule_results", []),
            verified_at=inp["verified_at"],
            error_code=inp.get("error_code", -32000),
        )
        # Verify at a time slightly past expiry but within skew
        result = receipt.verify_temporal(now=inp["verify_at_time"])
        assert result is True
        assert v["expected_output"]["temporal_valid"] is True


# ── CAID Action Mapping ────────────────────────────────────────────

class TestCAIDActionMapping:
    def test_caid_001_exact_match_shell(self):
        """CAID-001: 'shell' → shell.execute (exact match)."""
        v = _load("caid-001.json")
        result = map_tool_to_action(v["input"]["tool_name"])
        assert result.value == v["expected_output"]["action"]

    def test_caid_002_mcp_prefix(self):
        """CAID-002: 'mcp__filesystem__read_file' → file.read (MCP prefix)."""
        v = _load("caid-002.json")
        result = map_tool_to_action(v["input"]["tool_name"])
        assert result.value == v["expected_output"]["action"]

    def test_caid_003_heuristic_keyword(self):
        """CAID-003: 'custom_read_handler' → file.read (heuristic)."""
        v = _load("caid-003.json")
        result = map_tool_to_action(v["input"]["tool_name"])
        assert result.value == v["expected_output"]["action"]

    def test_caid_004_fallback_unknown(self):
        """CAID-004: 'quantum_teleport' → unknown (fallback)."""
        v = _load("caid-004.json")
        result = map_tool_to_action(v["input"]["tool_name"])
        assert result.value == v["expected_output"]["action"]
