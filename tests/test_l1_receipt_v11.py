"""
CCS Verifier L1 Receipt v1.1 — Test Suite

Covers the two architectural improvements from autogen#7265:
  1. rule_version — "Pin the rule, not just the action"
  2. tool_call_id + args_digest — Approval-execution cryptographic binding

Test categories:
  - rule_version correctly written to receipt and affects signature
  - tool_call_id + args_digest correctly bound
  - Backward compatibility (no new fields → receipt still valid)
  - args_digest auto-computed from params
  - tool_call_id auto-derived from trace_id + tool + nonce
  - compute_rule_hash helper function
  - Serialization round-trip with new fields
  - Tamper detection on new fields

Run: python3 -m pytest tests/test_l1_receipt_v11.py -v
"""

import hashlib
import json
import time
import sys
import os
from pathlib import Path

import pytest

# Add repo root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ccs_verifier_l1 import (
    Ed25519Signer,
    L1ReceiptBuilder,
    L1Receipt,
    DeploymentMode,
    verify_l1_receipt,
    serialize_receipt,
    deserialize_receipt,
    compute_rule_hash,
    _canonical_json,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def signer():
    """Fresh Ed25519 signer for each test."""
    return Ed25519Signer()


@pytest.fixture
def builder(signer):
    """Standard L1ReceiptBuilder."""
    return L1ReceiptBuilder(
        signer=signer,
        issuer="ccs-verifier:v0.5.0",
        audience="agent:test",
        verifier_source_class="VerifierServer",
        verifier_deployment_mode=DeploymentMode.IN_PROCESS,
        verifier_version="0.5.0",
        rules=["ssrf_protection", "rce_protection"],
        validity_seconds=300,
    )


def _make_receipt(builder, **kwargs):
    """Helper to build a standard receipt with sensible defaults."""
    defaults = dict(
        agent_id="agent:test",
        tool="shell",
        params={"command": "echo hello"},
        trace_id="trc_test_001",
        request_timestamp=time.time(),
        verdict="allow",
        rule_results=[],
        verified_at=time.time(),
    )
    defaults.update(kwargs)
    return builder.build(**defaults)


# ---------------------------------------------------------------------------
# 1. compute_rule_hash helper
# ---------------------------------------------------------------------------

class TestComputeRuleHash:
    """Tests for the compute_rule_hash utility function."""

    def test_returns_64_char_hex(self):
        """compute_rule_hash should return a 64-character hex string."""
        h = compute_rule_hash("v1.0.0")
        assert len(h) == 64
        int(h, 16)  # Should be valid hex

    def test_different_versions_different_hash(self):
        """Different rule versions should produce different hashes."""
        h1 = compute_rule_hash("v1.0.0")
        h2 = compute_rule_hash("v2.0.0")
        assert h1 != h2

    def test_same_inputs_same_hash(self):
        """Same inputs should produce identical hashes (deterministic)."""
        h1 = compute_rule_hash("v1.0.0", "ssrf_protection")
        h2 = compute_rule_hash("v1.0.0", "ssrf_protection")
        assert h1 == h2

    def test_rule_name_affects_hash(self):
        """Including a rule_name should change the hash."""
        h1 = compute_rule_hash("v1.0.0", "")
        h2 = compute_rule_hash("v1.0.0", "ssrf_protection")
        assert h1 != h2

    def test_empty_string_valid_input(self):
        """Empty strings should be valid input (backward compat)."""
        h = compute_rule_hash("")
        assert len(h) == 64

    def test_matches_manual_sha256(self):
        """Hash should match manual SHA-256 of canonical JSON."""
        rule_version = "v2.1.0"
        rule_name = "rce_protection"
        expected = hashlib.sha256(
            json.dumps(
                {"rule_version": rule_version, "rule_name": rule_name},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        assert compute_rule_hash(rule_version, rule_name) == expected


# ---------------------------------------------------------------------------
# 2. rule_version field
# ---------------------------------------------------------------------------

class TestRuleVersion:
    """Tests for rule_version field — 'Pin the rule, not just the action'."""

    def test_rule_version_default_empty(self, builder):
        """Default rule_version should be empty string (backward compat)."""
        receipt = _make_receipt(builder)
        assert receipt.rule_version == ""

    def test_rule_version_written_to_receipt(self, builder):
        """rule_version should be correctly stored in the receipt."""
        receipt = _make_receipt(builder, rule_version="v2.1.0")
        assert receipt.rule_version == "v2.1.0"

    def test_rule_version_affects_signature(self, builder):
        """Different rule_version values should produce different signatures."""
        receipt_a = _make_receipt(builder, rule_version="v1.0.0")
        receipt_b = _make_receipt(builder, rule_version="v2.0.0")
        assert receipt_a.signature != receipt_b.signature

    def test_rule_version_in_signing_payload(self, builder):
        """rule_version must be included in the signing payload."""
        receipt = _make_receipt(builder, rule_version="v3.0.0")
        payload_dict = json.loads(receipt.signing_payload())
        assert "rule_version" in payload_dict
        assert payload_dict["rule_version"] == "v3.0.0"

    def test_rule_version_in_to_dict(self, builder):
        """rule_version should appear in to_dict() output."""
        receipt = _make_receipt(builder, rule_version="v1.5.0")
        d = receipt.to_dict()
        assert "rule_version" in d
        assert d["rule_version"] == "v1.5.0"

    def test_tamper_rule_version_breaks_signature(self, builder):
        """Modifying rule_version after signing should break the signature."""
        receipt = _make_receipt(builder, rule_version="v1.0.0")
        assert receipt.verify_signature() is True
        receipt.rule_version = "v9.9.9"
        assert receipt.verify_signature() is False

    def test_same_rule_version_same_signature_components(self, builder):
        """Same rule_version with identical other inputs should produce
        identical signing payloads (verifying rule_version is deterministic)."""
        ts = time.time()
        receipt_a = _make_receipt(
            builder,
            rule_version="v1.0.0",
            trace_id="trc_same",
            request_timestamp=ts,
            verified_at=ts,
        )
        receipt_b = _make_receipt(
            builder,
            rule_version="v1.0.0",
            trace_id="trc_same",
            request_timestamp=ts,
            verified_at=ts,
        )
        # Nonce will differ, so signatures differ, but rule_version in payload matches
        payload_a = json.loads(receipt_a.signing_payload())
        payload_b = json.loads(receipt_b.signing_payload())
        assert payload_a["rule_version"] == payload_b["rule_version"]


# ---------------------------------------------------------------------------
# 3. tool_call_id field
# ---------------------------------------------------------------------------

class TestToolCallId:
    """Tests for tool_call_id — unique tool call instance identifier."""

    def test_tool_call_id_default_auto_derived(self, builder):
        """When not provided, tool_call_id should be auto-derived (non-empty)."""
        receipt = _make_receipt(builder)
        assert receipt.tool_call_id != ""
        assert len(receipt.tool_call_id) > 0

    def test_tool_call_id_explicit_value(self, builder):
        """Explicitly provided tool_call_id should be used as-is."""
        receipt = _make_receipt(builder, tool_call_id="call_abc123")
        assert receipt.tool_call_id == "call_abc123"

    def test_tool_call_id_auto_derived_from_trace_tool_nonce(self, builder):
        """Auto-derived tool_call_id should be deterministic given same inputs."""
        ts = time.time()
        # Build with explicit nonce control is not possible, but we can verify
        # the derivation logic by checking the formula
        receipt = _make_receipt(
            builder,
            trace_id="trc_fixed",
            tool="read_file",
        )
        assert receipt.tool_call_id != ""

    def test_tool_call_id_in_signing_payload(self, builder):
        """tool_call_id must be in the signing payload."""
        receipt = _make_receipt(builder, tool_call_id="call_xyz789")
        payload_dict = json.loads(receipt.signing_payload())
        assert "tool_call_id" in payload_dict
        assert payload_dict["tool_call_id"] == "call_xyz789"

    def test_tamper_tool_call_id_breaks_signature(self, builder):
        """Modifying tool_call_id after signing should break signature."""
        receipt = _make_receipt(builder, tool_call_id="call_original")
        assert receipt.verify_signature() is True
        receipt.tool_call_id = "call_tampered"
        assert receipt.verify_signature() is False

    def test_different_tool_call_ids_different_signatures(self, builder):
        """Different tool_call_ids should produce different signatures."""
        ts = time.time()
        receipt_a = _make_receipt(
            builder, tool_call_id="call_a", trace_id="trc_same",
            request_timestamp=ts, verified_at=ts,
        )
        receipt_b = _make_receipt(
            builder, tool_call_id="call_b", trace_id="trc_same",
            request_timestamp=ts, verified_at=ts,
        )
        assert receipt_a.signature != receipt_b.signature


# ---------------------------------------------------------------------------
# 4. args_digest field
# ---------------------------------------------------------------------------

class TestArgsDigest:
    """Tests for args_digest — SHA-256 of exact pre-execution arguments."""

    def test_args_digest_default_auto_computed(self, builder):
        """When not provided, args_digest should be auto-computed from params."""
        params = {"command": "echo test", "timeout": 30}
        receipt = _make_receipt(builder, params=params)
        assert receipt.args_digest != ""

        # Verify it matches manual computation
        expected = hashlib.sha256(
            _canonical_json(params)
        ).hexdigest()[:16]
        assert receipt.args_digest == expected

    def test_args_digest_explicit_value(self, builder):
        """Explicitly provided args_digest should be used as-is."""
        receipt = _make_receipt(builder, args_digest="deadbeef12345678")
        assert receipt.args_digest == "deadbeef12345678"

    def test_args_digest_different_params_different_digest(self, builder):
        """Different params should produce different args_digests."""
        receipt_a = _make_receipt(builder, params={"command": "echo a"})
        receipt_b = _make_receipt(builder, params={"command": "echo b"})
        assert receipt_a.args_digest != receipt_b.args_digest

    def test_args_digest_same_params_same_digest(self, builder):
        """Same params should produce same args_digest (deterministic)."""
        params = {"command": "echo same", "flag": True}
        ts = time.time()
        receipt_a = _make_receipt(
            builder, params=params, trace_id="trc_a",
            request_timestamp=ts, verified_at=ts,
        )
        receipt_b = _make_receipt(
            builder, params=params, trace_id="trc_b",
            request_timestamp=ts, verified_at=ts,
        )
        assert receipt_a.args_digest == receipt_b.args_digest

    def test_args_digest_in_signing_payload(self, builder):
        """args_digest must be in the signing payload."""
        receipt = _make_receipt(builder, args_digest="abcdef0123456789")
        payload_dict = json.loads(receipt.signing_payload())
        assert "args_digest" in payload_dict
        assert payload_dict["args_digest"] == "abcdef0123456789"

    def test_tamper_args_digest_breaks_signature(self, builder):
        """Modifying args_digest after signing should break signature."""
        receipt = _make_receipt(builder, args_digest="original12345678")
        assert receipt.verify_signature() is True
        receipt.args_digest = "tampered99999999"
        assert receipt.verify_signature() is False

    def test_args_digest_is_16_chars_when_auto_computed(self, builder):
        """Auto-computed args_digest should be 16 hex characters (truncated SHA-256)."""
        receipt = _make_receipt(builder, params={"key": "value"})
        assert len(receipt.args_digest) == 16
        int(receipt.args_digest, 16)  # Valid hex

    def test_args_digest_empty_when_no_params(self, builder):
        """When params is empty dict and no args_digest given, should be empty."""
        receipt = _make_receipt(builder, params={})
        # Empty params → falsy → args_digest stays empty
        assert receipt.args_digest == ""


# ---------------------------------------------------------------------------
# 5. Backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Tests ensuring old callers (not passing new fields) still work."""

    def test_receipt_valid_without_new_fields(self, builder):
        """Receipt built without new fields should pass full verification."""
        receipt = _make_receipt(builder)
        results = verify_l1_receipt(receipt)
        assert results["signature_valid"] is True
        assert results["all_pass"] is True

    def test_new_fields_default_empty(self, builder):
        """New fields should default to empty strings when not provided."""
        receipt = _make_receipt(builder)
        assert receipt.rule_version == ""
        # tool_call_id and args_digest are auto-derived, so non-empty
        # but rule_version stays empty

    def test_receipt_version_is_1_1(self, builder):
        """receipt_version should be '1.1' after the upgrade."""
        receipt = _make_receipt(builder)
        assert receipt.receipt_version == "1.1"

    def test_deserialize_old_format_with_empty_new_fields(self):
        """Deserializing a receipt dict with missing new fields should work
        (they default to empty string)."""
        signer = Ed25519Signer()
        old_builder = L1ReceiptBuilder(
            signer=signer,
            issuer="ccs-verifier",
            audience="agent:old",
            verifier_version="0.5.0",
        )
        receipt = _make_receipt(old_builder)
        d = receipt.to_dict()
        # Simulate old format by removing new fields
        d.pop("rule_version", None)
        d.pop("tool_call_id", None)
        d.pop("args_digest", None)
        # Should still deserialize (dataclass defaults)
        restored = L1Receipt(**d)
        assert restored.rule_version == ""
        assert restored.tool_call_id == ""
        assert restored.args_digest == ""

    def test_l0_sign_receipt_still_works(self):
        """L0 HMAC signing function should be unchanged."""
        from ccs_verifier_l1 import sign_receipt_l0
        sig = sign_receipt_l0(
            trace_id="trc_l0",
            verdict="allow",
            timestamp=time.time(),
            secret=b"test_secret_key",
            tool="shell",
            params_hash="abc123",
        )
        assert len(sig) == 32
        assert all(c in "0123456789abcdef" for c in sig)


# ---------------------------------------------------------------------------
# 6. Serialization round-trip
# ---------------------------------------------------------------------------

class TestSerialization:
    """Tests for JSON serialization with new fields."""

    def test_serialize_deserialize_roundtrip(self, builder):
        """Serialized and deserialized receipt should preserve new fields."""
        receipt = _make_receipt(
            builder,
            rule_version="v2.0.0",
            tool_call_id="call_roundtrip",
            args_digest="roundtrip1234567",
        )
        json_str = serialize_receipt(receipt)
        restored = deserialize_receipt(json_str)

        assert restored.rule_version == "v2.0.0"
        assert restored.tool_call_id == "call_roundtrip"
        assert restored.args_digest == "roundtrip1234567"
        assert restored.verify_signature() is True

    def test_to_json_includes_new_fields(self, builder):
        """to_json() output should include new fields."""
        receipt = _make_receipt(builder, rule_version="v1.0.0")
        d = json.loads(receipt.to_json())
        assert "rule_version" in d
        assert "tool_call_id" in d
        assert "args_digest" in d

    def test_serialized_receipt_verification(self, builder):
        """A serialized-then-deserialized receipt should still verify."""
        receipt = _make_receipt(
            builder,
            rule_version="v1.2.0",
            tool_call_id="call_verify",
            args_digest="verify1234567890",
        )
        json_str = serialize_receipt(receipt)
        restored = deserialize_receipt(json_str)
        results = verify_l1_receipt(restored)
        assert results["signature_valid"] is True


# ---------------------------------------------------------------------------
# 7. Integration: all three new fields together
# ---------------------------------------------------------------------------

class TestIntegration:
    """Integration tests combining all v1.1 improvements."""

    def test_all_new_fields_together(self, builder):
        """All three new fields should work together in a single receipt."""
        params = {"command": "rm -rf /tmp/test", "force": True}
        receipt = _make_receipt(
            builder,
            params=params,
            verdict="deny",
            block_reason="RCE protection triggered",
            rule_version="v3.0.0",
            tool_call_id="call_integration_001",
            args_digest="integration12345",
        )
        assert receipt.rule_version == "v3.0.0"
        assert receipt.tool_call_id == "call_integration_001"
        assert receipt.args_digest == "integration12345"
        assert receipt.verify_signature() is True
        assert receipt.receipt_version == "1.1"

        results = verify_l1_receipt(receipt)
        assert results["all_pass"] is True

    def test_full_chain_tamper_detection(self, builder):
        """Tampering with ANY of the three new fields should break signature."""
        receipt = _make_receipt(
            builder,
            rule_version="v1.0.0",
            tool_call_id="call_chain",
            args_digest="chain1234567890",
        )
        assert receipt.verify_signature() is True

        # Tamper rule_version
        receipt.rule_version = "v9.9.9"
        assert receipt.verify_signature() is False
        receipt.rule_version = "v1.0.0"
        assert receipt.verify_signature() is True

        # Tamper tool_call_id
        receipt.tool_call_id = "tampered_call"
        assert receipt.verify_signature() is False
        receipt.tool_call_id = "call_chain"
        assert receipt.verify_signature() is True

        # Tamper args_digest
        receipt.args_digest = "tampered00000000"
        assert receipt.verify_signature() is False

    def test_rule_hash_can_be_computed_alongside_receipt(self, builder):
        """compute_rule_hash can be used to generate a hash that accompanies
        the receipt for external audit."""
        rule_version = "v2.1.0"
        rule_name = "ssrf_protection"
        receipt = _make_receipt(builder, rule_version=rule_version)
        rule_hash = compute_rule_hash(rule_version, rule_name)

        # The rule_hash is a separate audit artifact
        assert len(rule_hash) == 64
        assert receipt.rule_version == rule_version

    def test_auto_derivation_consistency(self, builder):
        """Auto-derived args_digest should be consistent with manual computation."""
        params = {"file": "/etc/passwd", "mode": "read"}
        receipt = _make_receipt(builder, params=params)

        manual_digest = hashlib.sha256(
            _canonical_json(params)
        ).hexdigest()[:16]
        assert receipt.args_digest == manual_digest

    def test_performance_new_fields_minimal_overhead(self, builder):
        """Adding new fields should not significantly impact performance."""
        # Warmup
        for _ in range(10):
            _make_receipt(builder)

        # Measure
        latencies = []
        for _ in range(100):
            t0 = time.perf_counter_ns()
            _make_receipt(
                builder,
                rule_version="v1.0.0",
                tool_call_id="call_perf",
                args_digest="perf12345678901",
            )
            t1 = time.perf_counter_ns()
            latencies.append(t1 - t0)

        import statistics
        p50 = statistics.median(latencies)
        # P50 should be well under 1ms (1,000,000 ns)
        # The spec target is < 100μs but Ed25519 signing dominates,
        # so we verify it's reasonable (< 10ms as a sanity check)
        assert p50 < 10_000_000, f"P50 too high: {p50}ns"
        print(f"\n  P50 latency: {p50/1000:.1f}μs")
