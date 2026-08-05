#!/usr/bin/env python3
"""
CCS Verifier L1 Receipt — Benchmark Script

Measures latency for L1 receipt generation and verification.
Outputs JSON to benchmark_output_l1.json.

Usage: python3 benchmark_l1.py [--samples N] [--warmup N]
"""
import json
import sys
import time
import statistics
import os

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccs_verifier_l1 import (
    Ed25519Signer, L1ReceiptBuilder, DeploymentMode,
    verify_l1_receipt, sign_receipt_l0, map_tool_to_action,
)


def benchmark_l1_receipt(samples=1000, warmup=100):
    """Benchmark L1 receipt generation and verification."""
    signer = Ed25519Signer()
    builder = L1ReceiptBuilder(
        signer=signer,
        issuer="ccs-verifier:v0.5.0",
        audience="agent:benchmark",
        verifier_source_class="VerifierServer",
        verifier_deployment_mode=DeploymentMode.IN_PROCESS,
        verifier_version="0.5.0",
        rules=["ssrf_protection", "rce_protection"],
        validity_seconds=300,
    )

    # --- Warmup ---
    for _ in range(warmup):
        r = builder.build(
            agent_id="agent:warmup",
            tool="shell",
            params={"command": "echo warmup"},
            trace_id="trc_warmup",
            request_timestamp=time.time(),
            verdict="allow",
            rule_results=[],
            verified_at=time.time(),
        )
        verify_l1_receipt(r)

    # --- L1 generation benchmark ---
    gen_latencies = []
    for i in range(samples):
        t0 = time.perf_counter_ns()
        receipt = builder.build(
            agent_id="agent:bench",
            tool="shell",
            params={"command": "echo bench"},
            trace_id=f"trc_bench_{i:06d}",
            request_timestamp=time.time(),
            verdict="allow",
            rule_results=[],
            verified_at=time.time(),
        )
        t1 = time.perf_counter_ns()
        gen_latencies.append((t1 - t0) / 1000.0)  # ns -> us

    # --- L1 verification benchmark ---
    verify_latencies = []
    for _ in range(samples):
        receipt = builder.build(
            agent_id="agent:bench",
            tool="shell",
            params={"command": "echo bench"},
            trace_id="trc_verify_bench",
            request_timestamp=time.time(),
            verdict="allow",
            rule_results=[],
            verified_at=time.time(),
        )
        t0 = time.perf_counter_ns()
        verify_l1_receipt(receipt)
        t1 = time.perf_counter_ns()
        verify_latencies.append((t1 - t0) / 1000.0)

    # --- L0 HMAC benchmark (for comparison) ---
    l0_latencies = []
    secret = os.urandom(32)
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        sign_receipt_l0(
            trace_id="trc_l0_bench",
            verdict="allow",
            timestamp=time.time(),
            secret=secret,
            tool="shell",
            params_hash="abcd1234",
        )
        t1 = time.perf_counter_ns()
        l0_latencies.append((t1 - t0) / 1000.0)

    # --- Ed25519 sign-only benchmark ---
    sign_only_latencies = []
    for _ in range(samples):
        data = os.urandom(256)
        t0 = time.perf_counter_ns()
        signer.sign(data)
        t1 = time.perf_counter_ns()
        sign_only_latencies.append((t1 - t0) / 1000.0)

    # --- Ed25519 verify-only benchmark ---
    verify_only_latencies = []
    test_data = b"benchmark verify test data"
    test_sig = signer.sign(test_data)
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        signer.public_key.verify(test_sig, test_data)
        t1 = time.perf_counter_ns()
        verify_only_latencies.append((t1 - t0) / 1000.0)

    # --- Compute stats ---
    def stats(latencies):
        lat = sorted(latencies)
        return {
            "mean_us": round(statistics.mean(lat), 1),
            "p50_us": round(statistics.median(lat), 1),
            "p95_us": round(lat[int(len(lat) * 0.95)], 1),
            "p99_us": round(lat[int(len(lat) * 0.99)], 1),
            "min_us": round(min(lat), 1),
            "max_us": round(max(lat), 1),
            "samples": len(lat),
        }

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runtime": f"cpython-{sys.version.split()[0]}",
        "samples": samples,
        "warmup": warmup,
        "benchmarks": {
            "l1_full_receipt_generation": stats(gen_latencies),
            "l1_full_receipt_verification": stats(verify_latencies),
            "l0_hmac_sha256": stats(l0_latencies),
            "ed25519_sign_only": stats(sign_only_latencies),
            "ed25519_verify_only": stats(verify_only_latencies),
        }
    }
    return results


if __name__ == "__main__":
    samples = 1000
    warmup = 100
    for arg in sys.argv[1:]:
        if arg.startswith("--samples="):
            samples = int(arg.split("=")[1])
        elif arg.startswith("--warmup="):
            warmup = int(arg.split("=")[1])

    print(f"CCS Verifier L1 Benchmark — {samples} samples, {warmup} warmup")
    results = benchmark_l1_receipt(samples, warmup)

    # Write to benchmark_output_l1.json
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_output_l1.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(json.dumps(results, indent=2))
    print(f"\nResults written to {out_path}")
