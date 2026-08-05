#!/usr/bin/env python3
"""
CCS Verifier v0.5.0 — Benchmark Script
Measures throughput and latency for all 9 rules (3 Security + 6 dimension rules)

Usage: python3 benchmark.py [--samples N] [--warmup N]
"""
import json
import sys
import time
import statistics

def benchmark_verify_invocation(samples=50000, warmup=1000):
    """Benchmark ccs_verifier.verify_invocation with all rules active"""
    try:
        from ccs_verifier import verify_invocation
    except ImportError:
        print("ERROR: ccs_verifier not installed. Run: pip install ccs-verifier", file=sys.stderr)
        sys.exit(1)

    # Standard test invocation
    test_args = {
        "command": "echo hello",
        "url": "https://api.example.com/data",
        "path": "/data/file.txt",
        "code": "x = 1 + 2"
    }
    test_metadata = {
        "estimated_latency_us": 50000,
        "cost_tokens": 500,
        "latency_budget_us": 100000,
        "token_budget": 4000
    }

    # Warmup
    for _ in range(warmup):
        verify_invocation(tool_name="benchmark", arguments=test_args, metadata=test_metadata)

    # Benchmark
    latencies = []
    start_total = time.monotonic()
    for i in range(samples):
        t0 = time.perf_counter_ns()
        verify_invocation(tool_name="benchmark", arguments=test_args, metadata=test_metadata)
        t1 = time.perf_counter_ns()
        latencies.append((t1 - t0) / 1000.0)  # ns to us
    total_s = time.monotonic() - start_total

    # Statistics
    latencies.sort()
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runtime": f"cpython-{sys.version.split()[0]}",
        "samples": samples,
        "warmup": warmup,
        "results": {
            "p50_us": statistics.median(latencies),
            "p99_us": latencies[int(len(latencies) * 0.99)],
            "mean_us": statistics.mean(latencies),
            "min_us": min(latencies),
            "max_us": max(latencies),
            "throughput_ops_per_sec": int(samples / total_s),
            "total_s": round(total_s, 3)
        }
    }
    return results

if __name__ == "__main__":
    samples = 50000
    warmup = 1000
    for arg in sys.argv[1:]:
        if arg.startswith("--samples="):
            samples = int(arg.split("=")[1])
        elif arg.startswith("--warmup="):
            warmup = int(arg.split("=")[1])

    print(f"CCS Verifier Benchmark — {samples} samples, {warmup} warmup")
    print(f"Rules: RCERule + SSRFRule + CredentialLeakRule + 6 dimension rules")
    print()

    results = benchmark_verify_invocation(samples, warmup)
    print(json.dumps(results, indent=2))
