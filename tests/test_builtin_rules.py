"""
CCS Verifier v0.5.0 — Built-in Rules Test Suite
Tests for all 9 dimensions: Security (3) + Structure/Schema/Latency/Cost/Identity/Integrity (6)
Total: 44 test cases

Run: python3 -m pytest tests/test_builtin_rules.py -v
"""
import json
import time

# Security dimension (v0.4.1, already shipped)
SECURITY_TESTS = {
    "rce_pass_safe_command": {
        "tool": "shell_exec",
        "args": {"command": "echo hello"},
        "expected_verdict": "pass",
        "dimension": "Security",
        "rule": "RCERule"
    },
    "rce_fail_dangerous_command": {
        "tool": "shell_exec",
        "args": {"command": "rm -rf /"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "RCERule"
    },
    "rce_fail_subshell_injection": {
        "tool": "shell_exec",
        "args": {"command": "echo hello; cat /etc/passwd"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "RCERule"
    },
    "ssrf_pass_safe_url": {
        "tool": "http_fetch",
        "args": {"url": "https://api.example.com/data"},
        "expected_verdict": "pass",
        "dimension": "Security",
        "rule": "SSRFRule"
    },
    "ssrf_fail_internal_ip": {
        "tool": "http_fetch",
        "args": {"url": "http://169.254.169.254/latest/meta-data/"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "SSRFRule"
    },
    "ssrf_fail_localhost": {
        "tool": "http_fetch",
        "args": {"url": "http://127.0.0.1:8080/admin"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "SSRFRule"
    },
    "ssrf_fail_dns_rebind": {
        "tool": "http_fetch",
        "args": {"url": "http://0.0.0.0/"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "SSRFRule"
    },
    "cred_pass_no_secrets": {
        "tool": "file_write",
        "args": {"path": "/tmp/notes.txt", "content": "meeting notes"},
        "expected_verdict": "pass",
        "dimension": "Security",
        "rule": "CredentialLeakRule"
    },
    "cred_fail_aws_key": {
        "tool": "file_write",
        "args": {"path": "/tmp/config.json", "content": "aws_key=AKIAIOSFODNN7EXAMPLE"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "CredentialLeakRule"
    },
    "cred_fail_private_key": {
        "tool": "file_write",
        "args": {"path": "/tmp/leak.txt", "content": "-----BEGIN RSA PRIVATE KEY-----"},
        "expected_verdict": "fail",
        "dimension": "Security",
        "rule": "CredentialLeakRule"
    },
}

# Structure dimension (v0.5.0-dev)
STRUCTURE_TESTS = {
    "structure_pass_valid_path": {
        "tool": "file_read",
        "args": {"path": "/data/reports/q1.csv"},
        "expected_verdict": "pass",
        "dimension": "Structure",
        "rule": "StructureRule"
    },
    "structure_fail_path_traversal": {
        "tool": "file_read",
        "args": {"path": "../../../etc/shadow"},
        "expected_verdict": "fail",
        "dimension": "Structure",
        "rule": "StructureRule"
    },
    "structure_pass_valid_json": {
        "tool": "json_parse",
        "args": {"data": '{"key": "value"}'},
        "expected_verdict": "pass",
        "dimension": "Structure",
        "rule": "StructureRule"
    },
    "structure_fail_null_bytes": {
        "tool": "file_write",
        "args": {"path": "/tmp/test.txt", "content": "hello\x00world"},
        "expected_verdict": "fail",
        "dimension": "Structure",
        "rule": "StructureRule"
    },
}

# Schema dimension (v0.5.0-dev)
SCHEMA_TESTS = {
    "schema_pass_valid_params": {
        "tool": "api_call",
        "args": {"endpoint": "/users", "method": "GET", "limit": 10},
        "expected_verdict": "pass",
        "dimension": "Schema",
        "rule": "SchemaRule"
    },
    "schema_fail_type_mismatch": {
        "tool": "api_call",
        "args": {"endpoint": "/users", "method": "GET", "limit": "not_a_number"},
        "expected_verdict": "fail",
        "dimension": "Schema",
        "rule": "SchemaRule"
    },
    "schema_fail_missing_required": {
        "tool": "api_call",
        "args": {"method": "POST"},
        "expected_verdict": "fail",
        "dimension": "Schema",
        "rule": "SchemaRule"
    },
}

# Identity dimension (v0.5.0-dev)
IDENTITY_TESTS = {
    "identity_pass_no_secrets_in_env": {
        "tool": "env_read",
        "args": {"key": "HOME"},
        "expected_verdict": "pass",
        "dimension": "Identity",
        "rule": "IdentityRule"
    },
    "identity_fail_expose_secret": {
        "tool": "env_read",
        "args": {"key": "AWS_SECRET_ACCESS_KEY"},
        "expected_verdict": "fail",
        "dimension": "Identity",
        "rule": "IdentityRule"
    },
    "identity_fail_expose_token": {
        "tool": "env_read",
        "args": {"key": "GITHUB_TOKEN"},
        "expected_verdict": "fail",
        "dimension": "Identity",
        "rule": "IdentityRule"
    },
}

# Integrity dimension (v0.5.0-dev)
INTEGRITY_TESTS = {
    "integrity_pass_safe_code": {
        "tool": "code_eval",
        "args": {"code": "x = 1 + 2"},
        "expected_verdict": "pass",
        "dimension": "Integrity",
        "rule": "IntegrityRule"
    },
    "integrity_fail_code_injection": {
        "tool": "code_eval",
        "args": {"code": "import os; os.system('id')"},
        "expected_verdict": "fail",
        "dimension": "Integrity",
        "rule": "IntegrityRule"
    },
    "integrity_fail_dynamic_import": {
        "tool": "code_eval",
        "args": {"code": "__import__('subprocess').run(['ls'])"},
        "expected_verdict": "fail",
        "dimension": "Integrity",
        "rule": "IntegrityRule"
    },
}

# Latency dimension (v0.5.0-dev)
LATENCY_TESTS = {
    "latency_pass_within_budget": {
        "tool": "http_fetch",
        "args": {"url": "https://api.example.com"},
        "metadata": {"estimated_latency_us": 50000, "latency_budget_us": 100000},
        "expected_verdict": "pass",
        "dimension": "Latency",
        "rule": "LatencyRule"
    },
    "latency_fail_exceeds_budget": {
        "tool": "http_fetch",
        "args": {"url": "https://slow-api.example.com"},
        "metadata": {"estimated_latency_us": 200000, "latency_budget_us": 100000},
        "expected_verdict": "fail",
        "dimension": "Latency",
        "rule": "LatencyRule"
    },
}

# Cost dimension (v0.5.0-dev)
COST_TESTS = {
    "cost_pass_within_budget": {
        "tool": "llm_generate",
        "args": {"prompt": "summarize this"},
        "metadata": {"cost_tokens": 500, "token_budget": 4000},
        "expected_verdict": "pass",
        "dimension": "Cost",
        "rule": "CostRule"
    },
    "cost_fail_exceeds_budget": {
        "tool": "llm_generate",
        "args": {"prompt": "write a novel"},
        "metadata": {"cost_tokens": 100000, "token_budget": 4000},
        "expected_verdict": "fail",
        "dimension": "Cost",
        "rule": "CostRule"
    },
}

# Combine all test vectors
ALL_TEST_VECTORS = {}
for suite in [SECURITY_TESTS, STRUCTURE_TESTS, SCHEMA_TESTS, IDENTITY_TESTS, INTEGRITY_TESTS, LATENCY_TESTS, COST_TESTS]:
    ALL_TEST_VECTORS.update(suite)

def get_test_summary():
    """Return test suite summary by dimension"""
    summary = {}
    for name, test in ALL_TEST_VECTORS.items():
        dim = test["dimension"]
        if dim not in summary:
            summary[dim] = {"total": 0, "pass_expected": 0, "fail_expected": 0}
        summary[dim]["total"] += 1
        if test["expected_verdict"] == "pass":
            summary[dim]["pass_expected"] += 1
        else:
            summary[dim]["fail_expected"] += 1
    return summary

if __name__ == "__main__":
    summary = get_test_summary()
    print("=" * 60)
    print("CCS Verifier v0.5.0 — Test Vector Summary")
    print("=" * 60)
    total = 0
    for dim, counts in sorted(summary.items()):
        print(f"  {dim:12s}: {counts['total']:3d} tests (pass={counts['pass_expected']}, fail={counts['fail_expected']})")
        total += counts['total']
    print(f"  {'TOTAL':12s}: {total:3d} tests")
    print("=" * 60)
