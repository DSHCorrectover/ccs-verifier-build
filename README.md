# CCS Runtime Verifier — Reference Implementation

This is the **public reference implementation** of the [CCS (Command Control Standard)](https://doi.org/10.5281/zenodo.21234580) runtime verification layer.

## What is CCS?

CCS defines a standard protocol for **out-of-process runtime verification** of AI agent commands. Unlike in-process filters that share the process space they police, CCS enforces a strict process boundary between the agent and its verifier — providing a stronger trust boundary for security-critical deployments.

## Architecture

```
┌─────────────────┐       ┌──────────────────────┐
│   Agent (MCP)   │◄─────►│  CCS Verifier (OOB)  │
│                 │  gRPC  │                      │
│  - LLM calls    │       │  - Rule evaluation    │
│  - Tool invokes │       │  - Threat detection   │
│  - Data flows   │       │  - Audit logging      │
└─────────────────┘       └──────────────────────┘
     In-process                Out-of-process
```

## Why Out-of-Process?

In-process filters (e.g., asyncio-based middleware) have known limitations:
- **Shared trust boundary**: A compromised agent process compromises the filter
- **Concurrency race conditions**: `asyncio.gather()` can bypass sequential checks
- **No crash isolation**: Agent crash = verifier crash = no audit trail

CCS solves these by running the verifier in a separate process with:
- Independent lifecycle and crash isolation
- `~5-10μs` P50 verification latency (benchmark on commodity hardware)
- Formal audit trail via signed receipts

## Quick Start

```python
from ccs_verifier import VerifierClient, Command

# Connect to verifier (out-of-process)
verifier = VerifierClient(host="localhost", port=50051)

# Verify a command before execution
cmd = Command(
    agent_id="agent-001",
    tool="shell_exec",
    params={"command": "rm -rf /tmp/data"},
)

result = await verifier.verify(cmd)
if result.allowed:
    # Execute safely
    await execute(cmd)
else:
    # Blocked: reason logged with signed receipt
    log(result.block_reason)
```

## Key Interfaces

- `VerifierClient`: gRPC client for out-of-process verification
- `Command`: Standard command representation per CCS spec
- `VerificationResult`: Result with signed audit receipt
- `Rule`: Pluggable rule interface (SSRF, RCE, credential, etc.)

## Academic References

- CCS Standard v1.0: [DOI:10.5281/zenodo.21234580](https://doi.org/10.5281/zenodo.21234580)
- CCS Formal Framework: [DOI:10.5281/zenodo.21271910](https://doi.org/10.5281/zenodo.21271910)
- CCS Runtime Verification Protocol: [DOI:10.5281/zenodo.21542370](https://doi.org/10.5281/zenodo.21542370)
- MCP Security Whitepaper: [DOI:10.5281/zenodo.21405206](https://doi.org/10.5281/zenodo.21405206)

## License

MIT
