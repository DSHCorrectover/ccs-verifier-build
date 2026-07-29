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

### Deployment Modes

**In-Process (Recommended for most use cases):**
Use the `Verifier` class for immediate, synchronous verification. This is the simplest way to add CCS protection to your agent.

**Out-of-Process (Advanced):**
Use `VerifierClient` + `VerifierServer` for a separate verifier process with full isolation. This provides stronger security guarantees (verifier survives agent crashes, independent memory space). Note: gRPC transport is currently a stub and will be implemented in a future release.

## Quick Start

```python
from ccs_verifier import Verifier, Command
from ccs_verifier import SSRFRule, RCERule, CredentialLeakRule

# Create verifier with built-in rules
verifier = Verifier(rules=[SSRFRule(), RCERule(), CredentialLeakRule()])

# Verify a command before execution
cmd = Command(
    agent_id="agent-001",
    tool="shell_exec",
    params={"command": "rm -rf /tmp/data"},
)

result = verifier.verify(cmd)
if result.allowed:
    # Command is safe, proceed with execution
    await execute(cmd)
else:
    # Command blocked: reason logged with signed receipt
    print(f"Blocked: {result.block_reason}")
    print(f"Receipt: {result.receipt}")  # Tamper-evident audit record
```

## Built-in Rules

The package includes three built-in security rules:

- **SSRFRule**: Blocks requests to dangerous URL schemes (file://, gopher://, dict://) and blocked hosts (cloud metadata endpoints, localhost).
- **RCERule**: Detects dangerous shell patterns (rm -rf /, piped commands, command substitution).
- **CredentialLeakRule**: Detects attempts to exfiltrate secrets (API keys, private keys, tokens).

## Custom Rules

Implement the `Rule` protocol to create custom verification rules:

```python
from ccs_verifier import Rule, Command, RuleResult, Verdict

class MyCustomRule:
    name = "my_custom_rule"

    def evaluate(self, command: Command) -> RuleResult:
        # Your custom logic here
        if is_dangerous(command):
            return RuleResult(
                rule_name=self.name,
                verdict=Verdict.DENY,
                reason="Custom rule triggered",
            )
        return RuleResult(rule_name=self.name, verdict=Verdict.ALLOW)
```

## Verification Result

Each verification returns a `VerificationResult` with:

- `verdict`: ALLOW, DENY, or ESCALATE
- `block_reason`: Human-readable reason if blocked
- `rule_results`: Detailed results from each rule evaluation
- `receipt`: HMAC-SHA256 signed audit receipt covering trace_id, verdict, timestamp, tool, params hash, and rule summary
- `verified_at`: Unix timestamp of verification

The receipt provides a tamper-evident audit trail, ensuring verification results cannot be modified after the fact.

## Audit Log

The verifier maintains an in-process audit log of all verifications:

```python
for entry in verifier.audit_log:
    print(f"{entry.trace_id}: {entry.verdict.value} at {entry.verified_at}")
```

## Async API

For async applications, use `averify()`:

```python
result = await verifier.averify(cmd)
```

## Key Interfaces

- `Verifier`: High-level synchronous/asynchronous verifier (recommended)
- `VerifierClient`: Client for out-of-process verification (requires running server)
- `VerifierServer`: Server for out-of-process verification
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
