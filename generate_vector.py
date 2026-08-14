import time
import json
from ccs_verifier.server import VerifierServer, VERSION
from ccs_verifier.protocol import Command, Verdict
from ccs_verifier.builtin_rules import SSRFRule
from ccs_verifier.ccs_verifier_l1 import generate_ed25519_key

# Generate L1 signing key
private_key = generate_ed25519_key()

# Create server with L1 mode enabled
server = VerifierServer(rules=[SSRFRule()], l1_signing_key=private_key)

# Create a test command
cmd = Command(
    agent_id="agent-test-001",
    tool="shell_exec",
    params={"command": "echo hello"},
    timestamp=time.time(),
    trace_id="trace-canonical-001"
)

# Run verification
import asyncio
result = asyncio.run(server.verify(cmd))

# Extract L1 receipt
l1_receipt = getattr(result, 'l1_receipt', None)

# Output canonical vector
vector = {
    "version": VERSION,
    "timestamp": time.time(),
    "command": {
        "agent_id": cmd.agent_id,
        "tool": cmd.tool,
        "params": cmd.params,
        "timestamp": cmd.timestamp,
        "trace_id": cmd.trace_id
    },
    "result": {
        "verdict": result.verdict.value,
        "verified_at": result.verified_at,
        "block_reason": result.block_reason,
    },
    "l1_receipt": l1_receipt
}

print(json.dumps(vector, indent=2))
