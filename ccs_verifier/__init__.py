"""
CCS Runtime Verifier — Reference Implementation

Out-of-process runtime verification for AI agent commands.
Protocol specification: https://doi.org/10.5281/zenodo.21234580

Transport options:
- Unix domain socket (default, lowest latency)
- TCP (for distributed deployments)

Usage:
    from ccs_verifier import Verifier, Command
    from ccs_verifier.builtin_rules import SSRFRule, RCERule

    # Auto-detect out-of-process server, fallback to in-process
    verifier = Verifier(rules=[SSRFRule(), RCERule()])
    cmd = Command(agent_id="a1", tool="shell", params={"command": "ls"})
    result = verifier.verify(cmd)
"""

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult, DimensionError, sign_receipt
)
from ccs_verifier.client import VerifierClient, Verifier
from ccs_verifier.server import VerifierServer
from ccs_verifier.builtin_rules import SSRFRule, RCERule, CredentialLeakRule
from ccs_verifier.transport import (
    Transport,
    TransportError,
    UnixSocketTransport,
    TCPSocketTransport,
)

__version__ = "0.4.1"
__all__ = [
    # Protocol
    "Command",
    "VerificationResult",
    "Verdict",
    "Rule",
    "RuleResult",
    "DimensionError",
    "sign_receipt",
    # Client & Server
    "VerifierClient",
    "Verifier",
    "VerifierServer",
    # Built-in rules
    "SSRFRule",
    "RCERule",
    "CredentialLeakRule",
    # Transport
    "Transport",
    "TransportError",
    "UnixSocketTransport",
    "TCPSocketTransport",
]
