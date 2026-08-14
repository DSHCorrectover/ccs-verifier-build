"""
CCS Runtime Verifier — Reference Implementation (v1.1.2)

Out-of-process runtime verification for AI agent commands.
Protocol specification: https://doi.org/10.5281/zenodo.21234580

Receipt levels:
- L0: HMAC-SHA256 receipt (6 fields, backward compatible)
- L1: Ed25519 signed receipt (29 fields, CAID-compatible)

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

    # L1 Ed25519 receipt
    from ccs_verifier.ccs_verifier_l1 import generate_ed25519_key, L1Receipt
    private_key = generate_ed25519_key()
    server = VerifierServer(rules=[SSRFRule()], l1_signing_key=private_key)
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
from ccs_verifier.ccs_verifier_l1 import (
    L1Receipt,
    L1ReceiptBuilder,
    RECEIPT_VERSION,
    SIGNING_ALGORITHM,
    generate_ed25519_key,
    get_public_key,
    public_key_fingerprint,
    sign_l1_receipt,
    verify_l1_receipt,
    compute_hash,
    compute_args_digest,
    compute_request_hash,
    compute_response_hash,
    canonical_json,
)

__version__ = "1.1.7"
__all__ = [
    # Protocol (L0)
    "Command",
    "VerificationResult",
    "Verdict",
    "Rule",
    "RuleResult",
    "DimensionError",
    "sign_receipt",
    # L1 Receipt
    "L1Receipt",
    "L1ReceiptBuilder",
    "RECEIPT_VERSION",
    "SIGNING_ALGORITHM",
    "generate_ed25519_key",
    "get_public_key",
    "public_key_fingerprint",
    "sign_l1_receipt",
    "verify_l1_receipt",
    "compute_hash",
    "compute_args_digest",
    "compute_request_hash",
    "compute_response_hash",
    "canonical_json",
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
