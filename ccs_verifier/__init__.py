"""
CCS Runtime Verifier — Reference Implementation

Out-of-process runtime verification for AI agent commands.
Protocol specification: https://doi.org/10.5281/zenodo.21234580
"""

from ccs_verifier.protocol import (
    Command, VerificationResult, Verdict, Rule, RuleResult, sign_receipt
)
from ccs_verifier.client import VerifierClient, Verifier
from ccs_verifier.server import VerifierServer
from ccs_verifier.builtin_rules import SSRFRule, RCERule, CredentialLeakRule

__version__ = "0.2.0"
__all__ = [
    "Command",
    "VerificationResult",
    "Verdict",
    "Rule",
    "RuleResult",
    "VerifierClient",
    "Verifier",
    "VerifierServer",
    "SSRFRule",
    "RCERule",
    "CredentialLeakRule",
    "sign_receipt",
]
