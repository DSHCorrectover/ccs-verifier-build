"""
CCS Runtime Verifier — Reference Implementation

Out-of-process runtime verification for AI agent commands.
Protocol specification: https://doi.org/10.5281/zenodo.21234580
"""

from ccs_verifier.protocol import Command, VerificationResult, Rule, RuleResult
from ccs_verifier.client import VerifierClient
from ccs_verifier.server import VerifierServer

__version__ = "0.1.0"
__all__ = ["Command", "VerificationResult", "Rule", "RuleResult", "VerifierClient", "VerifierServer"]
