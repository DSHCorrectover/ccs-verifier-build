"""
Built-in CCS verification rules.

These are reference implementations of common security rules.
Production deployments should extend these with domain-specific rules.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from ccs_verifier.protocol import Command, RuleResult, Verdict, DimensionError


class SSRFRule:
    """Detect Server-Side Request Forgery attempts."""

    name = "ssrf_protection"
    dimension_error = DimensionError.SECURITY  # explicit dimension declaration

    _BLOCKED_SCHEMES = {"file", "gopher", "dict"}
    _BLOCKED_HOSTS = {
        "169.254.169.254",  # AWS/GCP metadata
        "100.100.100.200",  # Alibaba metadata
        "127.0.0.1", "localhost", "0.0.0.0",
    }

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        url = command.params.get("url", "") or ""
        parsed = urlparse(url)

        if parsed.scheme.lower() in self._BLOCKED_SCHEMES:
            return RuleResult(
                rule_name=self.name,
                verdict=Verdict.DENY,
                reason=f"Blocked scheme: {parsed.scheme}",
                error_code=self.dimension_error.value,
            )

        if parsed.hostname and parsed.hostname.lower() in self._BLOCKED_HOSTS:
            return RuleResult(
                rule_name=self.name,
                verdict=Verdict.DENY,
                reason=f"Blocked host: {parsed.hostname}",
                error_code=self.dimension_error.value,
            )

        latency = (time.perf_counter() - t0) * 1_000_000
        return RuleResult(rule_name=self.name, verdict=Verdict.ALLOW, latency_us=latency)


class RCERule:
    """Detect Remote Code Execution patterns in shell commands."""

    name = "rce_protection"
    dimension_error = DimensionError.SECURITY  # explicit dimension declaration

    _DANGEROUS_PATTERNS = [
        re.compile(r"(rm\s+-rf\s+/)"),
        re.compile(r"(curl|wget)\s*.*\|\s*(bash|sh|python)"),
        re.compile(r";\s*(rm|chmod|chown|dd)\s"),
        re.compile(r"\$\(|`"),  # Command substitution
    ]

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        cmd = command.params.get("command", "") or ""

        for pattern in self._DANGEROUS_PATTERNS:
            if pattern.search(cmd):
                latency = (time.perf_counter() - t0) * 1_000_000
                return RuleResult(
                    rule_name=self.name,
                    verdict=Verdict.DENY,
                    reason=f"RCE pattern detected: {pattern.pattern}",
                    latency_us=latency,
                    error_code=self.dimension_error.value,
                )

        latency = (time.perf_counter() - t0) * 1_000_000
        return RuleResult(rule_name=self.name, verdict=Verdict.ALLOW, latency_us=latency)


class CredentialLeakRule:
    """Detect attempts to exfiltrate credentials or secrets."""

    name = "credential_leak"
    dimension_error = DimensionError.SECURITY  # explicit dimension declaration

    _SECRET_PATTERNS = [
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]"),
        re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI-style keys
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),   # GitHub PATs
    ]

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        content = str(command.params)

        for pattern in self._SECRET_PATTERNS:
            if pattern.search(content):
                latency = (time.perf_counter() - t0) * 1_000_000
                return RuleResult(
                    rule_name=self.name,
                    verdict=Verdict.DENY,
                    reason=f"Credential pattern detected: {pattern.pattern[:30]}...",
                    latency_us=latency,
                    error_code=self.dimension_error.value,
                )

        latency = (time.perf_counter() - t0) * 1_000_000
        return RuleResult(rule_name=self.name, verdict=Verdict.ALLOW, latency_us=latency)
