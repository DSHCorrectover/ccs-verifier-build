"""
Built-in CCS verification rules — MCP security scanner.

5 vulnerability pattern bypass detection layers:
  1. SSRF     — scheme/host/IP encoding bypass detection
  2. RCE      — obfuscated command execution detection
  3. CredLeak — credential exfiltration pattern detection
  4. ToolPoisoning — hidden instruction injection in tool descriptions
  5. RugPull  — dynamic behavior change / post-approval mutation detection

Each rule implements semantic-aware detection, not just regex matching.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from urllib.parse import urlparse, unquote

from ccs_verifier.protocol import Command, RuleResult, Verdict, DimensionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _allow(rule_name: str, t0: float) -> RuleResult:
    latency = (time.perf_counter() - t0) * 1_000_000
    return RuleResult(rule_name=rule_name, verdict=Verdict.ALLOW, latency_us=latency)


def _deny(rule_name: str, t0: float, reason: str,
          error_code: int = DimensionError.SECURITY.value) -> RuleResult:
    latency = (time.perf_counter() - t0) * 1_000_000
    return RuleResult(
        rule_name=rule_name, verdict=Verdict.DENY,
        reason=reason, latency_us=latency, error_code=error_code,
    )


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/loopback/link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (addr.is_private or addr.is_loopback or
                addr.is_link_local or addr.is_reserved or
                addr.is_unspecified)
    except (ValueError, TypeError):
        return False


def _decode_ip_variants(host: str) -> list[str]:
    """Expand a host string into all IP representations for checking."""
    candidates = [host]
    decoded = unquote(host)
    if decoded != host:
        candidates.append(decoded)
    # Decimal IP: 2130706433 -> 127.0.0.1
    try:
        n = int(host)
        candidates.append(str(ipaddress.IPv4Address(n)))
    except (ValueError, TypeError):
        pass
    # Hex IP: 0x7f000001
    if host.startswith(("0x", "0X")):
        try:
            candidates.append(str(ipaddress.IPv4Address(int(host, 16))))
        except (ValueError, TypeError):
            pass
    # Octal IP: 0177.0.0.1
    if "." in host and any(p.startswith("0") and len(p) > 1 for p in host.split(".")):
        try:
            parts = [int(p, 8) for p in host.split(".")]
            if all(0 <= p <= 255 for p in parts):
                candidates.append(".".join(str(p) for p in parts))
        except (ValueError, TypeError):
            pass
    return candidates


# ===========================================================================
# 1. SSRF Rule — enhanced with IP encoding bypass detection
# ===========================================================================

class SSRFRule:
    """
    Detect Server-Side Request Forgery attempts.

    Bypass vectors covered:
    - Standard: file://, gopher://, dict://
    - Cloud metadata: 169.254.169.254, 100.100.100.200
    - IP encoding bypass: decimal, hex, octal
    - IPv6 loopback: ::1, [::1], ::ffff:127.0.0.1
    - DNS rebinding: @-trick
    - Private range: 10.x, 172.16.x, 192.168.x, fc00::/7
    """

    name = "ssrf_protection"
    dimension_error = DimensionError.SECURITY

    _BLOCKED_SCHEMES = frozenset({
        "file", "gopher", "dict", "ftp", "tftp",
        "jar", "netdoc", "nfs", "smb",
    })

    _BLOCKED_HOSTS = frozenset({
        "169.254.169.254",   # AWS/GCP/Azure metadata
        "100.100.100.200",   # Alibaba metadata
        "127.0.0.1", "localhost", "0.0.0.0",
        "::1", "[::1]", "[::]", "::",
        "::ffff:127.0.0.1",
        "0x7f000001",
        "2130706433",
        "0177.0.0.1",
        "metadata.google.internal",
        "metadata.internal",
    })

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        url = command.params.get("url", "") or ""
        if not url:
            return _allow(self.name, t0)

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().strip()

        if scheme in self._BLOCKED_SCHEMES:
            return _deny(self.name, t0, f"Blocked scheme: {scheme}")

        if hostname in self._BLOCKED_HOSTS:
            return _deny(self.name, t0, f"Blocked host: {hostname}")

        for variant in _decode_ip_variants(hostname):
            if variant in self._BLOCKED_HOSTS:
                return _deny(self.name, t0, f"Blocked IP variant: {variant}")
            if _is_private_ip(variant):
                return _deny(self.name, t0, f"Private/reserved IP: {variant}")

        if hostname.startswith("[") and hostname.endswith("]"):
            inner = hostname[1:-1]
            if _is_private_ip(inner):
                return _deny(self.name, t0, f"IPv6 private: {inner}")

        if parsed.netloc and "@" in parsed.netloc:
            after_at = parsed.netloc.rsplit("@", 1)[-1]
            if _is_private_ip(after_at.split(":")[0]):
                return _deny(self.name, t0, f"DNS rebinding via @: {after_at}")

        return _allow(self.name, t0)


# ===========================================================================
# 2. RCE Rule — enhanced with obfuscated execution bypass detection
# ===========================================================================

class RCERule:
    """
    Detect Remote Code Execution patterns.

    Bypass vectors covered:
    - Direct: rm -rf /, curl|bash, command substitution
    - Obfuscated: base64 decode pipes, python -c, eval/exec
    - Path traversal: ../../etc/passwd
    - Indirect: xargs, find -exec, nc reverse shells
    """

    name = "rce_protection"
    dimension_error = DimensionError.SECURITY

    _DANGEROUS_PATTERNS = [
        re.compile(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*\/"),
        re.compile(r"mkfs\.\w+\s+/dev/"),
        re.compile(r"dd\s+.*of=/dev/"),
        re.compile(r"(curl|wget|fetch)\s+.*\|\s*(bash|sh|zsh|python[23]?|perl|ruby)"),
        re.compile(r"(curl|wget)\s+.*-o\s*.*\.(sh|py|pl|rb)\b"),
        re.compile(r"\$\(|`[^`]*`"),
        re.compile(r";\s*(rm|chmod|chown|dd|mkfs)\b"),
        re.compile(r"&&\s*(rm|chmod|chown|dd|mkfs)\b"),
        re.compile(r"python[23]?\s+-c\s+['\"]"),
        re.compile(r"perl\s+-e\s+['\"]"),
        re.compile(r"ruby\s+-e\s+['\"]"),
        re.compile(r"base64\s+(-d|--decode).*\|\s*(bash|sh|python|perl)"),
        re.compile(r"(nc|ncat|netcat)\s+.*-e\s+/(bin/)?(bash|sh)"),
        re.compile(r"/dev/tcp/"),
        re.compile(r"/dev/udp/"),
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        re.compile(r"__import__\s*\("),
        re.compile(r"subprocess\.(call|run|Popen|check_output)\s*\("),
        re.compile(r"os\.system\s*\("),
        re.compile(r"os\.popen\s*\("),
        re.compile(r"find\s+.*-exec\s+"),
        re.compile(r"xargs\s+.*(-I\s+|sh\s+-c|bash\s+-c)"),
        re.compile(r"(?:\.\./){2,}"),
        re.compile(r"/etc/(passwd|shadow|hosts)"),
    ]

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        fields = [
            command.params.get("command", ""),
            command.params.get("shell", ""),
            command.params.get("script", ""),
            command.params.get("code", ""),
        ]
        cmd = " ".join(str(v) for v in fields if v)
        if not cmd:
            return _allow(self.name, t0)

        for pattern in self._DANGEROUS_PATTERNS:
            if pattern.search(cmd):
                return _deny(self.name, t0,
                             f"RCE pattern detected: {pattern.pattern[:50]}")

        return _allow(self.name, t0)


# ===========================================================================
# 3. Credential Leak Rule — enhanced with broader secret detection
# ===========================================================================

class CredentialLeakRule:
    """
    Detect attempts to exfiltrate credentials or secrets.

    Bypass vectors covered:
    - Direct: api_key=, password=, token=
    - PEM keys, cloud keys (AWS/GCP/Stripe/Slack)
    - Auth tokens: JWT, OAuth bearer, GitHub/GitLab PATs
    - Environment variable access: os.environ, process.env
    - Base64-encoded credential exfiltration
    """

    name = "credential_leak"
    dimension_error = DimensionError.SECURITY

    _SECRET_PATTERNS = [
        re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*\S+"),
        re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"ghp_[a-zA-Z0-9]{20,}"),        # GitHub classic PAT (20+)
        re.compile(r"github_pat_[a-zA-Z0-9_]{22,}"), # GitHub fine-grained PAT
        re.compile(r"AKIA[0-9A-Z]{16}"),             # AWS access key
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+"),  # JWT
        re.compile(r"AIza[a-zA-Z0-9_-]{35}"),        # Google API key
        re.compile(r"xox[baprs]-[0-9a-zA-Z-]+"),     # Slack token
        re.compile(r"(sk|pk)_(test|live)_[a-zA-Z0-9]{20,}"),  # Stripe key
        re.compile(r"os\.environ\[.?(HOME|USER|PASS|SECRET|TOKEN|KEY|CREDENTIAL)"),
        re.compile(r"process\.env\.[A-Z_]*(KEY|SECRET|TOKEN|PASS)"),
        re.compile(r"(?i)authorization\s*:\s*Bearer\s+[a-zA-Z0-9._-]+"),
    ]

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        content = str(command.params)

        for pattern in self._SECRET_PATTERNS:
            if pattern.search(content):
                return _deny(self.name, t0,
                             f"Credential pattern detected: {pattern.pattern[:40]}...")

        return _allow(self.name, t0)


# ===========================================================================
# 4. Tool Poisoning Rule — detect hidden instructions in tool descriptions
# ===========================================================================

class ToolPoisoningRule:
    """
    Detect tool poisoning attacks via hidden instructions in tool descriptions.

    Attack: Malicious MCP servers embed hidden instructions in tool descriptions
    that are invisible to users but read by LLMs, manipulating agent behavior.

    Detection vectors:
    - HTML/XML tags (style, script, hidden, iframe, etc.)
    - Unicode invisible characters (zero-width, bidi overrides)
    - Prompt injection patterns (ignore previous, override, system prompt)
    - Excessively long descriptions (>2KB)
    - Encoded/obfuscated instructions (base64 blocks)
    """

    name = "tool_poisoning"
    dimension_error = DimensionError.SECURITY

    _MAX_DESC_LENGTH = 2048

    _SUSPICIOUS_HTML_TAGS = re.compile(
        r"<\s*(style|script|hidden|iframe|object|embed|link|meta|base|form|input"
        r"|button|textarea|select|frame|frameset|svg|math|template)\b",
        re.IGNORECASE,
    )

    _INVISIBLE_CHARS = re.compile(
        "["
        "\u200b-\u200f"
        "\u2028-\u202f"
        "\u2060-\u2069"
        "\ufeff"
        "\ufff0-\ufff8"
        "\u00ad"
        "\u0600-\u0605"
        "\u061c"
        "]"
    )

    _INJECTION_PATTERNS = [
        re.compile(r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules)"),
        re.compile(r"(?i)you\s+are\s+now\s+(a|an|in)\s+"),
        re.compile(r"(?i)disregard\s+(all\s+)?(previous|prior|earlier)"),
        re.compile(r"(?i)override\s+(previous|system|safety)\b"),
        re.compile(r"(?i)new\s+instructions?\s*:"),
        re.compile(r"(?i)system\s*prompt\s*:"),
        re.compile(r"(?i)\[INST\]"),
        re.compile(r"(?i)<\|im_start\|>"),
        re.compile(r"(?i)###\s*(system|instruction)"),
    ]

    _BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        desc = (
            (command.params.get("description", "") or "") + " " +
            (command.params.get("tool_description", "") or "")
        ).strip()

        if not desc:
            return _allow(self.name, t0)

        if len(desc) > self._MAX_DESC_LENGTH:
            return _deny(self.name, t0,
                         f"Tool description too long ({len(desc)} chars, max {self._MAX_DESC_LENGTH})")

        if self._SUSPICIOUS_HTML_TAGS.search(desc):
            return _deny(self.name, t0, "Suspicious HTML tag in tool description")

        if self._INVISIBLE_CHARS.search(desc):
            return _deny(self.name, t0, "Invisible Unicode characters in tool description")

        for pattern in self._INJECTION_PATTERNS:
            if pattern.search(desc):
                return _deny(self.name, t0,
                             f"Prompt injection pattern: {pattern.pattern[:40]}")

        if self._BASE64_BLOCK.search(desc):
            return _deny(self.name, t0, "Suspicious base64 block in tool description")

        return _allow(self.name, t0)


# ===========================================================================
# 5. Rug Pull Rule — detect post-approval behavior changes
# ===========================================================================

# Metadata params that are not business parameters and should be excluded
# from new-parameter detection
_METADATA_PARAMS = frozenset({"description", "tool_description"})


class RugPullRule:
    """
    Detect rug pull attacks — dynamic behavior changes after initial approval.

    Attack: MCP server initially behaves benignly to pass security review,
    then changes tool definitions, descriptions, or behavior silently.

    Detection vectors:
    - New unapproved business parameters (excluding metadata fields)
    - Privilege escalation (read-only -> write/delete)
    - Parameter type mutation
    - Description hash change (post-approval injection)
    """

    name = "rug_pull"
    dimension_error = DimensionError.INTEGRITY

    def __init__(self):
        self._approved_schemas: dict[str, dict] = {}

    def register_approved(self, tool_name: str, schema: dict,
                          description_hash: str = "") -> None:
        """Register an approved tool schema for future comparison."""
        self._approved_schemas[tool_name] = {
            "schema": schema,
            "description_hash": description_hash,
            "registered_at": time.time(),
        }

    def evaluate(self, command: Command) -> RuleResult:
        t0 = time.perf_counter()
        tool_name = command.tool

        if tool_name not in self._approved_schemas:
            return _allow(self.name, t0)

        approved = self._approved_schemas[tool_name]
        approved_schema = approved["schema"]

        # New parameters (excluding metadata params)
        current_params = set(command.params.keys()) - _METADATA_PARAMS
        approved_params = set(approved_schema.get("params", {}).keys())
        new_params = current_params - approved_params
        if new_params:
            return RuleResult(
                rule_name=self.name, verdict=Verdict.DENY,
                reason=f"New unapproved parameters: {new_params}",
                latency_us=(time.perf_counter() - t0) * 1_000_000,
                error_code=DimensionError.INTEGRITY.value,
            )

        # Description hash change (check before privilege escalation,
        # since a changed description is a stronger signal)
        if approved["description_hash"]:
            current_desc = str(command.params.get("description", ""))
            current_hash = hashlib.sha256(current_desc.encode()).hexdigest()
            if current_hash != approved["description_hash"]:
                return RuleResult(
                    rule_name=self.name, verdict=Verdict.DENY,
                    reason="Tool description changed since approval (possible rug pull)",
                    latency_us=(time.perf_counter() - t0) * 1_000_000,
                    error_code=DimensionError.INTEGRITY.value,
                )

        # Privilege escalation
        approved_ops = set(approved_schema.get("operations", []))
        if "read" in approved_ops and "write" not in approved_ops:
            write_indicators = ["write", "create", "delete", "update", "modify",
                                "remove", "insert", "drop", "alter", "truncate"]
            if any(ind in tool_name.lower() for ind in write_indicators):
                return RuleResult(
                    rule_name=self.name, verdict=Verdict.DENY,
                    reason="Privilege escalation: read-only tool now performing write",
                    latency_us=(time.perf_counter() - t0) * 1_000_000,
                    error_code=DimensionError.INTEGRITY.value,
                )

        # Parameter type mutation
        for param_name, param_value in command.params.items():
            if param_name in _METADATA_PARAMS:
                continue
            param_def = approved_schema.get("params", {}).get(param_name, {})
            expected_type = param_def.get("type", "")
            if expected_type and not isinstance(param_value,
                                                 _type_str_to_python(expected_type)):
                return RuleResult(
                    rule_name=self.name, verdict=Verdict.DENY,
                    reason=f"Parameter type mismatch: {param_name} expected {expected_type}",
                    latency_us=(time.perf_counter() - t0) * 1_000_000,
                    error_code=DimensionError.INTEGRITY.value,
                )

        return _allow(self.name, t0)


def _type_str_to_python(type_str: str) -> type:
    mapping = {
        "string": str, "integer": int, "number": (int, float),
        "boolean": bool, "array": (list, tuple), "object": dict,
    }
    return mapping.get(type_str, object)
