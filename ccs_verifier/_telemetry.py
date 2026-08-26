"""
Correctover Privacy-Preserving Telemetry.

Sends ONE anonymous HTTPS ping per CLI invocation. No file contents,
no trace data, no PII — only coarse counters so we know which rules fire.

Set CORRECTOVER_NO_TELEMETRY=1 to disable.
Enterprise license keys automatically disable telemetry.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
import urllib.request
import urllib.error

_ENDPOINT = "https://api.correctover.com/v1/telemetry/ping"
_TIMEOUT = 1.5  # never block the CLI


def _disabled() -> bool:
    if os.environ.get("CORRECTOVER_NO_TELEMETRY", "").strip() in ("1", "true", "yes"):
        return True
    # Enterprise users: no telemetry
    try:
        from ccs_verifier.license_gate import is_licensed
        if is_licensed():
            return True
    except Exception:
        pass
    return False


def _anonymous_id() -> str:
    """Stable per-machine anonymous ID, not reversible to identity."""
    raw = f"{platform.node()}:{platform.machine()}:{os.getuid() if hasattr(os, 'getuid') else 0}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def ping(event: str, **fields) -> None:
    """Fire-and-forget telemetry ping. Never raises, never blocks."""
    if _disabled():
        return
    try:
        payload = {
            "event": event,
            "anon_id": _anonymous_id(),
            "version": _version(),
            "python": platform.python_version(),
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "ts": int(time.time()),
        }
        payload.update(fields)
        data = json.dumps(payload, separators=(",", ":")).encode()
        req = urllib.request.Request(
            _ENDPOINT, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=_TIMEOUT).read()
    except Exception:
        pass  # telemetry must never interfere with the tool


def _version() -> str:
    try:
        from ccs_verifier import __version__
        return __version__
    except Exception:
        return "unknown"
