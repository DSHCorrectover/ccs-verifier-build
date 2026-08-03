"""
CCS Verifier CLI — Standalone daemon for out-of-process verification.

Usage:
    # Unix socket (default)
    python -m ccs_verifier
    
    # TCP
    python -m ccs_verifier --transport tcp --host 0.0.0.0 --port 50051
    
    # Custom socket path
    python -m ccs_verifier --socket /var/run/ccs-verifier.sock
    
    # With specific rules
    python -m ccs_verifier --rules ssrf,rce,credential_leak
    
    # With signing key from environment
    CCS_SIGNING_KEY=$(cat /etc/ccs/signing.key) python -m ccs_verifier
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

from ccs_verifier.server import VerifierServer
from ccs_verifier.builtin_rules import SSRFRule, RCERule, CredentialLeakRule
from ccs_verifier.transport.unix_socket import UnixSocketTransport
from ccs_verifier.transport.tcp_socket import TCPSocketTransport


RULE_REGISTRY = {
    "ssrf": SSRFRule,
    "rce": RCERule,
    "credential_leak": CredentialLeakRule,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ccs-verifier",
        description="CCS Runtime Verifier — Out-of-process verification daemon",
    )
    parser.add_argument(
        "--transport",
        choices=["unix", "tcp"],
        default="unix",
        help="Transport type (default: unix)",
    )
    parser.add_argument(
        "--socket",
        default="/tmp/ccs-verifier.sock",
        help="Unix socket path (default: /tmp/ccs-verifier.sock)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="TCP bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=50051,
        help="TCP bind port (default: 50051)",
    )
    parser.add_argument(
        "--rules",
        default="ssrf,rce,credential_leak",
        help="Comma-separated rules to load (default: ssrf,rce,credential_leak)",
    )
    parser.add_argument(
        "--signing-key",
        default=None,
        help="HMAC signing key (hex string). Falls back to CCS_SIGNING_KEY env var",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ccs-verifier 0.4.0",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("ccs_verifier")

    # Resolve rules
    rule_names = [r.strip() for r in args.rules.split(",")]
    rules = []
    for name in rule_names:
        if name in RULE_REGISTRY:
            rules.append(RULE_REGISTRY[name]())
        else:
            logger.error(f"Unknown rule: {name}. Available: {list(RULE_REGISTRY.keys())}")
            sys.exit(1)

    # Resolve signing key
    signing_key = None
    if args.signing_key:
        signing_key = bytes.fromhex(args.signing_key)
    elif os.environ.get("CCS_SIGNING_KEY"):
        signing_key = bytes.fromhex(os.environ["CCS_SIGNING_KEY"])

    # Create transport
    if args.transport == "unix":
        transport = UnixSocketTransport(socket_path=args.socket)
    else:
        transport = TCPSocketTransport(host=args.host, port=args.port)

    # Create and start server
    server = VerifierServer(rules=rules, signing_key=signing_key)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Handle signals
    def shutdown(sig, frame):
        logger.info("Shutting down...")
        loop.create_task(server.stop())

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    async def run() -> None:
        await server.start(transport=transport)
        logger.info(
            f"CCS Verifier v0.4.0 listening on {transport.describe()} "
            f"with rules: {[r.name for r in rules]}"
        )
        await server.serve_forever()

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        logger.info("Interrupted, shutting down...")
    finally:
        loop.run_until_complete(server.stop())
        loop.close()


if __name__ == "__main__":
    main()
