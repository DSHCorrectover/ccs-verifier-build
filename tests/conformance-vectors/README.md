# Conformance Test Vectors

This directory contains 17 conformance test vectors for CCS Verifier L0 and L1 receipt verification.

## Structure

Each test vector is a JSON file with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique test case identifier (e.g., `L0-001`, `L1-003`, `TAMPER-002`) |
| `category` | string | Test category (see below) |
| `description` | string | Human-readable description of what the test validates |
| `input` | object | Input data for the test case |
| `expected_output` | object | Expected verification result |

## Categories

| Category | Count | Description |
|----------|-------|-------------|
| `L0_basic_receipt` | 2 | L0 HMAC-SHA256 receipt: valid and tampered |
| `L1_ed25519_receipt` | 2 | L1 Ed25519 receipt: allow and deny verdicts (valid) |
| `L1_ed25519_receipt_fail` | 3 | L1 receipt with tampered fields (verdict, trace_id, request_hash) |
| `tamper_detection` | 3 | Tamper detection: action, nonce, public_key modifications |
| `anti_replay` | 3 | Anti-replay: unique nonce, expired receipt, clock skew tolerance |
| `caid_action_mapping` | 4 | CAID action mapping: exact, MCP prefix, heuristic, fallback |

## Running

```python
import json
from ccs_verifier_l1 import Ed25519Signer, L1ReceiptBuilder, DeploymentMode, verify_l1_receipt, map_tool_to_action, sign_receipt_l0

# Load a test vector
with open("tests/conformance-vectors/l1-001.json") as f:
    vector = json.load(f)

# Execute against the module and compare with expected_output
```
