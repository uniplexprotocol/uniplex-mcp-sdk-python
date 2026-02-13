# uniplex-mcp-sdk

<!-- mcp-name: io.github.uniplexprotocol/sdk -->

[![PyPI version](https://img.shields.io/pypi/v/uniplex-mcp-sdk)](https://pypi.org/project/uniplex-mcp-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

**Protect your MCP server with Uniplex.** Add permission verification, constraint enforcement, and a cryptographic audit trail to any tool — in a few lines of code.

Every tool call is checked against the calling agent's passport. Unauthorized requests are denied before your handler ever runs.

---

## What is Uniplex?

[Uniplex](https://uniplex.ai) is an open protocol that adds a lightweight trust layer for the agentic web. It has two sides:

**Gates** protect your tools, APIs, and MCP servers. A Gate is a verification checkpoint — you define a permission catalog of what's allowed, and incoming agent requests are checked against it locally, with no network round-trip. Every decision produces a signed attestation for a tamper-evident audit trail.

**Passports** are signed credentials that agents carry. Each passport specifies who issued it, what the agent is allowed to do, and under what constraints — scoped to specific actions, resources, and time windows.

This SDK lets you add a Gate to your MCP server. You define tools, declare the permissions they require, and the SDK handles verification, constraint enforcement, and attestation logging automatically.

→ [Protocol specification](https://github.com/uniplexprotocol/uniplex) · [Documentation](https://uniplex.ai) · [Management MCP server](https://github.com/uniplexprotocol/uniplex-mcp-manage)

---

## Installation

```bash
pip install uniplex-mcp-sdk
```

Requires the [`uniplex`](https://pypi.org/project/uniplex/) protocol SDK (v1.2.1+), installed automatically as a dependency.

---

## Quick Start

```python
from uniplex_mcp import UniplexMCPServer, define_tool

# Define a tool with a required permission
search_flights = (
    define_tool()
    .name('search_flights')
    .permission('flights:search')
    .schema({
        'type': 'object',
        'properties': {
            'origin': {'type': 'string'},
            'destination': {'type': 'string'},
            'date': {'type': 'string', 'format': 'date'}
        },
        'required': ['origin', 'destination', 'date']
    })
    .handler(search_flights_handler)
    .build()
)

async def search_flights_handler(input):
    # Your logic here — only runs if the agent's passport allows flights:search
    return {'flights': []}

# Create and start the server
server = UniplexMCPServer(
    gate_id='gate_acme-travel',
    tools=[search_flights],
    test_mode=True  # Use mock passports for development
)

server.start()
```

That's it. Any agent calling `search_flights` must carry a valid passport with the `flights:search` permission. No valid passport, no execution.

---

## How It Works

1. **Agent calls a tool** — the request includes a passport (signed credential)
2. **Gate checks the passport** — signature valid? Permission granted? Constraints met? Not expired or revoked?
3. **If allowed** — your handler runs, and an attestation is logged
4. **If denied** — the request is rejected before your code executes

All verification happens locally in the request flow. No network calls in the hot path. Sub-millisecond overhead.

---

## Features

### Permission Verification

Every tool declares the permission it requires. The SDK checks the agent's passport against your gate's permission catalog automatically.

```python
book_flight = (
    define_tool()
    .name('book_flight')
    .permission('flights:book')
    .risk_level('high')
    # ...
)
```

### Constraint Enforcement

Go beyond simple allow/deny. Enforce cost limits, rate limits, and custom constraints that are checked against values in the passport:

```python
book_flight = (
    define_tool()
    .name('book_flight')
    .permission('flights:book')
    .risk_level('high')
    .constraint({
        'key': 'core:cost:max_per_action',
        'source': 'input',
        'input_path': '$.price',
        'transform': 'dollars_to_cents'
    })
    .schema({
        'type': 'object',
        'properties': {
            'flight_id': {'type': 'string'},
            'price': {'type': 'string'}  # Use string for financial values
        },
        'required': ['flight_id', 'price']
    })
    .handler(book_flight_handler)
    .build()
)

async def book_flight_handler(input):
    return {'confirmation': 'ABC123'}
```

### Three-Tier Decision Model

Constraint evaluation produces one of three decisions:

| Decision | Wire | Meaning |
|----------|------|---------|
| **PERMIT** | `"permit"` | All constraints satisfied — handler runs |
| **SUSPEND** | `"deny"` | Soft denial — agent can request approval (`obligations: ["require_approval"]`) |
| **BLOCK** | `"deny"` | Hard denial — constraint violated, no recourse |

```python
result = verify_locally(request)

if result.decision == 'permit':
    # handler runs
elif result.constraint_decision == 'SUSPEND':
    # soft denial — check result.obligations and result.reason_codes
else:
    # hard block — check result.denial
```

### CEL Constraint Evaluation

Constraints are evaluated using a CEL (Common Expression Language) engine from the [`uniplex`](https://pypi.org/project/uniplex/) protocol SDK. The SDK re-exports the evaluation functions:

```python
from uniplex_mcp import evaluate_constraints, CumulativeStateTracker

tracker = CumulativeStateTracker()
result = evaluate_constraints(passport, catalog, action, context, tracker)
# result.decision: 'PERMIT' | 'BLOCK' | 'SUSPEND'
```

### Anonymous Access

Gates can define an anonymous access policy for unauthenticated requests with rate limiting:

```python
from uniplex_mcp import evaluate_anonymous_access, MemoryAnonymousRateLimiter

limiter = MemoryAnonymousRateLimiter()
decision = evaluate_anonymous_access(policy, action, client_id, limiter)
# decision.allowed, decision.reason
```

### Attestation Logging

Every gate decision — allowed or denied — produces a signed attestation. This gives you a tamper-evident audit trail of every agent action across your tools.

### Local-First Verification

Passport verification runs locally in the request flow. No network calls on the hot path. Designed for sub-millisecond overhead.

---

## Commerce

Enable metered billing for your tools with consumption attestations. When an agent uses a paid tool, the gate issues a cryptographic receipt that both sides can verify.

### Enable Commerce

```python
server = UniplexMCPServer(
    gate_id='gate_weather-api',
    tools=[forecast_tool],
    commerce_enabled=True,
    issue_receipts=True  # Auto-issue consumption attestations
)
```

### Issue and Verify Receipts

```python
from uniplex_mcp import (
    issue_consumption_attestation,
    verify_consumption_attestation,
    generate_request_nonce,
    aggregate_attestations,
    compute_platform_fee
)

# Gate issues receipt after tool execution
receipt = await issue_consumption_attestation(
    gate_id='gate_weather-api',
    agent_id='agent_travel-planner',
    passport_id='passport_123',
    permission_key='weather:forecast',
    catalog_version=1,
    effective_constraints={
        'core:pricing:per_call_cents': 10,
        'core:pricing:currency': 'USD',
        'core:platform_fee:basis_points': 200  # 2%
    },
    sign=sign_with_gate_key,
    signing_key_id='gate_weather-api#key-1'
)

# Agent verifies receipt
nonce = generate_request_nonce('agent_travel-planner')
verification = await verify_consumption_attestation(
    attestation=receipt,
    expected_nonce=nonce.nonce,
    gate_public_key=gate_public_key,
    verify=verify_signature
)

# Aggregate for billing
billing = aggregate_attestations(receipts, '2026-02-01', '2026-02-28')
# → BillingPeriod(total_calls=150, total_cost_cents=1500, total_platform_fee_cents=30)
```

### Commerce Types

```python
from uniplex_mcp import (
    ConsumptionAttestation,  # Receipt after tool execution
    ConsumptionData,         # Units, cost, timestamp
    PricingConstraints,      # per_call_cents, per_minute_cents, currency
    SLAConstraints,          # uptime_basis_points, response_time_ms
    PlatformFeeConstraints,  # basis_points, recipient
    BillingPeriod,           # Aggregated settlement
    RequestNonce,            # For bilateral verification
    DiscoveryQuery,          # Find services by price/capability
    DiscoveryResult          # Matching gates
)
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `UNIPLEX_GATE_ID` | Yes | Your gate identifier |
| `UNIPLEX_API_URL` | No | API URL (default: `https://uniplex.ai`) |

### Server Options

```python
server = UniplexMCPServer(
    gate_id='gate_acme-travel',
    tools=[search_flights, book_flight],

    test_mode=True,              # Mock passports for development
    cache_config={
        'catalog_ttl_ms': 300000,     # 5 minutes
        'revocation_ttl_ms': 60000    # 1 minute
    }
)
```

---

## Claude Desktop Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "travel": {
      "command": "uniplex-mcp-sdk",
      "args": ["--gate-id", "gate_acme-travel"],
      "env": {
        "UNIPLEX_GATE_ID": "gate_acme-travel"
      }
    }
  }
}
```

---

## API Reference

### `define_tool()`

Fluent builder for tool definitions:

```python
(
    define_tool()
    .name(str)                                   # Tool name
    .permission(str)                             # Required permission (e.g., 'flights:book')
    .risk_level('low' | 'medium' | 'high' | 'critical')
    .schema(dict)                                # Input schema (JSON Schema)
    .constraint(dict)                            # Add constraint enforcement
    .handler(async_func)                         # Tool implementation
    .build()                                     # Returns ToolDefinition
)
```

### `UniplexMCPServer`

```python
server = UniplexMCPServer(config)

server.start()                # Start stdio transport
server.register_tool(tool)    # Add tool at runtime
```

### `VerifyResult`

The result of local passport verification:

```python
class VerifyResult:
    allowed: bool                                   # True when decision is "permit"
    decision: Literal['permit', 'deny']             # Wire-level decision
    constraint_decision: ConstraintDecision | None   # 'PERMIT' | 'BLOCK' | 'SUSPEND'
    reason_codes: list[str] | None                  # e.g., ["approval_required"]
    obligations: list[str] | None                   # e.g., ["require_approval"]
    denial: Denial | None                           # Denial details (code + message)
    effective_constraints: dict | None
    confident: bool                                 # True if cache was fresh
```

### Financial Utilities

```python
from uniplex_mcp import transform_to_canonical, dollars_to_cents

transform_to_canonical('4.99', 2)             # → 499
transform_to_canonical('1.005', 2, 'round')   # → 101
dollars_to_cents('19.99')                     # → 1999
```

### Commerce Functions

```python
from uniplex_mcp import (
    issue_consumption_attestation,   # Gate issues receipt
    verify_consumption_attestation,  # Agent verifies receipt
    generate_request_nonce,          # Create nonce for bilateral verification
    aggregate_attestations,          # Sum receipts for billing period
    compute_platform_fee,            # Calculate fee (ceiling rounding)
    compute_call_cost,               # Cost for per-call pricing
    compute_time_cost,               # Cost for per-minute pricing
    matches_discovery_criteria,      # Check if service matches price/currency
    meets_sla_requirements           # Check if service meets uptime/latency
)
```

---

## Testing

```bash
pytest
```

Use `test_mode=True` in your server config to run with mock passports during development — no real gate or issuer needed.

---

## Learn More

- [Uniplex Protocol Specification](https://github.com/uniplexprotocol/uniplex)
- [Documentation & Guides](https://uniplex.ai)
- [Management MCP Server (TypeScript)](https://www.npmjs.com/package/uniplex-mcp-manage) · [Management SDK (Python)](https://pypi.org/project/uniplex-mcp-manage/)
- [Protocol SDK (TypeScript)](https://www.npmjs.com/package/uniplex) · [Protocol SDK (Python)](https://pypi.org/project/uniplex/)
- [Discussions](https://github.com/uniplexprotocol/uniplex/discussions) — Questions and ideas
- [@uniplexprotocol](https://x.com/uniplexprotocol) — Updates and announcements

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)

Building the trust infrastructure for AI agents.
