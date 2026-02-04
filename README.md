# uniplex-mcp-sdk

Permission-aware MCP server SDK for AI agent tool execution. Enables AI agents (Claude, ChatGPT, custom agents) to discover, request, and use permissions through Uniplex-protected tools.

## Installation

```bash
pip install uniplex-mcp-sdk
```

## Quick Start

```python
from uniplex_mcp import UniplexMCPServer, define_tool

# Define your tool
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
    # Your API call here
    return {'flights': []}

# Create and run server
server = UniplexMCPServer(
    gate_id='gate_acme-travel',
    tools=[search_flights],
    test_mode=True  # Use mock data for development
)

server.start()
```

## Features

- **Permission Verification** — Every tool call verified against agent passports
- **Constraint Enforcement** — Rate limits, cost caps, and custom constraints
- **Local-First** — Hot path verification with no network calls (<1ms)
- **Attestation Logging** — Cryptographic audit trail for every action
- **Commerce Support** — Consumption attestations, billing, and service discovery

## Commerce (Uni-Commerce Profile)

Enable metered billing for your tools with consumption attestations:

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

# Platform fee uses ceiling rounding
compute_platform_fee(1000, 200)  # 2% of $10 = 20 cents
compute_platform_fee(101, 200)   # 2% of $1.01 = 3 cents (ceiling)
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

### Enable Commerce in Server

```python
server = UniplexMCPServer(
    gate_id='gate_weather-api',
    tools=[forecast_tool],
    commerce_enabled=True,
    issue_receipts=True  # Auto-issue consumption attestations
)
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `UNIPLEX_GATE_ID` | Yes | Your gate identifier |
| `UNIPLEX_API_URL` | No | API URL (default: https://api.uniplex.ai) |

### Server Options

```python
server = UniplexMCPServer(
    gate_id='gate_acme-travel',
    tools=[search_flights, book_flight],
    
    # Optional
    test_mode=True,              # Mock passports for development
    cache_config={
        'catalog_ttl_ms': 300000,     # 5 minutes
        'revocation_ttl_ms': 60000    # 1 minute
    }
)
```

## Adding Constraints

Tools can enforce constraints like cost limits:

```python
book_flight = (
    define_tool()
    .name('book_flight')
    .permission('flights:book')
    .risk_level('high')
    .constraint({
        'key': 'core:cost:max',
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
    # Book the flight
    return {'confirmation': 'ABC123'}
```

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

## API Reference

### `define_tool()`

Fluent builder for tool definitions:

```python
(
    define_tool()
    .name(str)                     # Tool name
    .permission(str)               # Permission key (e.g., 'flights:book')
    .risk_level('low'|'medium'|'high'|'critical')
    .schema(dict)                  # Input schema (JSON Schema)
    .constraint(dict)              # Add constraint
    .handler(async_func)           # Tool implementation
    .build()                       # Returns ToolDefinition
)
```

### `UniplexMCPServer`

```python
server = UniplexMCPServer(config)

server.start()                     # Start stdio transport
server.register_tool(tool)         # Add tool at runtime
```

### `transform_to_canonical()`

Convert financial values to integers:

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

## Testing

```bash
pytest
```

## License

Apache 2.0

---

*Standard Logic Co. — Building the trust infrastructure for AI agents*
