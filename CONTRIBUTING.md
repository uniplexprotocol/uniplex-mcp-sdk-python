# Contributing to uniplex-mcp-sdk

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/mcp-server-python.git`
3. Install dependencies: `pip install -e ".[dev]"`
4. Run tests: `pytest`

## Development

### Project Structure

```
uniplex_mcp/
├── __init__.py       # Package exports
├── server.py         # MCP Server implementation
├── types.py          # Type definitions
├── transforms.py     # Financial value transforms
├── verification.py   # 9-step verification algorithm
├── cache.py          # Catalog/revocation caching
├── session.py        # Passport session management
└── cli.py            # CLI entry point

tests/
├── conftest.py       # Pytest fixtures
├── test_transforms.py
└── test_verification.py
```

### Running Tests

```bash
pytest                # Run all tests
pytest -v             # Verbose output
```

### Code Style

- Format and lint with Ruff: `ruff check . && ruff format .`
- Type check with mypy: `mypy uniplex_mcp`

## Pull Requests

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes
3. Run tests: `pytest`
4. Push and open a PR

### Commit Messages

Use conventional commits:

```
feat: add session digest support
fix: correct platform fee rounding
docs: update README examples
test: add constraint merge tests
```

## Normative Behavior

Some functions are **normative** — they must produce identical results across all SDK implementations (TypeScript, Python):

- `transform_to_canonical()` — Deterministic integer conversion
- `verify_locally()` — 9-step verification algorithm
- `compute_platform_fee()` — Ceiling rounding for fees
- Denial codes — Must match specification

Changes to normative behavior require specification updates first.

## License

MIT

---

*Standard Logic Co. — Building the trust infrastructure for AI agents*
