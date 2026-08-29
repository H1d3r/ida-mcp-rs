# Tests

Integration tests for ida-mcp using a minimal `mini.c` fixture.

## Prerequisites

- `curl` (for HTTP tests)
- `jq` (for most protocol-level integration tests)
- IDA Pro 9.4 and a valid license for database-backed tests

## Build the fixture

```bash
just fixture
```

Compiles `fixtures/mini.c` to `fixtures/mini`. `just test-bootstrap` explicitly
requests auto-analysis to create `fixtures/mini.i64`; raw inputs are not
auto-analyzed by default.

## Run tests

```bash
just test       # Stdio JSONL test
just test-http  # HTTP/SSE test
just test-bootstrap # Generate fixtures/mini.i64 once via the MCP server
just test-workspace # Explicit database_id routing over stdio and HTTP
just test-rebuild-idb # Raw reuse, typed targets, and failed-open cleanup
just test-debugger # Debugger availability and status
env DEBUGGER_REQUIRE_READY=1 just test-debugger-live # Authorized macOS lifecycle
just test-tool-filter # Tool filters and availability checks
just test-script # IDAPython script test
just test-observability # Foreground progress/recent_operations test
just test-elicitation # open_idb auto-background elicitation test
```

Run the test commands above from the repository root. The top-level recipes build
`target/debug/ida-mcp` before entering this directory. `test-debugger-live`
exercises the real debugger on Apple Silicon macOS. On Windows,
`debugger_integration.ps1` confirms that unsupported debugger tools stay hidden.

## Clean

```bash
just --justfile test/justfile clean
```
