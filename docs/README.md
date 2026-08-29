# Documentation

ida-mcp is a headless IDA Pro MCP server with a discovery-first tool model.

## Design

- **Default tools stay stable** - Existing clients keep the baseline schema.
  Workspace and debugger tools only appear when enabled
- **Tool discovery** - Use `tool_catalog` to find tools, `tool_help` for docs
- **Stdio and Streamable HTTP** - Both use one implicit database by default and
  support opt-in workspaces
- **One database per worker** - IDA serializes work inside each process.
  Workspace and pooled modes add child workers for additional databases

## Contents

- [TOOLS.md](TOOLS.md) - Tool catalog and discovery workflow
- [TRANSPORTS.md](TRANSPORTS.md) - Stdio vs Streamable HTTP
- [BUILDING.md](BUILDING.md) - Build from source
- [TESTING.md](TESTING.md) - Running tests
