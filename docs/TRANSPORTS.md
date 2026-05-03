# Transports

## Stdio (default)

- Single-client, simplest setup.
- Use with CLI agents that launch a child process.

```bash
./target/release/ida-mcp
```

### Progress observability

The server does not emit MCP `notifications/progress` messages. On stdio they
race with the response on fast tools (under ~100 ms): Node-based clients
(e.g. Claude Code) deliver coalesced messages in a single `data` event and
process the response — which retires the `progressToken` — before the
notification handlers run, dropping the transport with "unknown progress
token". Phase progress is recorded server-side instead and surfaced via the
`recent_operations` tool. Long-running work (e.g. `analyze_funcs`) should be
launched through the task system (`enqueue_task` + poll `task_status`).

## Streamable HTTP (multi-client)

- Supports multiple clients over HTTP.
- SSE is used for streaming responses within this transport.
- The server validates `Origin` and `Host` headers. IP-literal `Host` values
  that are reachable through the bind address are accepted automatically; DNS
  names must be added with `--allow-host`.

```bash
./target/release/ida-mcp serve-http --bind 127.0.0.1:8765
# Exposing on a LAN by IP address
./target/release/ida-mcp serve-http \
  --bind 0.0.0.0:8765 \
  --allow-origin http://10.0.0.5:8765

# Exposing on a LAN by DNS name
./target/release/ida-mcp serve-http \
  --bind 0.0.0.0:8765 \
  --allow-host ida-box.local \
  --allow-origin http://ida-box.local:8765
```

Options:
- `--stateless`: POST-only mode (no sessions)
- `--allow-origin`: comma-separated `Origin` allowlist (default: `http://localhost,http://127.0.0.1`)
- `--allow-host`: comma-separated extra `Host` allowlist for DNS names or
  alternate authorities; pass a quoted `*` or an empty value to disable the check
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)
- `--session-keep-alive-secs`: HTTP session inactivity timeout (default: 1800; 0 disables)

## Concurrency model

IDA requires main-thread access. All IDA operations are serialized through a single
worker loop, while multiple clients can submit requests concurrently.

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT and will close the open database
before exiting when possible.
