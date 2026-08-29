# Testing

## Run tests

```bash
just check        # Format, Clippy, and unit tests
just test         # Stdio JSONL integration test
just test-http    # HTTP/SSE integration test
just test-modern  # MCP 2026 discover/stateless lifecycle test
just test-workspace # Explicit database_id routing over stdio and HTTP
just test-rebuild-idb # Raw reuse, idb_out, typed targets, and cleanup
just test-debugger # Debugger advertisement and readiness gates
env DEBUGGER_REQUIRE_READY=1 just test-debugger-live # Authorized macOS live lifecycle
just test-tool-filter # Toolsets, explicit tools, exclusions, and read-only mode
just test-script  # IDAPython script execution test
just test-elicitation # open_idb auto-background elicitation test
just test-session-cancel # legacy-session cancel-on-disconnect test
just test-http-startup # HTTP bind-failure exit status (no IDA license needed)
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
```

Most database-backed integration tests require IDA Pro with a valid license.
`just test-http-startup` does not open IDA, and `just test-debugger` checks
readiness without launching a target. Every top-level `just test-*` recipe
builds the debug binary before running its harness.

## What's tested

**Stdio test** (`just test`)
- MCP protocol handshake
- Tool discovery (`tool_catalog`, `tool_help`)
- Database operations (`open_idb`, `close_idb`, `idb_meta`, `analysis_status`)
- Analysis tools (`list_functions`, `resolve_function`, `disasm_by_name`, `find_insns`, `find_insn_operands`)
- Editing tools (`set_comments`, `rename`, `patch`, `patch_asm`)
- Types/stack tools (`declare_type`, `apply_types`, `infer_types`, `stack_frame`, `declare_stack`, `delete_stack`)
- Metadata tools (`segments`, `strings`, `imports`, `exports`, `structs`, `xrefs_to_field`, `search_structs`)

**HTTP test** (`just test-http`)
- Streamable HTTP transport with SSE
- `tools/list` returns the full tool list
- Database operations work over HTTP (`open_idb`, `list_functions`, `close_idb` with close_token)

**MCP 2026 test** (`just test-modern`)
- Exercises `server/discover`, `tools/list`, and `tools/call` over stdio
- Rejects MCP 2026 requests with incomplete required request metadata
- Exercises the same lifecycle over sessionless single-worker HTTP and verifies
  that no legacy session ID is created
- Verifies a legacy stdio task remains visible on the same connection when one
  request carries full routing metadata and the next omits it
- Verifies pooled HTTP advertises versions only through `2025-11-25`, rejects
  a `2026-07-28` request, and rejects sessionless inline-metadata tool calls
  that declare a legacy version

**Workspace test** (`just test-workspace`)
- Verifies that allocation tools return distinct UUID `database_id` handles and
  every database-scoped schema/help example requires one
- Keeps mutations isolated to the selected database and invalidates only the
  handle passed to `close_idb`
- Exercises `list_databases`, IDA-style range rendering, directional/truncated
  callgraphs, paginated patch records, and explicit raw output routing
- Repeats explicit-handle routing over stateless HTTP

**Raw rebuild/provenance test** (`just test-rebuild-idb`)
- Verifies default reuse and explicit `rebuild=true` replacement semantics
- Requires SHA-256 or recorded-path provenance before adopting or replacing an
  existing output
- Covers `idb_out` beside read-only inputs, typed raw processor/bitness/base
  configuration, Thumb-tagged entry points, and failed-open cleanup

**Debugger availability test** (`just test-debugger`)
- Confirms debugger tools are absent by default and stay hidden on unsupported hosts
- On Apple Silicon macOS, checks the opt-in status surface and workspace-only
  `debug_open_module` schema without launching a target
- `test/debugger_integration.ps1` runs the same availability check on Windows

**Live debugger test** (`just test-debugger-live`)
- Runs only on the enabled Apple Silicon macOS path and requires IDA's supported
  Take Control authorization
- Launches and suspends the fixture, lists runtime modules, opens one in a
  separate workspace database, resolves symbols, and performs terminal stop
- Covers external target exit recovery and out-of-band pooled-worker death
- Set `DEBUGGER_REQUIRE_READY=1` to fail instead of accepting the documented
  `user_action_required` readiness result

**Tool-filter test** (`just test-tool-filter`)
- Verifies flags and environment mirrors for toolsets, explicit tools,
  exclusions, and read-only mode
- Refuses configurations that would start a server with no advertised tools

**Script test** (`just test-script`)
- Opens a binary, then runs inline Python via `run_script`
- Verifies stdout/stderr capture
- Verifies Python error reporting (division by zero)
- Verifies file-based script execution (`.py` file path)

**Elicitation test** (`just test-elicitation`)
- Creates a sparse Mach-O fixture just over 50 MiB
- Verifies `open_idb(auto_analyse=true)` silently routes analysis to a background task when the client has no elicitation capability
- Verifies an elicitation-capable client receives `elicitation/create`, accepts it, and gets `analysis_background=true` plus a pollable `analysis_task_id`
- Verifies MCP `2026-07-28` returns `input_required`, accepts the echoed
  integrity-protected `requestState` plus `inputResponses`, and completes the
  retried tool call

**Startup-failure test** (`just test-http-startup`)
- Squats a port with a pooled parent (binds in ms, takes no IDA license), then
  starts each HTTP topology against it
- Asserts single-worker HTTP exits nonzero, does not wedge (watchdog SIGKILL
  would show as 137), and releases its IDA worker loop
- Asserts pooled HTTP exits nonzero and never logs a clean stop it didn't achieve
- Needs no IDA license, database, or fixture

**Session-cancel test** (`just test-session-cancel`)
- Single-worker HTTP: a legacy session starts a slow foreground `open_idb`
  (observed via `recent_operations`), queues a background `analyze_funcs`
  behind it, then DELETEs the session
- Verifies a second legacy session cannot reuse the deduplicated task ID or
  poll the first session's task
- Verifies the server records owner cancellation only after the background
  operation settles and never records successful completion for that task

**DSC test** (`just test-dsc <path>`)
- Requires a real `dyld_shared_cache_arm64e` file
- Tests the native IDA 9.4 `dscu` path and legacy generated-`.i64` fallback where available
- Polls `task_status` until completion
- Verifies the database is usable after loading (`list_functions`)

**Unit tests** (`just cargo-test`)
- `src/dsc.rs` — file type strings, idat args, script generation, Python string escaping
- `src/server/task.rs` — task registry lifecycle, owner-scoped access and
  deduplication, bounded admission, cancellation, and ISO timestamps

## Test fixture

Tests use `test/fixtures/mini.c`, a minimal C program compiled into a Mach-O binary.
`just test-bootstrap` explicitly requests auto-analysis through `open_idb` and
writes `fixtures/mini.i64`; tests that need a deterministic analyzed database
reuse that fixture. Raw inputs are not auto-analyzed by default.
