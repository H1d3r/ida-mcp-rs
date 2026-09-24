<p align="center">
  <!--<a href="https://github.com/blacktop/ida-mcp-rs"><img alt="Logo" src="https://raw.githubusercontent.com/blacktop/ida-mcp-rs/refs/heads/main/docs/logo.svg" height="400"/></a>-->
  <h1 align="center">ida-mcp-rs</h1>
  <h4><p align="center">Headless IDA Pro MCP server for AI-powered reverse engineering.</p></h4>
  <p align="center">
    <a href="https://github.com/blacktop/ida-mcp-rs/actions" alt="Actions">
          <img src="https://github.com/blacktop/ida-mcp-rs/actions/workflows/build.yml/badge.svg" /></a>
    <a href="https://github.com/blacktop/ida-mcp-rs/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/ida-mcp-rs/total.svg" /></a>
    <a href="https://github.com/blacktop/ida-mcp-rs/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/v/release/blacktop/ida-mcp-rs" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p>
<br>

## Prerequisites

- IDA Pro 9.4 with a valid license

## Getting started

### Install

**macOS / Linux** (via [Homebrew](https://brew.sh))
```bash
brew install blacktop/tap/ida-mcp        # Latest (IDA 9.4)
```

**macOS (Apple Silicon), older IDA releases** (via versioned Homebrew casks)
```bash
brew install blacktop/tap/ida-mcp@9.3    # IDA 9.3/9.3sp1
brew install blacktop/tap/ida-mcp@9.2    # IDA 9.2
```

**Windows** (via [Scoop](https://scoop.sh))
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
```

> **Windows note:** see [Windows](#windows) below for DLL discovery options.

**macOS / Linux** (via [Nix](https://nixos.org))
```bash
nix shell github:blacktop/nur#ida-mcp \
  --extra-experimental-features 'nix-command flakes'
```

**Direct download:** grab the archive for your platform from [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases).

**Build from source:** see [docs/BUILDING.md](docs/BUILDING.md).

> ida-mcp versions follow IDA Pro versions: `v9.4.x` for IDA 9.4, `v9.3.x` for IDA 9.3, and `v9.2.x` for IDA 9.2. ida-mcp checks compatibility when it initializes IDA. An incompatible version causes IDA-backed tools to fail with an error identifying the detected version and, when available, the loaded library path. Scoop and NUR publish only the latest version. For an older IDA, use the matching [GitHub Release](https://github.com/blacktop/ida-mcp-rs/releases) or, on Apple Silicon, a versioned Homebrew cask.

### Platform setup

#### macOS

Standard IDA installs in `/Applications` work without extra setup:
```bash
claude mcp add ida -- ida-mcp
```

If you see `Library not loaded: @rpath/libida.dylib`, point `DYLD_LIBRARY_PATH` at your IDA install:
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp
```

Paths found automatically:
- `/Applications/IDA Professional 9.4.app/Contents/MacOS`
- `/Applications/IDA Pro 9.4.app/Contents/MacOS`
- `/Applications/IDA Home 9.4.app/Contents/MacOS`
- `/Applications/IDA Essential 9.4.app/Contents/MacOS`

#### Linux

The IDA installer defaults to `~/ida-pro-9.4`, and the launcher script looks there:
```bash
claude mcp add ida -- ida-mcp
```

For any other install location, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

Lookup order: `$IDADIR`, then `~/ida-pro-9.4`, then `/opt/ida-pro-9.4` and the other RUNPATH fallbacks.

#### Windows

**Option A:** put `ida-mcp.exe` in your IDA directory. This is the simplest route and needs no environment setup:
```powershell
# Copy the binary next to ida.dll / idalib.dll
copy ida-mcp.exe "C:\Program Files\IDA Professional 9.4\"
claude mcp add ida -- "C:\Program Files\IDA Professional 9.4\ida-mcp.exe"
```

**Option B:** install with [Scoop](https://scoop.sh), which finds IDA and sets `IDADIR`:
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
claude mcp add ida -- ida-mcp
```

**Option C:** set `IDADIR` yourself:
```powershell
$idaDir = "C:\Program Files\IDA Professional 9.4"
[Environment]::SetEnvironmentVariable("IDADIR", $idaDir, "User")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ";" | Where-Object { $_ })
if (-not ($pathEntries -contains $idaDir)) {
  [Environment]::SetEnvironmentVariable(
    "Path", (@($pathEntries + $idaDir) -join ";"), "User"
  )
}
# Then restart your terminal
claude mcp add ida -- ida-mcp
```

Windows has to find `ida.dll` and `idalib.dll` before `ida-mcp` starts. Putting `ida-mcp.exe` in the IDA directory is the easiest way. Otherwise, set `IDADIR` and add the same directory to `PATH` so the DLLs load at runtime.

Common IDA paths:
- `C:\Program Files\IDA Professional 9.4`
- `C:\Program Files\IDA Pro 9.4`
- `C:\Program Files\IDA Home 9.4`

### Runtime requirements

The binary links against IDA's libraries at runtime. Baked-in RPATHs cover the standard install paths. For anything else:

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so` | `IDADIR` (launcher reads it) or `LD_LIBRARY_PATH` |
| Windows | `ida.dll` | Place exe in IDA dir, or set `IDADIR` and add IDA dir to `PATH` |

### Configure your AI agent

#### [Claude Code](https://code.claude.com/docs/en/mcp)
```bash
claude mcp add ida -- ida-mcp
```

#### [Codex CLI](https://github.com/openai/codex)
```bash
codex mcp add ida -- ida-mcp
```

#### [Gemini CLI](https://github.com/google-gemini/gemini-cli)
```bash
gemini mcp add ida -- ida-mcp
```

#### [Cursor](https://cursor.com)
Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "ida": { "command": "ida-mcp" }
  }
}
```

### Usage

Once your agent is configured, it can drive the tools directly:

```
# Open a binary. This returns quickly; analysis runs separately.
open_idb(path: "~/samples/malware")

# Keep the generated database out of a read-only input directory
open_idb(path: "/System/example", idb_out: "~/ida-work/example.i64")

# Pick one slice of a universal (fat) Mach-O
open_idb(path: "/bin/ls", arch: "arm64e", idb_out: "~/ida-work/ls.i64")

# These work immediately, no analysis needed
list_functions(limit: 20)
disasm_by_name(name: "main", count: 20)
strings(limit: 10)

# For xrefs/decompile on large binaries, run analysis in the background
analyze_funcs(background: true)   # returns task_id
task_status(task_id: "analyze-<random>") # poll progress (ID from the analyze_funcs response)

# Decompile (requires Hex-Rays + completed analysis)
decompile(address: "0x100000f00")

# Discover more tools
tool_catalog(query: "find callers")
```

Tools that change the database (`rename`, `set_comments`, `patch`, `patch_asm`,
`apply_types`, `declare_stack`, `delete_stack`, and `lumina_apply`) take exactly
one address or one symbol name. Names must match exactly, case included. A near
miss changes nothing and returns up to eight similar names with their addresses.
A returned `target` record identifies the database, resolved symbol (or `null`),
and requested and effective addresses. Check the operation's result to determine
whether the change succeeded.

## Opening binaries

### Raw blobs

Raw inputs use IDA's normal loader by default and save to `<input>.i64`. Pass
`idb_out` to put the database somewhere else, for example when the input
directory is read-only. An existing database is reused only when the input
SHA-256 recorded in it matches the current file. `rebuild: true` overwrites a
database only when its recorded hash or input path shows it was built from this
input.

For headerless blobs, `open_idb` also takes typed loader hints:

```text
open_idb(
  path: "~/firmware/boot.bin",
  idb_out: "~/ida-work/boot.i64",
  processor: "arm:ARMv7-M",
  bitness: 32,
  base_address: "0x08000000",
  entry_point: "0x08000101"
)
```

Processor families with several modes need an explicit IDA processor variant,
so bare names such as `arm` or `metapc` are rejected. The hints apply only when
creating a database from a raw input; they never change an existing
`.i64`/`.idb`. On 32-bit ARM, an odd `entry_point` is a Thumb pointer: ida-mcp
clears bit 0 for the code address and records the Thumb state before creating
the entry instruction.

### Universal (fat) Mach-O

When IDA loads a fat binary headlessly, it takes the x86_64 slice whenever one
exists, and it doesn't recognize 64-bit fat headers at all. So `open_idb` picks
the slice itself. Pass `arch` (for example `arm64e` or `x86_64`), or leave it out
and answer the prompt if your client supports input requests.

If no answer comes back, the call fails and lists the slices so an unattended
agent can retry with `arch`. That covers clients that can't prompt, a declined
prompt, and pre-2026 clients that don't reply within 30 seconds. MCP 2026
clients get the question back in the response and retry with the answer, so
the server never sits waiting on them.

The chosen slice is copied to `<input name>.<arch>` next to the output database
and opened as a single-architecture Mach-O. An identical copy already at that
path is reused; a different file there is never overwritten. The response's
`universal` field names the slice, and `loader` shows what IDA loaded.

### `dyld_shared_cache`

`open_dsc` opens one module from Apple's dyld_shared_cache. On IDA 9.4, ida-mcp
reads the DSC header directly and loads images through IDA's native `dscu`
service. Older IDA builds fall back to the legacy `idat` background flow when a
`.i64` has to be generated.

```
# Open a module from the DSC
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib")

# If a legacy background task was started, poll until done
task_status(task_id: "dsc-<random>")  # ID from the open_dsc response

# Load additional frameworks for cross-module references
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib",
         frameworks: ["/System/Library/Frameworks/Foundation.framework/Foundation"])

# Incrementally load another DSC dylib into an already-open database
dsc_add_dylib(module: "/usr/lib/libSystem.B.dylib")

# Incrementally load a DSC data/GOT/stub region by address
dsc_add_region(address: "0x180116000")

# After dsc_add_dylib/dsc_add_region, confirm analysis readiness
analysis_status()
```

Requirements:
- IDA 9.4+ for native `dscu` loading
- For older IDA builds, `idat` must be available via `$IDADIR` or standard install paths

## IDAPython scripting

`run_script` runs Python in the open database through IDA's IDAPython engine
and returns what the script wrote to stdout and stderr.

```
# Inline script
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")

# Run a .py file from disk
run_script(file: "/path/to/analysis_script.py")

# With timeout (default 120s, max 600s)
run_script(code: "import ida_bytes; print(ida_bytes.get_bytes(0x1000, 16).hex())",
           timeout_secs: 30)
```

All `ida_*` modules, `idc`, and `idautils` are available. See the [IDAPython API reference](https://python.docs.hex-rays.com).

## Multiple databases and HTTP

### Workspace mode (opt-in)

By default ida-mcp works on one implicit database, so tool calls don't carry a
handle. To keep several databases open at once, start with `--workspace`:

```bash
ida-mcp --workspace --workspace-max-workers 4
ida-mcp --workspace serve-http --bind 127.0.0.1:8765 --stateless
```

In workspace mode, each `open_idb`/`open_dsc` returns a `database_id`, and every
database-scoped call must send it. Runtime tools such as `tool_catalog` reject
it. `close_idb(database_id: ...)` closes only that handle. Idle handles are
reaped after 30 minutes; `--workspace-idle-timeout-secs 0` turns that off.

`list_databases` returns every routed `database_id` with its database path and
state (`open`, `busy`, or `no_worker`). An agent that lost a response, or
reconnected over stateless HTTP, can use it to find an open database again
instead of leaving it stranded until the idle timeout. It is read-only and only
appears when the server runs with `--workspace`.

### HTTP/SSE worker pool

`serve-http` runs one in-process IDA worker by default. To serve several
stateful HTTP/SSE clients at once, set `--max-workers` above `1`. Each session
then gets its own child `ida-mcp worker` process:

```bash
ida-mcp serve-http --bind 127.0.0.1:8765 --max-workers 4 --min-workers 1
```

Without `--max-workers N`, all HTTP sessions share one IDA context. A second
client that opens another binary waits behind the first, then gets the usual
`A database is already open` error. Pooled startup logs include
`Starting pooled HTTP router` and `MCP pooled HTTP server listening`.

An HTTP session holds its worker from the first open until `close_idb`, HTTP
`DELETE`, session timeout, or server shutdown. `close_idb` releases the worker
right away, but the child process may stay alive for reuse until
`--worker-idle-timeout-secs` passes. When every worker is taken, new
`open_idb`/`open_dsc` calls fail with `Worker pool exhausted` so clients can
retry later. Pooled mode needs stateful HTTP sessions, so `--max-workers > 1`
is rejected together with `--stateless`.

If an SSE client exits without sending `close_idb` or HTTP `DELETE`, pooled
mode closes its session once the standalone SSE stream disconnects and the
`--worker-disconnect-grace-secs` reconnect window runs out. POST-only clients
don't always leave a stream to watch, so their abandoned sessions are reclaimed
by `--session-keep-alive-secs` (default 1800 seconds). Lower it if you need
pooled workers back sooner.

### MCP 2026-07-28

MCP `2026-07-28` uses the sessionless `server/discover` lifecycle. ida-mcp
supports it over stdio and in the default single-worker HTTP mode, including
multi-round elicitation and the `io.modelcontextprotocol/tasks` extension for
background `open_dsc` calls.

Pooled HTTP (`--max-workers > 1`) advertises protocol versions only up to
`2025-11-25`. Its workers are tied to sessions, and MCP 2026 has no session ID
to route on, so a request could reach a different IDA worker. MCP 2026 requests
to pooled HTTP fail with an unsupported protocol-version error instead.

## Headless debugger (experimental)

Debugger tools are off by default. On supported platforms (Apple Silicon macOS
for now), start with `--enable-debugger` or `IDA_MCP_ENABLE_DEBUGGER=true` to add
`debug_status`, `debug_launch`, `debug_attach`, `debug_modules`, and
`debug_stop`. `debug_open_module` also needs `--workspace`, because it opens the
runtime image in a new database and leaves the database that owns the live
debug session alone:

```text
debug_status()
debug_launch(database_id: "…", path: "/absolute/path/to/program")
debug_modules(database_id: "…")
debug_open_module(
  database_id: "…",
  module: "/usr/lib/libobjc.A.dylib",
  idb_out: "~/ida-work/libobjc.i64"
)
debug_stop(database_id: "…", action: "auto")
```

`debug_open_module` opens standalone binaries and dlopen'd plugins directly. On
macOS it also resolves system libraries such as `/usr/lib/libobjc.A.dylib`
through the host dyld shared cache for the target's architecture, then loads the
image with IDA 9.4's in-process DSC service. It doesn't extract a temporary
dylib or run `idat`.

`debug_open_module` always requires `idb_out`. Runtime modules often live in
read-only system directories, and ida-mcp won't silently write an IDB next to
them. The response includes a checked runtime slide; the new database stays at
its on-disk preferred addresses.

In workspace mode, a launched or attached debug session pins its database so
the idle timeout skips it, until `debug_stop` succeeds or `close_idb` releases
the database.

Known limitations:

- **A target that exits on its own keeps its pin.** IDA caches the process
  state and refreshes it only when a call drains the pending debug event, so
  ida-mcp can't see a debuggee die in the background. The database stays
  pinned, and exempt from the idle timeout, until `debug_stop`, `close_idb`, or
  worker loss clears it. Both `debug_stop` and `close_idb` handle an
  already-exited target correctly.
- **Losing the worker doesn't stop the debuggee.** If the worker hosting a live
  session is killed, crashes, or is retired by ida-mcp after a wedged debugger
  call, it may never run its own teardown. IDA's debug-server helper can then be
  reparented instead of terminated, and the target may keep running. When an
  in-flight call detects or causes the retirement, ida-mcp returns a
  `Debugger session lost` error that says the target may still be alive, and
  clears the handle's debug pin. It never claims the debuggee ended. A leased
  worker can also die with no request in flight to carry an error;
  `list_databases` may briefly show `no_worker` before the reaper removes that
  handle, even with idle eviction disabled. Cleaning up a stray helper or
  debuggee is manual for now.

ida-mcp picks IDA's signed loopback helper from the opened database's target
architecture: `mac_server_arm` for ARM64 and `mac_server` for x86/x86_64. macOS
may require IDA's "Take Control" authorization once per login; until it's
granted, tools report `user_action_required`. ida-mcp does not ask for root,
disable SIP, edit `authorizationdb`, or re-sign binaries.

Linux and Windows don't advertise the debugger tools at all. IDA's ARM Linux
debugger only works remotely, and ida-mcp doesn't expose remote configuration.
The SDK has no Windows-on-ARM user-mode debugger. The native ARM64 test
harnesses on both platforms check that the tools stay unavailable. x86 Linux
and Windows stay off until a local debugger run passes on them.

## Lumina

ida-mcp turns off IDA's automatic Lumina lookup by default, so starting the
server or opening a database doesn't contact `lumina.hex-rays.com`. The setting
lives only in ida-mcp's private IDA user profile; your normal IDA GUI profile is
untouched. IDA on Windows keeps its settings in the registry rather than under
`IDAUSR`, so there ida-mcp also uses a process-local registry mapping. If
ida-mcp can't set up the private profile, it refuses to start.

To let IDA use its configured Lumina servers, opt in for that process:

```bash
ida-mcp --allow-lumina
```

The environment variable equivalent is `IDA_MCP_ALLOW_LUMINA=true`.

Two tools use it. Both are listed by default, but until you opt in they fail with
an error telling you to restart with `--allow-lumina`:

- `lumina_lookup` queries one function and reports the available metadata
  without changing the database.
- `lumina_apply` pulls and applies metadata using IDA's upgrade policy.
  `force: true` may replace existing names, types, or comments.

`--read-only` removes `lumina_apply` but keeps `lumina_lookup`, since a lookup
doesn't modify the database.

## Context optimization

By default `tools/list` returns 75 tools. The full tool list is roughly 12k
tokens, estimated at four characters per token. Seven more are opt-in: the six
debugger tools and `list_databases` appear only with
`--enable-debugger` or `--workspace`. Clients with dynamic tool discovery defer
the schema cost; clients that preload schemas pay it every session. To trim the
surface to what you need:

| Flag | Env var | Effect |
|---|---|---|
| `--toolsets=cat1,cat2` | `IDA_MCP_TOOLSETS` | Replaces "all tools" with the union of selected categories |
| `--tools=t1,t2`        | `IDA_MCP_TOOLS`         | Adds individual tools (additive to `--toolsets`) |
| `--exclude-tools=t1,t2`| `IDA_MCP_EXCLUDE_TOOLS` | Subtracts from the include set; always wins |
| `--read-only`          | `IDA_MCP_READ_ONLY`     | Strips mutating/arbitrary-code tools (`run_script`, `patch*`, `rename`, `set_comments`, `lumina_apply`, type/stack edits, `dsc_add_*`, `analyze_funcs`, and debugger process control); keeps lifecycle/discovery |

With no flags you get all 75 baseline tools. Categories: `core`, `functions`,
`disassembly`, `decompile`, `xrefs`, `control_flow`, `memory`, `search`,
`metadata`, `types`, `editing`, `scripting`; `debug` exists only when the
debugger is enabled on a supported platform (run `tool_catalog` to list them).
Flags override env vars, and unknown names are rejected at startup.

### Recommendations by client

- **Claude Code, Cursor:** nothing to do for context usage. Both defer MCP tool schemas and load them on demand. Filtering still helps if you want to limit what the agent can do.
- **Codex CLI:** current models with tool search defer MCP tools automatically. For models without tool search, or to limit what the agent can do, pick a focused subset:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile,xrefs
  ```
- **Clients without lazy tool loading:** every session receives the full tool list, estimated at ~12k tokens. Pick a focused subset as shown above.
- **Gemini CLI:** filtering is optional, but a smaller surface cuts down on wrong tool picks when several MCP servers are enabled:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile --read-only
  ```
- **Small / local models:** use the smallest surface that works. For triage:
  ```bash
  ida-mcp --toolsets=core,functions --tools=decompile,callees,callers --read-only
  ```

### Configuring through `mcpServers.json`

Most MCP configs run `ida-mcp` with no subcommand. The env vars work there too:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "command": "ida-mcp",
      "env": {
        "IDA_MCP_TOOLSETS": "core,functions,disassembly,decompile,xrefs",
        "IDA_MCP_READ_ONLY": "true"
      }
    }
  }
}
```

### Measuring

`just measure-tools` prints a per-tool char/token breakdown. It starts the server without filter flags, so the numbers cover the full default list. To see what a filter saves, check your client's context view (`/context` in Claude Code, or its equivalent elsewhere).

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
