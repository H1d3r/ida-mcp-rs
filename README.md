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

- IDA Pro 9.2+ with valid license

## Getting Started

### Install

**macOS / Linux** (via [Homebrew](https://brew.sh))
```bash
brew install blacktop/tap/ida-mcp        # Latest (IDA 9.3)
brew install blacktop/tap/ida-mcp@9.2    # IDA 9.2
```

**Windows** (via [Scoop](https://scoop.sh))
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
```

> **Windows note:** See the [Windows platform setup](#windows) section below for DLL discovery options.

**macOS / Linux** (via [Nix](https://nixos.org))
```bash
nix shell github:blacktop/nur#ida-mcp \
  --extra-experimental-features 'nix-command flakes'
```

**Linux** (via [Snap](https://snapcraft.io/ida-mcp))
```bash
snap install ida-mcp --classic
```
> Pending [classic confinement review](https://forum.snapcraft.io/t/classic-confinement-request-ida-mcp/51001). Until approved, build from source or use Homebrew/Nix.

**Direct download** — grab the archive for your platform from [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases).

**Build from source**

See [docs/BUILDING.md](docs/BUILDING.md).

> ida-mcp versions mirror IDA Pro versions (`v9.3.x` for IDA 9.3, `v9.2.x` for IDA 9.2). A version mismatch is detected at startup with a clear error message. Scoop and NUR publish the latest version. For older IDA versions, use the matching [GitHub Release](https://github.com/blacktop/ida-mcp-rs/releases) or the versioned Homebrew cask.

### Platform Setup

#### macOS

Standard IDA installations in `/Applications` work automatically:
```bash
claude mcp add ida -- ida-mcp
```

If you see `Library not loaded: @rpath/libida.dylib`, set `DYLD_LIBRARY_PATH` to your IDA path:
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp
```

Supported paths (auto-detected):
- `/Applications/IDA Professional 9.3.app/Contents/MacOS`
- `/Applications/IDA Home 9.3.app/Contents/MacOS`
- `/Applications/IDA Essential 9.3.app/Contents/MacOS`
- `/Applications/IDA Professional 9.2.app/Contents/MacOS`

#### Linux

The IDA installer defaults to `~/ida-pro-9.3` — the launcher script auto-detects this:
```bash
claude mcp add ida -- ida-mcp
```

For non-default install locations, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

Resolution order: `$IDADIR` → `~/ida-pro-9.3` → `/opt/ida-pro-9.3` and other RUNPATH fallbacks.

#### Windows

**Option A** — Install `ida-mcp.exe` into your IDA directory (simplest, no env setup needed):
```powershell
# Copy the binary next to ida.dll / idalib.dll
copy ida-mcp.exe "C:\Program Files\IDA Professional 9.3\"
claude mcp add ida -- "C:\Program Files\IDA Professional 9.3\ida-mcp.exe"
```

**Option B** — Install via [Scoop](https://scoop.sh) (auto-detects IDA and sets `IDADIR`):
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
claude mcp add ida -- ida-mcp
```

**Option C** — Set `IDADIR` manually:
```powershell
# Persistent (survives reboots)
setx IDADIR "C:\Program Files\IDA Professional 9.3"
# Then restart your terminal
claude mcp add ida -- ida-mcp
```

Windows requires `ida.dll` and `idalib.dll` to be discoverable at startup. Placing `ida-mcp.exe` in the IDA directory is the easiest approach. Otherwise, the IDA directory must be on `PATH` or pointed to by `IDADIR`.

Common IDA paths:
- `C:\Program Files\IDA Professional 9.3`
- `C:\Program Files\IDA Pro 9.3`
- `C:\Program Files\IDA Home 9.3`

### Runtime Requirements

The binary links against IDA's libraries at runtime. Standard installation paths are auto-detected via baked RPATHs. For non-standard paths:

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so` | `IDADIR` (launcher reads it) or `LD_LIBRARY_PATH` |
| Windows | `ida.dll` | Place exe in IDA dir, set `IDADIR`, or add IDA dir to `PATH` |

### Configure your AI agent

#### [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview)
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

Once configured, you can analyze binaries through your AI agent:

```
# Open a binary (IDA analyzes raw binaries automatically)
open_idb(path: "~/samples/malware")

# Discover available tools
tool_catalog(query: "find callers")

# List functions
list_functions(limit: 20)

# Disassemble by name
disasm_by_name(name: "main", count: 20)

# Decompile (requires Hex-Rays)
decompile(address: "0x100000f00")
```

#### `dyld_shared_cache` analysis

`open_dsc` opens a single module from Apple's dyld_shared_cache. On first use it runs `idat` in the background to create the `.i64` (this can take minutes). Subsequent opens are instant.

```
# Open a module from the DSC
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib")

# If a background task was started, poll until done
task_status(task_id: "dsc-1")

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
- `idat` binary (from IDA installation) must be available via `$IDADIR` or standard install paths
- The DSC loader and `dscu` plugin (bundled with IDA 9.x)

#### IDAPython scripting

`run_script` executes Python code in the open database via IDA's IDAPython engine. stdout and stderr are captured.

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

---

The default tool list includes all tools. Use `tool_catalog`/`tool_help` to discover capabilities and avoid dumping the full list into context.

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
