#!/usr/bin/env bash
# Universal (fat) Mach-O slice selection through open_idb: explicit arch, the
# legacy elicitation prompt (answered and timed out), the MCP 2026 input
# request, and 64-bit fat headers.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-mcp}}"
MODERN_META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"universal-modern","version":"0.1"},"io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}'
ARM64_HEADER="cffaedfe0c000001"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the universal Mach-O test (brew install jq)" >&2
  exit 1
fi
if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi
if [[ "$(od -An -tx1 -N8 fixtures/mini 2>/dev/null | tr -d ' \n')" != "$ARM64_HEADER" ]]; then
  echo "SKIP: fixtures/mini is not an arm64 Mach-O on this host; the universal fixture needs one"
  exit 0
fi

server_pid=""
tmpdir=""

cleanup_case() {
  exec 3>&- || true
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    sleep 0.5
    if kill -0 "$server_pid" >/dev/null 2>&1; then
      kill -9 "$server_pid" >/dev/null 2>&1 || true
    fi
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  if [[ -n "${tmpdir:-}" ]]; then
    rm -rf "$tmpdir"
    tmpdir=""
  fi
}

trap cleanup_case EXIT INT TERM

# Emit a big-endian 32-bit value as raw bytes.
be32() {
  local value=$1 shift
  for shift in 24 16 8 0; do
    printf '%b' "\\x$(printf %02x $(((value >> shift) & 255)))"
  done
}

be64() {
  be32 $(($1 >> 32))
  be32 $(($1 & 0xffffffff))
}

# Build a universal file from fixtures/mini (arm64) and a copy whose header
# says arm64e. IDA names the two differently ("ARM64" vs "ARM64e"), so the
# loader field shows which slice was opened. Slices sit on 16 KiB boundaries,
# which lets dd copy whole blocks instead of single bytes.
make_universal() {
  local out="$1" width="$2" arm64="${3:-fixtures/mini}"
  local arm64e="$tmpdir/mini.arm64e-header"
  cp fixtures/mini "$arm64e"
  printf '\x02\x00\x00\x80' | dd of="$arm64e" bs=1 seek=8 conv=notrunc 2>/dev/null
  local size small first second magic=$((0xcafebabe)) word=be32
  size=$(wc -c <"$arm64" | tr -d ' ')
  small=$(wc -c <"$arm64e" | tr -d ' ')
  first=16384
  second=$(((first + size + 16383) / 16384 * 16384))
  if [[ "$width" == 64 ]]; then
    magic=$((0xcafebabf))
    word=be64
  fi
  # fat_arch: cputype, cpusubtype, offset, size, align (+ reserved when 64-bit)
  fat_arch() {
    be32 $((0x0100000c))
    be32 "$1"
    "$word" "$2"
    "$word" "$3"
    be32 14
    if [[ "$width" == 64 ]]; then be32 0; fi
  }
  {
    be32 "$magic"
    be32 2
    fat_arch 0 "$first" "$size"
    fat_arch $((0x80000002)) "$second" "$small"
  } >"$out"
  dd if="$arm64" of="$out" bs=16384 seek=$((first / 16384)) conv=notrunc 2>/dev/null
  dd if="$arm64e" of="$out" bs=16384 seek=$((second / 16384)) conv=notrunc 2>/dev/null
}

send() {
  echo "$1" >&3
}

dump_server_logs() {
  echo "── server stdout ──" >&2
  cat "$log" >&2 || true
  echo "── server stderr ──" >&2
  tail -40 "$errlog" >&2 || true
}

json_line_matching() {
  local filter="$1"
  local timeout="${2:-60}"
  local elapsed=0
  while [[ "$elapsed" -lt "$timeout" ]]; do
    while IFS= read -r line; do
      if [[ "$line" != *'"jsonrpc"'* ]]; then
        continue
      fi
      if echo "$line" | jq -e "$filter" >/dev/null 2>&1; then
        echo "$line"
        return 0
      fi
    done <"$log"
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server process died while waiting for: $filter" >&2
      dump_server_logs
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for: $filter" >&2
  dump_server_logs
  return 1
}

wait_response() {
  json_line_matching ".id == $1 and (has(\"result\") or has(\"error\"))" "${2:-60}"
}

start_server() {
  tmpdir="$(mktemp -d)"
  fifo_in="$tmpdir/in.fifo"
  log="$tmpdir/server.log"
  errlog="$tmpdir/server.err.log"
  mkfifo "$fifo_in"
  # Create the log before the server's shell opens it: that shell blocks on
  # the FIFO first, so the first read below could otherwise find no file.
  : >"$log"
  RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" <"$fifo_in" >"$log" 2>"$errlog" &
  server_pid=$!
  exec 3>"$fifo_in"
}

initialize() {
  send "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"clientInfo\":{\"name\":\"$1\",\"version\":\"0.1\"},\"capabilities\":$2}}"
  wait_response 1 20 >/dev/null
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
}

call_tool() {
  local id="$1" name="$2" args="$3"
  send "$(jq -nc --argjson id "$id" --arg name "$name" --argjson args "$args" \
    '{jsonrpc:"2.0", id:$id, method:"tools/call", params:{name:$name, arguments:$args}}')"
}

tool_text() {
  jq -r '.result.content[0].text // empty'
}

expect_tool_error() {
  local response="$1" needle="$2" label="$3"
  if ! echo "$response" | jq -e --arg needle "$needle" \
    '.result.isError == true and (.result.content[0].text | contains($needle))' >/dev/null; then
    echo "❌ $label: expected a tool error containing: $needle" >&2
    echo "$response" | jq . >&2 || echo "$response" >&2
    return 1
  fi
}

# The open succeeded, reports the chosen slice, and IDA loaded that slice.
# $3 is a regex on IDA's loader name: "ARM64$" for arm64, "ARM64e" for arm64e
# (IDA appends the pointer-auth ABI, e.g. "ARM64e-pauth0").
expect_opened_slice() {
  local response="$1" arch="$2" loader="$3" label="$4"
  if ! echo "$response" | tool_text | jq -e --arg arch "$arch" --arg loader "$loader" '
    .universal.arch == $arch
    and .universal.slices == ["arm64", "arm64e"]
    and (.universal.slice_path | endswith("." + $arch))
    and (.loader | test($loader))' >/dev/null; then
    echo "❌ $label: open_idb did not open the $arch slice" >&2
    echo "$response" | jq . >&2 || echo "$response" >&2
    return 1
  fi
}

case_explicit_arch() {
  start_server
  echo "── explicit arch (client without input requests) ──"
  initialize "universal-explicit" '{}'
  local fat="$tmpdir/uni"
  mkdir "$tmpdir/out"
  make_universal "$fat" 32

  call_tool 2 open_idb "$(jq -nc --arg p "$fat" '{path:$p}')"
  expect_tool_error "$(wait_response 2 60)" "slices arm64, arm64e; the client cannot show input requests" "no arch"
  echo "   no arch -> error lists slices"

  call_tool 3 open_idb "$(jq -nc --arg p "$fat" '{path:$p, arch:"x86_64"}')"
  expect_tool_error "$(wait_response 3 60)" "slices arm64, arm64e; no x86_64 slice. Pass arch" "unknown arch"
  echo "   unknown arch -> error lists slices"

  local out="$tmpdir/out/uni.i64"
  call_tool 4 open_idb "$(jq -nc --arg p "$fat" --arg o "$out" '{path:$p, arch:"arm64e", idb_out:$o}')"
  local opened
  opened="$(wait_response 4 120)"
  expect_opened_slice "$opened" "arm64e" "ARM64e" "explicit arm64e"
  if [[ ! -f "$tmpdir/out/uni.arm64e" ]]; then
    echo "❌ extracted slice missing beside idb_out" >&2
    ls -la "$tmpdir/out" >&2
    return 1
  fi
  echo "   arch=arm64e -> $(echo "$opened" | tool_text | jq -r .loader)"

  call_tool 5 idb_meta '{}'
  if ! wait_response 5 30 | tool_text | jq -e '.loader | test("ARM64e")' >/dev/null; then
    echo "❌ idb_meta did not report the loader" >&2
    return 1
  fi
  call_tool 6 close_idb '{}'
  wait_response 6 60 >/dev/null
  if [[ ! -f "$out" ]]; then
    echo "❌ close_idb did not pack the database at idb_out" >&2
    ls -la "$tmpdir/out" >&2
    return 1
  fi

  call_tool 7 open_idb "$(jq -nc --arg p "$fat" --arg o "$out" '{path:$p, arch:"arm64e", idb_out:$o}')"
  expect_opened_slice "$(wait_response 7 120)" "arm64e" "ARM64e" "reopen"
  echo "   reopen reuses the extracted slice and database"
  call_tool 8 close_idb '{}'
  wait_response 8 60 >/dev/null

  call_tool 9 open_idb '{"path":"fixtures/mini","arch":"arm64e"}'
  expect_tool_error "$(wait_response 9 60)" "single-architecture arm64 Mach-O; arch=arm64e does not match" "thin"
  echo "   thin Mach-O rejects a different arch"

  local fat64="$tmpdir/uni64"
  make_universal "$fat64" 64
  call_tool 10 open_idb "$(jq -nc --arg p "$fat64" '{path:$p, arch:"arm64"}')"
  expect_opened_slice "$(wait_response 10 120)" "arm64" "ARM64$" "64-bit fat header"
  echo "   64-bit fat header opens the requested slice"
  cleanup_case
}

case_elicitation_accept() {
  start_server
  echo "── legacy slice prompt, answered ──"
  initialize "universal-elicit" '{"elicitation":{"form":{}}}'
  local fat="$tmpdir/uni"
  make_universal "$fat" 32
  call_tool 2 open_idb "$(jq -nc --arg p "$fat" '{path:$p}')"
  local prompt
  prompt="$(json_line_matching '.method == "elicitation/create"' 60)"
  if ! echo "$prompt" | jq -e '
    [.params.requestedSchema.properties.arch.oneOf[].const] == ["arm64", "arm64e"]
    and .params.requestedSchema.required == ["arch"]
    and (.params.requestedSchema.properties | has("background") | not)
    and (.params.message | contains("universal Mach-O with 2 slices"))' >/dev/null; then
    echo "❌ slice prompt did not carry the expected schema" >&2
    echo "$prompt" | jq . >&2
    return 1
  fi
  send "{\"jsonrpc\":\"2.0\",\"id\":$(echo "$prompt" | jq -c .id),\"result\":{\"action\":\"accept\",\"content\":{\"arch\":\"arm64\"}}}"
  expect_opened_slice "$(wait_response 2 120)" "arm64" "ARM64$" "answered prompt"
  echo "   prompt answered arm64 -> opened arm64"
  cleanup_case
}

case_elicitation_timeout() {
  start_server
  echo "── legacy slice prompt, unanswered ──"
  initialize "universal-timeout" '{"elicitation":{"form":{}}}'
  local fat="$tmpdir/uni"
  make_universal "$fat" 32
  call_tool 2 open_idb "$(jq -nc --arg p "$fat" '{path:$p, timeout_secs:5}')"
  json_line_matching '.method == "elicitation/create"' 60 >/dev/null
  expect_tool_error "$(wait_response 2 60)" "no slice was chosen within 5s" "timeout"
  if [[ -e "$tmpdir/uni.arm64" || -e "$tmpdir/uni.arm64e" ]]; then
    echo "❌ a slice was extracted without an answer" >&2
    return 1
  fi
  echo "   unanswered prompt -> error after 5s, nothing extracted"
  cleanup_case
}

# A slice over the auto-background threshold with auto_analyse=true: the one
# input request carries both questions, so the retry completes without a
# second round and routes analysis to the background.
case_mrtr_large() {
  start_server
  echo "── MCP 2026 input request, large slice ──"
  local big="$tmpdir/mini.big" fat="$tmpdir/uni"
  cp fixtures/mini "$big"
  dd if=/dev/zero of="$big" bs=1 count=1 seek=$((50 * 1024 * 1024)) conv=notrunc 2>/dev/null
  make_universal "$fat" 32 "$big"
  local args
  args="$(jq -nc --arg p "$fat" '{path:$p, auto_analyse:true, timeout_secs:600}')"
  send "$(jq -nc --argjson args "$args" --argjson meta "$MODERN_META" \
    '{jsonrpc:"2.0", id:20, method:"tools/call", params:{_meta:$meta, name:"open_idb", arguments:$args}}')"
  local first
  first="$(wait_response 20 60)"
  if ! echo "$first" | jq -e '
    .result.resultType == "input_required"
    and (.result.inputRequests | keys) == ["slice"]
    and .result.inputRequests.slice.params.requestedSchema.properties.background.type == "boolean"' \
    >/dev/null; then
    echo "❌ large slice prompt did not include the background question" >&2
    echo "$first" | jq . >&2
    return 1
  fi
  send "$(jq -nc --argjson args "$args" --arg state "$(echo "$first" | jq -r .result.requestState)" \
    --argjson meta "$MODERN_META" '
    {jsonrpc:"2.0", id:21, method:"tools/call", params:{
      _meta:$meta, name:"open_idb", arguments:$args, requestState:$state,
      inputResponses:{slice:{action:"accept", content:{arch:"arm64", background:true}}}}}')"
  local retry
  retry="$(wait_response 21 180)"
  if ! echo "$retry" | jq -e '.result.resultType == "complete"' >/dev/null ||
    ! echo "$retry" | tool_text | jq -e '
      .universal.arch == "arm64"
      and .analysis_background == true
      and (.analysis_task_id | startswith("analyze-"))' >/dev/null; then
    echo "❌ large slice retry did not open arm64 with background analysis" >&2
    echo "$retry" | jq . >&2
    return 1
  fi
  expect_opened_slice "$retry" "arm64" "ARM64$" "MRTR retry"
  echo "   one input request chose arm64 and background analysis"
  cleanup_case
}

case_explicit_arch
case_elicitation_accept
case_elicitation_timeout
case_mrtr_large

echo "✅ Universal Mach-O test passed"
