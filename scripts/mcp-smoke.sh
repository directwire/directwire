#!/usr/bin/env bash
# Process-level MCP smoke test: relay + node-b + mcp_server, drive a real MCP
# stdio session and assert every step. This is the "does an agent actually talk
# over the wire" check, one layer above the Rust integration tests.
#
# Run from the workspace root:
#   bash scripts/mcp-smoke.sh
#
# Notes:
# - Uses the prebuilt example binaries (not `cargo run`): `cargo run` detects a
#   feature mismatch and recompiles mid-script, which makes fixed `sleep 1`
#   race the build. Binaries start in <1s.
# - node-b's NodeId is polled (not a fixed sleep) so slow first-run startup
#   cannot flake the extract.
set -euo pipefail

PORT="${PORT:-19190}"
TMP="$(mktemp -d)"
EX="target/debug/examples"
RELAY="$EX/relay.exe"
NODE_B="$EX/node_b.exe"
MCP_SRV="$EX/mcp_server.exe"

# Windows: backgrounded children lock their .exe until the process exits, so
# kill them explicitly (by PID for our own jobs, by image name for any strays).
cleanup() {
  kill "$@" 2>/dev/null || true
  taskkill //F //IM relay.exe //IM node_b.exe //IM node_a.exe //IM mcp_server.exe 2>/dev/null || true
}
trap 'cleanup "$RPID" "$BPID"' EXIT

echo "== building examples (first run compiles) =="
cargo build -q -p p2p-mesh --features mcp --examples

echo "== relay on :$PORT =="
"$RELAY" --port "$PORT" >"$TMP/relay.log" 2>&1 &
RPID=$!
sleep 1

echo "== node-b (the ordinary peer) =="
"$NODE_B" --relay 127.0.0.1:"$PORT" --seed 31 >"$TMP/b.log" 2>&1 &
BPID=$!

# Poll for node-b's NodeId (stderr is unbuffered, but give first-run some slack).
B_HEX=""
for _ in $(seq 1 40); do
  B_HEX="$(grep -oP 'hex: \K[0-9a-f]{64}' "$TMP/b.log" 2>/dev/null | head -1 || true)"
  [ -n "$B_HEX" ] && break
  sleep 0.5
done
[ -n "$B_HEX" ] || { echo "FAIL: could not read node-b NodeId"; cat "$TMP/b.log"; exit 1; }
echo "   node-b = $B_HEX"

echo "== MCP session over stdio =="
# newline-delimited JSON-RPC 2.0; the pipe closes stdin, so the server exits cleanly
RESP="$(
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"peer_connect\",\"arguments\":{\"target\":\"$B_HEX\"}}}" \
    "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"peer_send\",\"arguments\":{\"target\":\"$B_HEX\",\"payload\":\"hello-from-mcp\"}}}" \
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"peer_recv","arguments":{"timeout_ms":8000}}}' \
  | "$MCP_SRV" --relay 127.0.0.1:"$PORT" --seed 30 2>"$TMP/mcp.log"
)"

echo "$RESP" | grep -q '"serverInfo"'        || { echo "FAIL: initialize";   echo "$RESP"; exit 1; }
echo "$RESP" | grep -q '"name":"peer_send"'  || { echo "FAIL: tools/list";   echo "$RESP"; exit 1; }
echo "$RESP" | grep -q 'punching/connecting' || { echo "FAIL: peer_connect"; echo "$RESP"; exit 1; }
echo "$RESP" | grep -q 'sent 14 bytes'       || { echo "FAIL: peer_send";    echo "$RESP"; exit 1; }
echo "$RESP" | grep -q 'ack:hello-from-mcp'  || {
    echo "FAIL: peer_recv (expected node-b's auto-ack)"; echo "$RESP"; cat "$TMP/b.log"; exit 1;
}

echo
echo "=== MCP SMOKE TEST PASSED ==="
echo "MCP server node: $(grep -o 'node_id=[0-9a-f]\{64\}' "$TMP/mcp.log" | head -1)"
echo "agent -> node-b round trip (relay + auto-ack) verified"
