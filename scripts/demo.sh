#!/usr/bin/env bash
# Directwire end-to-end demo: relay + two nodes, punch-to-direct upgrade.
#
#   scripts/demo.sh          # default: run every feature combination
#   scripts/demo.sh --gm-pq   # enable the SM2 + ML-KEM-768 channel
#
# Requires: cargo (Rust 1.75+), bash. On Windows, run from Git Bash or WSL.
set -euo pipefail

FEAT=""
if [[ "${1:-}" == "--gm-pq" ]]; then
  FEAT="--features gm-pq"
  echo "==> GM-PQ channel enabled (SM2 + ML-KEM-768 hybrid)"
fi

PORT=19100
WORK="$(mktemp -d)"
trap 'kill 0 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "==> building (first run compiles deps, this may take a while)"
cargo build $FEAT --examples --manifest-path crates/p2p-mesh/Cargo.toml

echo "==> starting relay on 127.0.0.1:$PORT"
cargo run $FEAT --manifest-path crates/p2p-mesh/Cargo.toml --example relay -- --port "$PORT" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
sleep 1.5

echo "==> starting node-b (passive listener)"
cargo run $FEAT --manifest-path crates/p2p-mesh/Cargo.toml --example node_b -- --relay 127.0.0.1:$PORT --seed 2 >"$WORK/node_b.log" 2>&1 &
NODEB_PID=$!
sleep 1.5

echo "==> extracting node-b NodeId from its log"
PEER_HEX="$(grep -oE '\(hex: [0-9a-f]+\)' "$WORK/node_b.log" | head -1 | sed -E 's/.*hex: ([0-9a-f]+).*/\1/')"
if [[ -z "$PEER_HEX" ]]; then
  echo "!! could not read node-b NodeId from log:" >&2
  cat "$WORK/node_b.log" >&2
  exit 1
fi
echo "    node-b NodeId = $PEER_HEX"

echo "==> starting node-a (initiator) against node-b"
cargo run $FEAT --manifest-path crates/p2p-mesh/Cargo.toml --example node_a -- --relay 127.0.0.1:$PORT --peer "$PEER_HEX" --seed 1 >"$WORK/node_a.log" 2>&1 &
NODEA_PID=$!

echo "==> demo running — watch the flow: relay messages -> punch -> direct -> path switch"
for i in $(seq 1 20); do
  if ! kill -0 "$NODEA_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo ""
echo "===================== node-a output ====================="
cat "$WORK/node_a.log"
echo "===================== node-b output ====================="
cat "$WORK/node_b.log"
echo "========================================================="
echo "demo finished (see the '*** path switch Relay -> Direct ***' line for the punch upgrade)"
