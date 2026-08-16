# Directwire

**Public-key native networking for autonomous agents.**

Directwire is an open protocol and reference implementation for direct, encrypted, server-independent communication between AI agents. **Dial by public key, not by IP.**

Today's agents are chained to central brokers and cloud relays. Directwire gives every agent a home address that cannot be taken away — a cryptographic identity, a direct path when one exists, and a secure fallback when NAT blocks the way.

## Why Directwire

- **Identity is the address.** Peers are dialed by their ed25519 node ID. No IP, no DNS, no central registry that can revoke you.
- **Encrypted by default, hybrid-hardened.** Sessions use a hybrid of national-crypto (SM2) and post-quantum (ML-KEM-768) key encapsulation — break one, the other still holds.
- **Direct when possible, relayed when not.** NAT hole punching establishes a peer-to-peer path; a relay guarantees liveness as a fallback.
- **Adaptive paths.** Route selection weighs RTT and loss with hysteresis — no flapping under real-world jitter.
- **Forward secrecy, replay protection, key hygiene.** Ephemeral keys, sliding replay windows, and zeroize on every secret.

## Status

**Research preview (v0.2).** The protocol is under active design; the reference implementation is a clean-room architecture-validation baseline, now covering the full five-layer stack (see [the architecture whitepaper](docs/architecture-whitepaper.md)). SemVer will not be meaningful until v1.

## Workspace

Five crates, one wire — from the cryptographic handshake up to the edge gateway:

| crate | layer | role |
|---|---|---|
| [`gm-pq-stack`](crates/gm-pq-stack) | Security | Hybrid national-crypto + post-quantum secure channel: SM2 + ML-KEM-768 handshake, SM4-GCM sessions, replay protection, cookie anti-DoS, 0-RTT resumption |
| [`p2p-mesh`](crates/p2p-mesh) | Connectivity | iroh-style public-key mesh networking: relay brokering, NAT hole punching, QUIC simultaneous-open direct, adaptive path selection, MCP server |
| [`moq-live`](crates/moq-live) | Media | MoQ-lite low-latency live transport: publish/subscribe, stream-per-group, priority-aware drop, catch-up |
| [`homa-rpc`](crates/homa-rpc) | RPC | Homa-style message-oriented transport over UDP + idempotent RPC: SRPT grant scheduling, 8-level QoS |
| [`xdp-edge`](crates/xdp-edge) | Edge | eBPF/XDP edge data plane: per-source rate limiting, SYN-flood detection, Maglev L4 load balancing, IPIP forwarding |

## Quickstart

```bash
# run all workspace tests (both crates)
cargo test --workspace --all-features

# three-process mesh demo (see crates/p2p-mesh/README.md)
cargo run -p p2p-mesh --example relay -- --port 9100
cargo run -p p2p-mesh --example node_b -- --relay 127.0.0.1:9100 --seed 2
cargo run -p p2p-mesh --example node_a -- --relay 127.0.0.1:9100 --peer <node-b-hex>
```

## End-to-end demo

One command starts a relay + two nodes on your machine, watches them establish a relay session,
punch a direct path, and switch: `scripts/demo.sh` (or `scripts/demo.sh --gm-pq` to also enable the
SM2 + ML-KEM-768 channel). The script prints both nodes' event streams; the line to look for is
`*** path switch Relay -> Direct ***` — after it, messages flow over the direct QUIC path instead of the relay.

## Architecture

```mermaid
flowchart LR
    A[Agent A] -- pubkey dial --> R[Relay]
    B[Agent B] -- pubkey dial --> R
    A -- direct after punch --> B
    A -- GM-PQ hybrid session --> A2[relay path]
```

## Docs

- [Protocol specification](SPEC.md)
- [Protocol deep-dive: design rationale](docs/protocol-deep-dive.md)
- [Architecture whitepaper: the five-layer stack](docs/architecture-whitepaper.md)
- [Security considerations](SPEC.md#security-considerations)
- [p2p-mesh README](crates/p2p-mesh/README.md) · [moq-live README](crates/moq-live/README.md) · [homa-rpc README](crates/homa-rpc/README.md) · [xdp-edge README](crates/xdp-edge/README.md)
- [gm-pq-stack README](crates/gm-pq-stack/README.md)
- [Integrating the crypto stack](crates/gm-pq-stack/docs/INTEGRATION.md)
- [Changelog](CHANGELOG.md) · [Governance](GOVERNANCE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

## FAQ

**"How is Directwire different from iroh?"**

Both dial peers by public key — the difference is the layer. iroh is a
connectivity library: identity + relay + hole punching + QUIC. Directwire is a
five-layer stack built on the same idea, where the connectivity layer
(`p2p-mesh`) is deliberately an MVP whose job is to prove "identity is the
address" end-to-end. The other four crates — `gm-pq-stack` (national-crypto +
post-quantum hybrid secure channel), `moq-live` (Media over QUIC live
transport), `homa-rpc` (Homa-style message-oriented RPC over UDP),
`xdp-edge` (eBPF/XDP edge data plane for the relay infrastructure) — are the
range iroh does not ship. The upper layers do not care which mesh library sits
under them; if all you need is a P2P connectivity library, use iroh. Directwire
is for teams that want the whole agent-native transport stack with the
compliance + post-quantum position built into the wire.

**"Why not use 铜锁 (Tongsuo)?"**

Tongsuo is a TLS stack that carries the same hybrid KEM — SM2MLKEM768
(IANA NamedGroup 4590) — as a TLS 1.3 extension point. Directwire uses the
*same algorithm combination at a different layer*: the hybrid handshake **is**
the transport, not a handshake inside a TLS record layer. Above the KEM, the
session plane is SM4-GCM + replay window + stateless cookie anti-DoS +
PSK/0-RTT resumption — a complete end-to-end secure channel that upper layers
consume as *the session*, not as a TLS extension. The `kem` trait makes the PQ
leg swappable in place: when the domestic PQC national standard lands
(expected 2027–2029), ML-KEM-768 is replaced under the same trait with no
handshake or session changes. And it is dual-licensed Apache-2.0 OR
MulanPSL-2.0, so the whole stack stays integratable into domestic
commercial-cryptography deployments. Use Tongsuo when you need a TLS library;
use `gm-pq-stack` when you want the compliance + quantum property in the wire
of a *new* protocol. (Honest caveat: `gm-pq-stack` is a clean-room reference
skeleton, not certified — see its README for the compliance red lines.)

**"The P99 numbers are loopback, right?"**

Yes — and the evidence matrix labels them as such. Numbers marked 🔁 loopback
(e.g. Homa short-RPC P50 2.7× vs TCP) were measured on a single machine over
loopback: no NIC queue disciplines, no real RTT. That is why v0.3 ships two
more evidence levels: 🌐 net-sim (a deterministic relay proxy injecting real
delay/loss over real sockets — 100 ms RTT 5.34×, +1% loss 4.66×, 5% loss
0 failures) and 🐧 real kernel (xdp-edge's XDP_TX loopback on a real kernel in
CI). The honest boundary: multi-machine, real-NIC measurements are still a
TODO, and we say so. Every number in the matrix carries its measuring device;
none is a slide.

## License

Dual-licensed under **Apache-2.0** or **MulanPSL-2.0** — you may choose either.
Both are OSI-approved permissive licenses and mutually compatible; Mulan PSL
v2 is the license of record for the Chinese national-crypto ecosystem
(OpenEuler / OpenGauss family), keeping the hybrid SM2 + ML-KEM-768 stack
integratable into domestic commercial-cryptography deployments.

- [LICENSE](LICENSE) — Apache License 2.0
- [LICENSE-MULANPSL-2.0](LICENSE-MULANPSL-2.0) — 木兰宽松许可证 第2版 (Mulan PSL v2)
