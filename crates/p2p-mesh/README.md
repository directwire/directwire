# p2p-mesh — iroh-style public-key mesh networking (toB MVP)

> **Dial by public key, not by IP.** NodeId = ed25519 public key; QUIC simultaneous-open hole-punch direct, falling back to an encrypted relay, with dual-path background probing and seamless switching.

## Positioning & the asymmetry

iroh v1.0 (2026-06) validated that the "public-key addressing + hole-punch direct + relay fallback" architecture works globally. There is **no open equivalent in China** — domestic PCDN products are all closed central-scheduler schemes. The asymmetry for this project:

- **iroh validated public-internet C-side meshes; we cut down to toB private deployments**: enterprise networking / IoT device direct / private deployment. Narrower scenario = controllable NAT environment + a clear compliance boundary (no public-internet P2P bandwidth business).
- **Protocol-stack simplification**: iroh is a full production stack (discovery/mdns/0-RTT/multi-relay failover…); this MVP keeps only the four architectural primitives, fully implemented:
  1. `identity`: NodeId = ed25519 public key, SHA-256 hash display; nodes self-sign certificates (**certificate public key == identity public key**, the TLS 1.3 handshake itself authenticates identity, no CA).
  2. `relay`: encrypted relay — **forwards ciphertext only** (end-to-end AEAD), brokers handshakes (cross-sends both sides' candidate addresses), per-node traffic accounting.
  3. `holepunch`: NAT-traversal state machine — after candidates are exchanged via the relay, both sides simultaneous-open; on timeout, fall back to the relay. The state machine is IO-free and deterministically unit-tested.
  4. `path`: path manager — direct + relay coexist, periodic probing (RTT + loss rate combined into an effective score), hysteresis + dwell-time seamless switching (a simplified multipath).

## Architecture

```
            ┌───────────────────────── relay ─────────────────────────┐
            │  TCP long conn · session registry · Exchange broker ·   │
            │  AEAD ciphertext only · per-node stats (up/down/msgs)   │
            └───────▲──────────────────────────────────▲──────────────┘
        control+fallback │ Hello/PunchRequest/RelayData │   (ciphertext end-to-end)
                    │                                   │
        ┌───────────┴──────────┐          ┌───────────┴──────────┐
        │        node-a        │          │        node-b        │
        │  identity (NodeId=   │          │  identity            │
        │   ed25519 pubkey)    │          │                      │
        │  holepunch state     │  PUNCH   │  holepunch state     │
        │  path manager(dual-  │◄─UDP───► │  path manager        │
        │   path probe/switch) │ simultaneous-open              │
        │  quic: self-signed,  │          │                      │
        │   pinned pubkey      │◄═ QUIC/TLS1.3 direct ══════════►│
        └──────────────────────┘  cert pubkey == NodeId  └───────┘

  data plane routing: path.active == Relay  → AEAD ciphertext → relay forward
                     path.active == Direct → QUIC bi stream (same-socket punching, consistent NAT mapping)
```

## Quick start

```bash
cargo test                # unit + loopback end-to-end suite (relay fallback/handshake/punch upgrade/multi-peer)
cargo test --features gm-pq   # + the GM-PQ channel integration tests (pin-anchor, BIND, hybrid handshake)
cargo build --examples    # three-process demo

# terminal 1
cargo run --example relay -- --port 9100
# terminal 2 (prints NodeId hex)
cargo run --example node_b -- --relay 127.0.0.1:9100 --seed 2
# terminal 3 (paste node-b's hex)
cargo run --example node_a -- --relay 127.0.0.1:9100 --peer <node-b-hex>

# GM-PQ demo (needs --features gm-pq build; add --gmpq on both ends)
cargo run --features gm-pq --example node_b -- --relay 127.0.0.1:9100 --seed 2 --gmpq
cargo run --features gm-pq --example node_a -- --relay 127.0.0.1:9100 --peer <node-b-hex> --gmpq
```

## Stable identity (`--key-file`)

`NodeIdentity::save` / `load` / `load_or_generate` persist the ed25519 seed as a raw 32-byte file
(best-effort `0600` permissions on Unix; the file IS the identity — keep it protected, encryption at
rest is a compliance follow-up). Every example accepts `--key-file <path>`: pass the same file and
the NodeId is stable across restarts — a node restarts as itself, reachable at the same public key.
Without it, examples fall back to `--seed` (deterministic demo) or a fresh random identity per process.

```bash
# same file, restarted twice -> identical NodeId both times
cargo run --example node_b -- --relay 127.0.0.1:9100 --key-file node-b.seed
```

Expected output: first `via=Relay` message → `punch result direct=Some(...)` → `★ path switch Relay -> Direct` → subsequent `via=Direct` messages → a latency comparison table.
With GM-PQ enabled you additionally see `encrypted session ready ... suite=sm2+ml-kem-768+sm4-gcm` (otherwise `x25519+ed25519`).

## GM-PQ channel (feature = `gm-pq`, off by default)

The relay fallback path defaults to the X25519+ed25519 three-message handshake + XChaCha20-Poly1305. With feature `gm-pq` enabled, the relay path switches to
[gm-pq-stack](../gm-pq-stack) (a path dependency) with **SM2+ML-KEM-768 hybrid-KEM three-message handshake + SM4-GCM** data plane —
the relay still only ever sees ciphertext.

- **Handshake-as-message**: directly uses gm-pq-stack's pure in-memory state machines (`Initiator`/`Responder`), carried over this stack's RelayData channel (payload leading byte `0x47` marks the GM-PQ subtype); no blocking threads / pipe bridges, natively driven by the actor.
- **Role rule**: the smaller NodeId is the client (initiator), the larger is the server (responder); simultaneous initiation is naturally deduplicated.
- **DoS protection**: the server replies with a Cookie first (`CookieIssuer`, client_tag bound to the peer's NodeId); the client retries with the cookie before handshake state is allocated.
- **Identity binding**: after the handshake both sides exchange BIND (`BND1 || ed25519 NodeId || signature`), signing the message
  `b"p2p-mesh/gmpq-bind" || sm3(gm_pk) || node_id || session_id`.
  **Security semantics**: the GM-PQ handshake layer's trust anchor is pluggable. Set `NodeConfig.gmpq_pin_file`
  to pin the SM2 public keys allowed to authenticate (TOFU upgraded to explicit pinning); without it the anchor
  stays `AllowAllAnchor` (tests/demos only). BIND additionally binds the session to the authenticated ed25519
  NodeId — an MITM splitting the handshake in two gets **different session_ids**, so a forwarded BIND is rejected.
- **Pin-file trust anchor** (`NodeConfig.gmpq_pin_file`): one line per trusted peer SM2 public key,
  `name <64-hex SM3 fingerprint>` (generate fingerprints with `p2p_mesh::gmpq::pin_fingerprint`). A configured
  file that fails to load aborts `Node::start` — no silent downgrade to TOFU. Unpinned peers are rejected at the
  handshake (`Error::PeerAuth`) before any session data flows.
- **Fallback**: when the peer has GM-PQ off, channel frames are silently ignored; after a 3s timeout the X25519+ed25519 fallback kicks in automatically (`GmCheck` carries a generation counter so stale timers can't misfire).
- **Priority**: GM-PQ session ready > X25519 session > queue + initiate handshake; the direct (QUIC) path is unaffected and still uses QUIC TLS.
- **MVP cuts**: no session tickets / 0-RTT (avoids cross-connection TicketCache sharing and idempotency red lines).

## Benchmarks vs. the field

| metric | iroh v1.0 (2026-06) | Tailscale | this MVP |
|---|---|---|---|
| hole-punch global success | ~92% | >90% | loopback/LAN 100% (public NAT pending) |
| direct latency | 1-5ms | 1-5ms | same order (QUIC/UDP) |
| relay latency | 10-50ms | 10-50ms | same order (one extra TCP hop) |
| traditional VPN (full traffic via gateway) | — | — | 50-150ms+, single point of failure |

Latency three-way comparison (typical): **direct 1-5ms < relay 10-50ms ≪ traditional VPN detour 50-150ms**.

## Cost model

Let traffic be G, relay bandwidth unit price C (CNY/GB):

- all-relay: cost = G·C
- with direct share p: cost = (1-p)·G·C + punch/probe overhead (≈0)
- **p ≥ 90% (iroh's measured range) → transit cost drops 50-80%** (p=90% saves 90% of bandwidth fees; net 50-80% after reserving relay capacity and ops)

In toB private deployments the relay is customer-hosted, so the model becomes: relay server spec drops from "carries all traffic" to "carries the 10% fallback".

## Domestic compliance boundary

- **Do**: enterprise networking, IoT device direct, private deployment (customer-hosted relay); software licensing / subscription fees.
- **Don't**: public-internet P2P bandwidth business (PCDN-style traffic reselling), open relay networks for consumers, any form of bandwidth crowdfunding / revenue sharing.
- The relay forwards ciphertext only + meters per node, naturally satisfying the "unreadable, auditable" enterprise compliance requirement.

## Tech debt / known TODOs

1. ~~relay session static DH has no forward secrecy~~ ✅ done: X25519 ephemeral DH + ed25519 identity signature (Noise IK semantics), fresh keys per session. ✅ key hygiene: ephemeral `StaticSecret`/`SharedSecret` and the ed25519 `SigningKey` all zeroize on drop (the `zeroize` feature on both dalek crates; compile-time contract in `tests/key_hygiene.rs`).
2. Certificate public-key extraction still uses "SPKI prefix scanning" (rcgen's structure is fixed, reliable but not canonical parsing); x509-parser evaluated and **deferred** (pulls in a nom/asn1-rs dependency tree; compile cost doesn't match the benefit — certificates are self-signed and self-consumed only).
3. ~~loopback-only candidate addresses~~ ✅ done: STUN-like observed address (relay echoes the peer's TCP address) + local multi-NIC enumeration (UDP connect trick + hostname resolution). Residual: real STUN (UDP-session observed mapped port), NAT-type probing, IPv6.
4. ~~no concurrent multi-peer punching~~ ✅ done: punch socket and QUIC endpoint are separated and resident, the actor's built-in punch scheduler dispatches by NodeId; a unified peer table (session/path/direct/probe each independent). **New tech debt**: the punch socket ≠ the QUIC socket; on real NATs the QUIC port mapping relies on the simultaneous-open QUIC Initial opening it itself (full-cone/restricted-cone work; symmetric needs the relay); the complete fix is reusing one socket (iroh's approach).
5. The relay is a single-point TCP forwarder; no multi-relay redundancy, no QUIC-packet-over-relay (iroh DERP semantics).
6. ~~path switching uses RTT alone~~ ✅ loss rate added (effective score = RTT×(1+10×loss)). Residual: bandwidth/jitter, distinguishing congestion vs physical loss within direct RTT samples.
7. Late peer PUNCH replies after punching completes have a budget cap (5/peer); extreme asymmetric latency may require re-initiating.
8. ~~relay path X25519-only~~ ✅ done: feature `gm-pq` wires in gm-pq-stack (SM2+ML-KEM-768 hybrid handshake + SM4-GCM), X25519 kept as automatic fallback. ✅ done: `NodeConfig.gmpq_pin_file` pins the trusted SM2 keys (TOFU → explicit pinning, `Error::PeerAuth` on mismatch). Residual: no session tickets / 0-RTT; key-at-rest encryption for persisted identity files is a compliance follow-up.
