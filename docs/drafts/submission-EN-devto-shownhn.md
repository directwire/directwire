# We built a five-layer protocol stack: national-crypto + post-quantum + agent-native

> **Draft — not published.** Target channels: dev.to / Show HN (HN title at the
> bottom is 80 chars, the limit). Everything factual in this post traces to the
> [v0.3 evidence-chain release](https://github.com/directwire/directwire/releases/tag/v0.3)
> and the [architecture whitepaper](https://github.com/directwire/directwire/blob/main/docs/architecture-whitepaper.md).
> Directwire is an anonymous org; no personal author block.

**TL;DR —** We built the networking layer agents need to talk to each other
*without a broker*, as a full five-layer stack in Rust. Security: SM2 +
ML-KEM-768 hybrid secure channel. Connectivity: public-key mesh, dial by
NodeId. Media: Media-over-QUIC live transport. RPC: Homa-style message-oriented
RPC over UDP. Edge: an eBPF/XDP gateway that defends the relay
infrastructure. Each layer is a separate crate, independently testable, all
sharing one wire. v0.3's rule: **every claim carries its measuring device**
(loopback / net-sim / real kernel). No number in this post is a slide.

---

## The bet

The AI-agent era needs a networking layer whose answer to *"who am I talking
to?"* is a cryptographic key — not an IP, not a domain, not a vendor account.
That is the thesis. But a thesis is not a product. **The product is a stack.**

No generic P2P library ships this range. No national-crypto library ships this
range. The position is the intersection: one stack that is simultaneously
**compliance-ready**, **post-quantum-ready**, and **agent-native**.

## The five layers

| Layer | Crate | Job | Tests |
|---|---|---|---|
| **Security** | `gm-pq-stack` | Hybrid national-crypto + post-quantum secure channel: SM2+ML-KEM-768 handshake, SM4-GCM sessions, replay window, cookie anti-DoS, PSK/0-RTT resumption | 46 |
| **Connectivity** | `p2p-mesh` | Public-key mesh: dial by NodeId, relay brokering, NAT hole punching, QUIC simultaneous-open, adaptive path selection, MCP server | — |
| **Media** | `moq-live` | MoQ-lite publish/subscribe live transport: stream-per-group, priority-aware drop, catch-up | 39 |
| **RPC** | `homa-rpc` | Homa-style message-oriented transport over UDP + idempotent RPC: SRPT grant scheduling, 8-level QoS, at-least-once | 20 |
| **Edge** | `xdp-edge` | eBPF/XDP edge data plane: per-source rate limiting, SYN-flood detection, Maglev L4 load balancing, IPIP forwarding | 31 |

≈ **180 tests** across the workspace, every one runnable locally or in CI with
`cargo test --workspace --all-features`. During a standards vacuum, the de
facto standard is whoever writes it best and tests it most thoroughly.

## Layer by layer

### 1. Security — `gm-pq-stack`

Not a KEM primitive — a complete secure channel. The hybrid handshake follows
the Noise-XX three-message shape: the classical leg is SM2-ECDH (GB/T 32918),
combined with ML-KEM-768 (FIPS 203) via a GHP18/X-wing-style combiner over SM3.
Security argument is strongest-wins: an attacker must break *both* legs. The
session plane stays in the national-crypto family — SM4-GCM AEAD, SM3-HKDF, a
64-slot sliding replay window, stateless cookie challenge, PSK resumption.

The load-bearing design decision: a **`kem` trait** makes the PQ leg swappable
in place. When the domestic PQC national standard lands (expected 2027–2029),
ML-KEM-768 is replaced under the same trait with no handshake or session
changes — a regime transition without a rewrite.

The algorithm combination itself is **not** ad-hoc: it is the **SM2MLKEM768**
hybrid key exchange registered in the IANA TLS NamedGroup registry (id 4590),
already in Alibaba Tongsuo and the ZeroTrust browser. What we differentiate on
is the *layer*: the hybrid handshake **is** the transport, not an extension
point inside a TLS stack.

### 2. Connectivity — `p2p-mesh`

**Identity is the address**: a NodeId *is* an ed25519 public key; peers are
dialed by NodeId and nothing else — no DNS, no registry, no CA, no account. Two
roles: **relay** (liveness) and **direct** (a hole-punched QUIC path). The
stack, not the agent, chooses the path: `eff = RTT × (1 + 10 × loss)`, with
hysteresis and a minimum dwell window; the relay stays warm so direct-path
failure degrades gracefully. The hole-punch UDP socket is the QUIC socket;
simultaneous-open needs no client/server role.

Two identities meet at the session layer — NodeId is ed25519, but the hybrid
handshake authenticates an SM2 key. A **BIND signature**
(`"p2p-mesh/gmpq-bind" || SM3(gm_pk) || node_id || session_id`) defeats the
splicing MITM: `session_id` is transcript-derived, so a spliced handshake
yields different IDs on the two halves and a forwarded BIND fails the check.

The layer also ships an **MCP server**: the mesh is exposed to agent toolchains
as MCP tools over stdio. "Dial by public key" stops being a library property
and becomes a callable tool.

### 3. Media — `moq-live`

Live media is moving from file-segment pull (HLS, 2–5 s) to object-stream
subscribe (MoQ, 0.3–1 s) — a standards transition already proven overseas
(Cloudflare runs MoQ on 330+ cities; 11 vendors interop at NAB 2026) with zero
Chinese participation. `moq-live` is a runnable MoQ-lite skeleton: varint
frame codec, namespace/track/group/object addressing, stream-per-group data
plane, relay-as-cache with catch-up, priority-aware drop (drop P-frames before
I-frames under congestion). And — like every other layer — it can be wrapped in
the `gm-pq` hybrid session.

### 4. RPC — `homa-rpc`

Homa (Stanford) is the message-oriented transport that replaces datacenter
TCP; its upstream is a Linux kernel patch still under review. `homa-rpc` is a
**pure-userspace, over-UDP** Homa-lite: message-oriented `send_to(msg)/recv()`,
a first-10KB-unscheduled window so short RPCs complete in one RTT,
receiver-driven GRANT scheduling (SRPT, overcommit K=2, anti-starvation),
8-level QoS queues, RESEND batch retransmission, at-least-once delivery with
idempotent RPC dedup. The two state machines (SenderCore/ReceiverCore) never
touch a socket — deterministic unit-testability is an architectural property,
not an afterthought.

Loopback mixed-load benchmark (550 calls, 91% 100 B short + 9% 1 MiB long,
8 workers): short-RPC **P50 2.7×** faster than the TCP baseline (520 µs vs
1.4 ms), P90 1.9× / P99 1.2×, total wall time **30%** faster. Long RPCs pay the
SRPT tax (~1.7× slower) — the structural price of letting short messages jump
the grant queue. Homa's IANA protocol number (146) stays unused: a user-space
transport needs no kernel patch, which is precisely the deployment wedge.

### 5. Edge — `xdp-edge`

The relay infrastructure is the always-on part of the network, and the
always-on part is what gets attacked. `xdp-edge` is an eBPF/XDP data plane in
the Katran/Unimog lineage: per-source token buckets, SYN-flood detection,
conntrack LRU, Maglev consistent hashing (≈1/N perturbation on backend
failure), IPIP forwarding. The XDP program runs before skb allocation
(third-party-measured ~4 µs P99 vs ~125 µs iptables), and the control plane
hot-swaps the Maglev LUT atomically.

Its dual-form delivery is the reproducibility discipline: a kernel `bpf/`
source (built with clang in CI) **plus a Rust userspace simulator that mirrors
the exact same decision pipeline line-by-line** and verifies everything on any
dev machine. That is what makes "5.2 Mpps, no DPDK box" a testable claim, not a
slide. Measured: 4.66–4.89 Mpps software path, P50 200 ns / P99 700 ns per
packet.

## The evidence matrix (v0.3)

Every number carries a measuring device. 🔁 loopback · 🌐 net-sim (deterministic
delay/loss injection over real sockets — an 80% stand-in for a multi-machine
testbed) · 🐧 real kernel · ✅ CI · 📚 third-party.

| # | Claim | Evidence | Level |
|---|---|---|---|
| 1 | ≈180 tests, every layer independently verifiable | `cargo test --workspace --all-features` in CI | ✅ CI |
| 2 | Homa short RPC beats TCP: P50 2.7× / P90 1.9× / P99 1.2×, wall time −30% | loopback mixed load (550 calls, 91% short + 9% long) | 🔁 loopback |
| 3 | Long message 38 ms → 4.6 ms in one hardening pass (≈16× total from 73 ms) | benchmark + `trace_probe`/`mix_probe` timelines | 🔁 loopback |
| 4 | 100 ms RTT long RPC **5.34×** vs TCP (322 ms vs 1 717 ms) | net-sim `net_probe`, 100 ms-RTT profile | 🌐 net-sim |
| 5 | 100 ms RTT + 1% loss still **4.66×** | net-sim 1%-loss profile | 🌐 net-sim |
| 6 | Short-RPC single-packet-loss dead zone closed: P99 5.1 s → **453 ms**, zero extra retrans on clean links | net-sim + deterministic unit test | 🌐 net-sim + ✅ |
| 7 | 10 ms RTT + 5% loss: **0 failures** in 273 short RPCs (v0.1: 2 failures, P99 ≈10 s) | net-sim 5%-loss profile | 🌐 net-sim |
| 8 | xdp-edge data plane runs correctly on a real kernel | bpf CI: veth load (=verifier accepts the program) + **XDP_TX loopback** through the full parse→ratelimit→conntrack→Maglev→IPIP→XDP_TX chain | 🐧 real kernel |
| 9 | 74 B IPIP frame byte-exact | veth drops `adjust_head` edits on the runner kernel (documented quirk); bytes verified by the Rust simulator, full-content asserts kept on kernels that preserve edits | 🔁 simulator |
| 10 | Katran-class ~5.2 Mpps "no DPDK box" → measured 4.66–4.89 Mpps | xdp-edge `benchmark` example (10⁷ packets, single thread, release) | 🔁 simulator |
| 11 | XDP P99 ~4 µs vs iptables ~125 µs | third-party public measurement (cited, not our run) | 📚 third-party |
| 12 | Maglev backend-failure perturbation ≈1/N, live-connection migration <1% | unit/integration tests | 🔁 simulator |
| 13 | fuzz: 5 targets, 10 min, zero crashes (~10⁹ iterations) | fuzz CI (libFuzzer smoke + nightly) | ✅ CI |
| 14 | gmpq keygen out of the iteration budget | `KeyPool` OnceLock pre-generates 8+8 keys; probes reach deep decap/AEAD-open states | ✅ code + test |

## The 16× hardening story

One 1 MiB RPC over loopback: **73 ms in the first cut → 38 ms after the
baseline pass → 4.6 ms now. ≈16×.**

What it took:

1. **GSO send batching + GRO recv batching** — fewer syscalls per fragment.
2. **ahashed hot maps** — the per-packet lookup paths.
3. **Zero-copy send** — the API takes a moved `Vec`, sends borrowed slices.
4. **Fixed worker pool** — no per-call thread churn on the server side.

And the part we're prouder of: we had a hypothesis that the next win was
"move packet construction out of the io_loop lock." We measured it instead of
refactoring on vibes — `io_lock_avg_batch` 16.9 µs held, **0.6 µs** wait. The
lock was never the bottleneck. The real cost is one memcpy per fragment
(`Packet::encode`, ~250 ns × 874 ≈ 200 µs per 1 MiB direction). The true fix is
`sendmsg` with a header iovec + payload slice (kernel gather). That's a ~20%
win on the transport's core path, so it ships with the multi-machine testbed,
not on single-machine loopback. **Measure first, then move.**

## Honest limits

- `gm-pq-stack` is a clean-room reference skeleton, **not certified** — MLPS
  evaluation and commercial-cryptography certification are explicit red lines;
  production must swap in certified modules.
- Homa's long-message concurrency is the weakest layer: single IO thread;
  io_uring/AF_XDP bypass and multi-thread IO are open directions.
- `moq-live` is a subset of draft-ietf-moq-transport-17: no datagram tracks,
  single-publisher topology, no cross-relay dedup.
- `xdp-edge`'s control plane is a skeleton; live probes are virtual-clock
  driven.
- **Multi-machine, real-NIC measurements are still a TODO** — net-sim is an
  80% stand-in, and we label it as such.

## Try it

```bash
git clone https://github.com/directwire/directwire
cd directwire
cargo test --workspace --all-features   # ~180 tests
cargo run --release -p homa-rpc --example benchmark    # loopback vs TCP
cargo run --release -p homa-rpc --example net_probe    # net-sim profiles
```

—

**Directwire** — an open protocol and reference implementation for direct,
encrypted, server-independent communication between AI agents. **Dial by
public key, not by IP.**

- GitHub: https://github.com/directwire/directwire
- v0.3 release (the evidence matrix above, with reproduce commands):
  https://github.com/directwire/directwire/releases/tag/v0.3

---

*Post title notes for submission:*
- dev.to: use the full title above.
- Show HN title (80 chars max): **"We built a 5-layer protocol stack:
  national-crypto + post-quantum + agent-native"** — exactly 80 chars.
