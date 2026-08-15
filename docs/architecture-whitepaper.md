# Directwire: the five-layer protocol stack

> _Architecture whitepaper from the Directwire reference implementation._ This
> is the companion to the [protocol deep-dive](protocol-deep-dive.md): the
> deep-dive explains *why the wire looks the way it does*; this paper explains
> *how the reference implementation is built as a full transport stack* — and
> why that shape is the one that survives the post-quantum standards transition.
> Last updated: 2026-08-15, for v0.2.

## The bet in one paragraph

The AI-agent era needs a networking layer whose answer to "who am I talking to?"
is a cryptographic key, not an IP, a domain, or a vendor account. That is
Directwire's thesis, and it cascades into every design decision. But a thesis is
not a product. **The product is a stack** — five layers, each a separate crate,
each independently testable, all sharing one wire. The stack spans from the
cryptographic handshake (SM2 + ML-KEM-768 hybrid KEM) all the way up to an XDP
edge gateway that DDoS-protects the relay infrastructure. No generic P2P library
ships this range; no national-crypto library ships this range; and no single
stack is simultaneously compliance-ready *and* quantum-ready *and*
agent-native. That intersection is the position.

## The five layers

| Layer | Crate | Job | Tests |
|---|---|---|---|
| **Security** | `gm-pq-stack` | Hybrid national-crypto + post-quantum secure channel: SM2+ML-KEM-768 handshake, SM4-GCM sessions, replay window, cookie anti-DoS, PSK/0-RTT resumption | 46 |
| **Connectivity** | `p2p-mesh` | Public-key mesh: dial by NodeId, relay brokering, NAT hole punching, QUIC simultaneous-open, adaptive path selection, MCP server | — |
| **Media** | `moq-live` | MoQ-lite publish/subscribe low-latency live transport: stream-per-group, priority-aware drop, catch-up | 39 (36 + 3 GM) |
| **RPC** | `homa-rpc` | Homa-style message-oriented transport over UDP + idempotent RPC: SRPT grant scheduling, 8-level QoS, at-least-once | 20 |
| **Edge** | `xdp-edge` | eBPF/XDP edge data plane: per-source token buckets, SYN-flood detection, Maglev L4 load balancing, IPIP forwarding | 31 |

≈ **180 tests** across the workspace, every one runnable locally or in CI with
`cargo test --workspace --all-features`. This is the "written best and tested
most thoroughly" claim made concrete — the thing that, during a standards
vacuum, *defines* the de facto standard.

## Layer 1 — Security: `gm-pq-stack`

The bottom layer is a complete secure-channel, not a KEM primitive. The hybrid
handshake follows the Noise-XX three-message shape, substituting the classical
leg with SM2-ECDH (GB/T 32918) and combining it with ML-KEM-768 (FIPS 203) via a
GHP18/X-Wing-style combiner over SM3. The security argument is the standard
strongest-wins guarantee: an attacker must break *both* legs. The session plane
stays in the national-crypto family — SM4-GCM AEAD, SM3-HKDF, a 64-slot sliding
replay window, a WireGuard/DTLS-style stateless cookie challenge, and PSK
session resumption with one-time-ticket replay protection. All secrets are
zeroized on drop.

The **`kem` trait abstraction** is the load-bearing design decision for the
standardization window: the PQ leg is swappable in place. When the domestic PQC
national standard lands (expected 2027–2029), the ML-KEM-768 component is
replaced under the same trait with no handshake or session-layer changes — a
regime transition without a rewrite.

### The layer-position argument

The SM2 + ML-KEM-768 combination is not an ad-hoc invention: it is the
**SM2MLKEM768** hybrid key exchange registered in the IANA TLS NamedGroup
registry (**id 4590**, proposed by the Chinese cryptographic community, already
in Alibaba Tongsuo and the ZeroTrust browser). What differentiates this stack is
not the algorithm combination — it is the **layer**:

| | Tongsuo / TLS stacks | Directwire `gm-pq-stack` |
|---|---|---|
| hybrid KEM | SM2MLKEM768 (IANA 4590) | same combination |
| transport | TLS 1.3 handshake carries the KEM | the hybrid handshake **is** the transport |
| beyond the KEM | TLS record layer | SM4-GCM sessions + replay window + cookie + PSK/0-RTT |
| scope | a KEM primitive inside a TLS stack | the complete end-to-end secure channel |

A deployment can take the whole channel in one `kem`-swappable package — and the
upper layers (connectivity, media, RPC) consume it as *the* session, not as a
TLS extension point. That is what "the wire is the product" means: the 
compliance+quantum property is in the wire, not behind a flag in a TLS stack.

## Layer 2 — Connectivity: `p2p-mesh`

Identity is the address: a NodeId **is** an ed25519 public key; peers are dialed
by NodeId and nothing else. There is no DNS, no registry, no CA, no account.
The transport has exactly two roles — **relay** (liveness: brokers candidates,
forwards ciphertext, guarantees reachability behind any NAT) and **direct**
(performance: a hole-punched QUIC path). The stack, not the agent, chooses the
path: `eff = RTT × (1 + 10 × loss)`, hysteresis, minimum dwell window, relay
kept warm so direct-path failure degrades gracefully. The hole-punch UDP socket
is the QUIC socket; simultaneous-open needs no client/server role.

Two identities meet at the session layer: NodeId is ed25519, but the hybrid
handshake authenticates an SM2 key. The **BIND** signature
(`"p2p-mesh/gmpq-bind" || SM3(gm_pk) || node_id || session_id`) defeats the
splicing MITM: `session_id` is transcript-derived, so a spliced handshake yields
different IDs on the two halves and a forwarded BIND fails the check.

The connectivity layer also ships the **MCP server** (v0.2, landed): the mesh is
exposed to agent toolchains as MCP tools over stdio. The wire format is the
contract; the MCP surface is how agents consume it. "Dial by public key" stops
being a property of the library and becomes a callable tool.

## Layer 3 — Media: `moq-live`

Live media is moving from file-segment pull (HLS/LL-HLS, 2–5 s) to object-stream
subscribe (MoQ, 0.3–1 s) — a standards transition already proven overseas
(Cloudflare runs MoQ on 330+ cities; 11 vendors interop at NAB 2026) with zero
Chinese participation. `moq-live` is a runnable MoQ-lite skeleton: varint frame
codec, namespace/track/group/object addressing, stream-per-group data plane,
relay-as-cache with catch-up semantics, and priority-aware drop decisions
(drop P-frames before I-frames under congestion). The media plane is a QUIC
subscriber graph — and, like every other layer, it can be wrapped in the
`gm-pq` hybrid session.

## Layer 4 — RPC: `homa-rpc`

Homa (Stanford) is the message-oriented transport that replaces datacenter TCP;
its upstream is a Linux kernel patch still under review. `homa-rpc` is a
**pure-userspace, over-UDP** Homa-lite: message-oriented `send_to(msg)/recv()`,
first-10KB-unscheduled window so short RPCs complete in one RTT, receiver-driven
GRANT scheduling (SRPT, overcommit K=2, anti-starvation), 8-level QoS queues,
RESEND batch retransmission, and at-least-once delivery with idempotent RPC
dedup. The two state machines (SenderCore/ReceiverCore) never touch a socket —
deterministic unit-testability is an architectural property, not an afterthought.
Loopback mixed-load benchmark: short-RPC P50 ≈ 1.7× faster than the TCP
baseline. Homa's IANA protocol number (146) stays unused — a user-space
transport needs no kernel patch, which is precisely the deployment wedge.

## Layer 5 — Edge: `xdp-edge`

The relay infrastructure is the always-on part of the network, and the always-on
part is what gets attacked. `xdp-edge` is an eBPF/XDP data plane in the
Katran/Unimog lineage: per-source token buckets, SYN-flood detection, conntrack
LRU, Maglev consistent hashing (≈1/N perturbation on backend failure), and IPIP
forwarding. The XDP program runs before skb allocation (~4 µs P99 vs ~125 µs for
the iptables path), and the control plane hot-swaps the Maglev LUT atomically.
Its dual-form delivery — kernel `bpf/` source (built with clang on Linux/CI) plus
a **Rust userspace simulator** that mirrors the exact same decision pipeline
line-by-line and verifies everything on any dev machine — is the reproducibility
discipline that makes "5.2 Mpps, no DPDK box" a testable claim, not a slide.
Measured: 4.66–4.89 Mpps software path, P50 200 ns / P99 700 ns per packet.

## The cross-cutting properties

- **Identity is the address** — one decision, every layer.
- **Encrypted by default, hybrid-hardened** — the relay holds no keying
  material; a fully compromised relay can only drop or meter, never decrypt.
- **Reproducibility as policy** — the Code of Conduct forbids benchmark claims
  without reproducible methodology; every number in this paper comes with its
  measuring harness.
- **Standards alignment as design** — IANA 4590 today, GM/T swappability
  tomorrow, IETF MoQ/Homa drafts as reference points; the roadmap's third stage
  (per GOVERNANCE.md) tracks IETF drafts and national crypto standards directly.

## Where this sits vs. the field

| | Generic P2P (iroh / libp2p) | National-crypto stacks (Tongsuo) | **Directwire** |
|---|---|---|---|
| Identity | public key | cert/account | public key (NodeId = ed25519) |
| Post-quantum session | roadmap | some TLS hybrid KEMs | **in the wire** (ML-KEM-768) |
| National-crypto family | absent | native | native (SM2/SM3/SM4-GCM) |
| Layer scope | transport | KEM inside TLS | **complete stack**: crypto → mesh → media → RPC → edge |
| Agent-native surface | SDK | TLS library | **MCP server** |
| Compliance + quantum markets | excluded | compliance only | **both, as the primary wedge** |

## The window

Domestic PQC deployment in critical infrastructure is ≈ 0%; a domestic national
standard is expected 2027–2029. NIST deprecates pure-classical algorithms by
2030; overseas PQ traffic share is already > 60%. In the vacuum, the de facto
standard is written by whoever writes it best and tests it most thoroughly.
Directwire's claim is the shape that wins: one stack, five layers, ~180 tests,
every layer independently verifiable, one wire that is simultaneously
compliance-ready and quantum-ready and agent-native. The standards land; the
wire is already there.

## Honest limits (v0.2)

- **Reference crypto is not certified.** `gm-pq-stack` is an
  architecture-validation skeleton; MLPS evaluation and
  commercial-cryptography certification are explicit red lines. Production
  deployments must swap in certified crypto modules / crypto cards for key
  operations.
- **Homa's long-message concurrency is the weakest layer** — single IO thread,
  grant-scheduling latency; io_uring/AF_XDP bypass and multi-thread IO are
  open directions.
- **MoQ-lite is a subset of draft-ietf-moq-transport-17** — no datagram tracks
  yet, single-publisher topology, no cross-relay dedup.
- **xdp-edge's control plane is a skeleton** — live probes are virtual-clock
  driven; real traffic is a roadmap item.
- **Identity is not yet persistent or recoverable** — keys are generated at
  process start.

## What to read next

- [Protocol deep-dive](protocol-deep-dive.md) — the wire-format rationale
- [SPEC.md](../SPEC.md) — the normative contract
- [gm-pq-stack README](../crates/gm-pq-stack/README.md) — standards alignment,
  benchmarks, compliance red lines
- [Governance](../GOVERNANCE.md) — three-stage model incl. standards-track stage
