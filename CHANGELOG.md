# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] — 2026-08-16

> **Evidence chain release** — every white-paper claim now carries its measuring
> harness: loopback benchmark, deterministic network simulation, real-kernel
> eBPF/XDP verification, or an explicit TODO. The claim→evidence matrix lives in
> the GitHub Release notes for this tag.

### Added

- **net-sim — deterministic network simulator** (`homa-rpc` `net_probe` example):
  real sockets + a seedable relay proxy injecting delay/loss — the same code
  paths, only the network is synthetic, an ~80% stand-in for a multi-machine
  testbed. Evidence in `docs/benchmarks/net-sim-v0.2.md`: 100 ms RTT 1 MiB long
  RPC **5.34×** vs TCP (322 ms vs 1.7 s), 1% loss still **4.66×**, 5% loss
  **0 failures** across 273 short RPCs, short-RPC single-packet-loss dead zone
  P99 **5.1 s → 453 ms**.
- **fuzz framework**: deterministic `fuzz-harness` engine (splitmix64, in-process
  driver, smoke tests) + `cargo-fuzz` adapters, 5 targets (homa_transport /
  moq_message / gmpq_handshake / p2p_proto / xdp_pipeline), CI smoke (10 min per
  PR) + nightly long-run (2 h), crash artifacts auto-uploaded. gmpq key corpus
  pre-generation (keygen out of the iteration budget, ~1.4× iteration gain) plus
  deep-state probes: golden mutual auth, PSK resumption, 0-RTT round-trip,
  stateless cookie challenge.
- **IETF Internet-Draft** `draft-directwire-agent-transport-00` (RFC 7991 v3
  XML, pure-python `xml2rfc` build → txt/html, idnits preflight in CI). Author
  block is the anonymous-org placeholder (`draft-directwire@directwire.example`);
  datatracker submission is a tracked TODO.
- **xdp-edge real-kernel verification**: GitHub Actions job compiles
  `xdp_edge.o` (clang `-target bpf`, `-Wall -Werror`), loads it onto a veth pair
  (load = the kernel verifier accepted the program), and drives the full
  datapath on a real kernel — per-source token-bucket rate drop, SYN-flood
  detection, conntrack, Maglev, IPIP encapsulation, XDP_TX delivery. XDP_TX only
  fires after successful encapsulation, so the original frame returning to the
  injection veth is itself the proof that the entire
  parse→ratelimit→conntrack→Maglev→IPIP→XDP_TX chain ran on the real kernel.
- **`docs/architecture-whitepaper.md`** — five-layer architecture paper
  (crypto → mesh → media → RPC → edge), the standards-position argument, honest
  limits, and the evidence chain for every benchmark number.

### Changed

- `homa-rpc` long-message hardening pass: UDP GSO/GRO batching, ahashed
  completed-cache and incoming maps, zero-copy send path (moved frames,
  borrowed bodies), and a fixed 32-worker handler pool replacing per-request
  thread spawn. Mixed-load benchmark (91% 100 B short + 9% 1 MiB long, 8
  workers): short-RPC P50 2.7× faster than TCP (520 µs vs 1.4 ms), P90 1.9× /
  P99 1.2× faster; long-RPC P50 38 ms → 4.6 ms; total wall time 30% faster
  (66 ms vs 94 ms). Added `trace_probe`/`mix_probe` diagnostic timelines;
  removed scratch spikes.
- `homa-rpc` 「确认前重发」 window closes the short-message single-packet-loss
  dead zone (P99 ≈ 5.1 s → 453 ms) with **zero extra retransmission on loss-free
  links** (deterministic unit test + ideal-profile bench both prove it).
- `xdp-edge` bpf datapath test degrades gracefully on runner kernels whose veth
  XDP_TX drops `bpf_xdp_adjust_head` edits: the frame's 74 B IPIP bytes are then
  covered by the Rust simulator instead (byte-exact), while stats + loopback
  delivery still prove the chain on the real kernel.
- `fuzz-harness` gmpq target: static key-pool pre-generation + legal-msg3 corpus
  seeds, so iterations reach `read_msg3` decapsulate/AEAD-open (deep states)
  instead of stalling on keygen or the length gate.

## [0.2.0] — 2026-08-15

### Added

- **`moq-live` crate**: MoQ-lite low-latency media transport — pub/sub tracks,
  stream-per-group data plane, relay-as-cache with GOP-boundary catch-up,
  priority drop queue (drop P, protect I), track-alias header compression,
  full control plane (UNSUBSCRIBE / SUBSCRIBE_ERROR / ANNOUNCE_OK / GOAWAY),
  pinned-certificate TLS.
- **`homa-rpc` crate**: Homa-style message-oriented RPC transport — connectionless,
  receiver-driven GRANT scheduling (SRPT with preemption), 8-level priority
  queues with real sender-side QoS, unscheduled first-RTT window, RESEND
  state machine, at-least-once RPC with idempotency dedup.
- **`xdp-edge` crate**: eBPF/XDP edge gateway data plane — XDP C source
  (Maglev LB, per-source token bucket, SYN-flood detection, conntrack,
  IPIP forwarding) plus a semantically aligned Rust userspace simulator
  (~5 Mpps single-thread), control-plane agent skeleton (health checking,
  lock-free LUT hot-publish, TTL sweeping), Prometheus metrics export,
  `ci/verify.sh` for Linux build/load verification.
- **`gm-pq` integration feature** in `moq-live` and `p2p-mesh`: the gm-pq-stack
  hybrid (SM2 + ML-KEM-768) session layer now protects MoQ control/data
  streams and mesh relay paths (0-RTT resumption verified end-to-end).
- Ecosystem scaffolding: CODE_OF_CONDUCT.md, GOVERNANCE.md, FUNDING.yml.

### Changed

- `p2p-mesh`: forward-secret relay sessions (ephemeral X25519 + ed25519
  identity signatures replace static DH); STUN-like observed-address
  discovery; concurrent multi-peer peer table; loss-aware path selection.
- `homa-rpc`: long-RPC pacing fixed (single 1 MiB RPC 73 ms → ~10 ms);
  anti-starvation overcommit; benchmark scaled to 500 short + 50 long × 1 MiB.
- `gm-pq-stack`: WireGuard-style stateless cookie challenge; PSK ticket
  resumption with 0-RTT; TrustAnchor trait with pin-file implementation;
  zeroize on all secrets; `docs/INTEGRATION.md` downstream contract.

## [0.1.0] — 2026-08-14

- Initial public release: `gm-pq-stack` + `p2p-mesh`, SPEC.md, CI, demos.
