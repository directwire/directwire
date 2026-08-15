# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- `homa-rpc` long-message hardening pass: UDP GSO/GRO batching, ahashed
  completed-cache and incoming maps, zero-copy send path (moved frames,
  borrowed bodies), and a fixed 32-worker handler pool replacing per-request
  thread spawn. Mixed-load benchmark (91% 100 B short + 9% 1 MiB long, 8
  workers): short-RPC P50 2.7× faster than TCP (520 µs vs 1.4 ms), P90 1.9× /
  P99 1.2× faster; long-RPC P50 38 ms → 4.6 ms; total wall time 30% faster
  (66 ms vs 94 ms). Added `trace_probe`/`mix_probe` diagnostic timelines;
  removed scratch spikes.

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
