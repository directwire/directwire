# Directwire Protocol Specification (draft v0.1)

> Status: **informative draft**. This document describes the target protocol and the behavior of the reference implementation. It is not yet a normative standard. Comments welcome via issues.

> Standards-facing snapshot: `ietf/draft-directwire-agent-transport-00.xml` (buildable IETF Internet-Draft, RFC 7991 v3; see `ietf/README.md`). This SPEC.md remains the living source of truth for protocol content.

## 1. Scope

This specification defines a transport layer for autonomous agents to discover, authenticate, and communicate with each other using cryptographic identities, without a central server or IP-based addressing as the primary identity.

## 2. Conventions

- Byte order: big-endian unless noted.
- Domain-separated protocol labels are fixed ASCII byte strings. They are part of the wire contract: **changing a label is a breaking change** and MUST be accompanied by a version bump.
- "MUST", "MUST NOT", "SHOULD" are to be interpreted as described in RFC 2119.

## 3. Identity

- Each node has an **ed25519 key pair**; the **Node ID** is the 32-byte ed25519 public key and is the address used for dialing.
- A node may additionally hold an **SM2 static key** bound to the ed25519 Node ID via a BIND signature. The binding prevents an active MITM from splicing a different SM2 key into the same identity.
- Identity is **public-key-first**: no DNS, no registry, no revocation list in the base protocol. Trust is established by key pinning / out-of-band fingerprint verification (TOFU in the reference implementation; production deployments SHOULD pre-pin peer public keys).

## 4. Transport

- Default transport: UDP. A node binds zero or more candidate endpoints (local interface addresses, observed addresses).
- A **relay** provides liveness: it forwards encrypted traffic between peers that cannot establish a direct path, and brokers candidate exchange.

### 4.1 Relay control frames

The relay connection is a TCP stream. Frames are length-prefixed (u32 BE length + payload). Control frames:

| frame | fields | meaning |
|---|---|---|
| `Hello` | `node_id` (32B), `cands` | register session + candidate addresses |
| `HelloAck` | `observed` (SocketAddr) | STUN-like echo of the peer's TCP source address |
| `PunchRequest` | `target` (NodeId) | ask the relay to broker both sides' candidates |
| `Exchange` | `peer` (NodeId), `cands` | relay cross-sends the peer's candidate set |
| `RelayData` | `to`, `from`, `payload` | forwarded ciphertext; `from` is overwritten from the connection identity (anti-spoofing) |
| `Error` | `msg` (string) | "first frame must be Hello", "target is not online", "recipient is not online" |
| `StatsQuery` / `StatsReport` | `text` | per-node traffic accounting |

Candidate addresses carry a type tag: `CAND_PUNCH` (hole-punch UDP) and `CAND_QUIC` (direct QUIC).

## 5. Hole punching (NAT traversal)

- Peers exchange candidate endpoints via the relay (`Exchange`), STUN-like observed address included.
- Each side sends **PUNCH** UDP packets to the peer's candidate set. A PUNCH packet is `PMP1` (4B magic) + NodeId (32B); the receiver dispatches it to the matching state machine by sender NodeId.
- On receiving a PUNCH from a candidate address, a peer establishes the direct path and replies. Successful exchange ⇒ direct path up.
- Failure or late arrival of a PUNCH MUST NOT wedge the session: the state machine falls back to the relay path. After completion, a small reply budget (default 5/peer) answers late PUNCH packets so an asymmetric peer can finish.

## 6. Session establishment

### 6.1 Default (relay path) handshake — X25519 + ed25519

A two-message handshake over the relay channel, Noise-IK-style ephemeral DH with identity signatures:

| message | wire form | purpose |
|---|---|---|
| `HS_INIT` | `HS_TAG` (0x48) `HS_KIND_INIT` (0x01) + ephemeral X25519 pk (32B) + NodeId (32B) + ed25519 signature | initiator proves identity, sends ephemeral |
| `HS_RESP` | `HS_TAG` (0x48) `HS_KIND_RESP` (0x02) + ephemeral X25519 pk (32B) + NodeId (32B) + ed25519 signature + AEAD envelope | responder proves identity, replies |

On success, transport keys are split from the DH shared secret and the identities; the transcript hash becomes the session ID. A ciphertext arriving before the handshake completes is dropped.

### 6.2 Optional GM-PQ channel (feature `gm-pq`)

When enabled on both sides, the relay path uses the hybrid handshake from `gm-pq-stack`: **SM2 + ML-KEM-768 hybrid KEM**, SM3 transcript, SM4-GCM data plane. Frames are relay payloads tagged with leading `GM_TAG` (0x47):

| subtype | meaning |
|---|---|
| `GM_KICK` (0x4B) | wake the peer and signal GM-PQ intent |
| `GM_MSG1` (0x01) | client ephemeral public key |
| `GM_COOKIE` (0x02) | stateless cookie challenge (DoS protection) |
| `GM_MSG1_RETRY` (0x03) | client echoes the cookie + retries MSG1 |
| `GM_MSG2` (0x04) | server response (hybrid ciphertext + AEAD identity) |
| `GM_MSG3` (0x05) | client final (hybrid ciphertext + AEAD identity + SM2 signature) |
| `GM_DATA` (0xD0) | encrypted session payload |

**Role rule**: the smaller NodeId is the client (initiator), the larger is the server (responder); simultaneous initiation is naturally deduplicated.

**Identity binding**: after the handshake both sides send **BIND** as the first ciphertext: `BND1` + ed25519 NodeId + signature over
`b"p2p-mesh/gmpq-bind" || sm3(gm_pk) || node_id || session_id`.
The handshake layer is TOFU (SM2 keys not pre-authenticated), but BIND strongly binds the session to the authenticated ed25519 identity — an MITM splicing two half-handshakes would obtain different session IDs, so a forwarded BIND is rejected. Production SHOULD replace TOFU with a pinned SM2 anchor.

**Fallback**: if the peer has GM-PQ off, channel frames are silently ignored; after a 3s timeout the implementation falls back to the §6.1 X25519 handshake (generation-tagged timer prevents stale-fire).

**Forward-secrecy guarantee**: breaking the hybrid session requires breaking both the classical (SM2) and the post-quantum (ML-KEM-768) components (X-Wing/GHP18 combiner, SM3 as random oracle).

### 6.3 Direct path — QUIC/TLS 1.3

The QUIC endpoint self-signs a certificate whose **public key equals the Node ID**. The connecting side pins the certificate to the expected NodeId (dial-by-public-key); the server side validates structural validity only. `ALPN = b"p2p-mesh/0"`, SAN `node.p2p-mesh.local`. Hole punching and QUIC run on the same UDP socket, so the opened NAT mapping serves both. Simultaneous-open: both sides connect and accept; the smaller NodeId's outbound connection is canonical, duplicates are closed (`b"duplicate"`, `b"superseded"`).

## 7. Message framing

- Messages carry a monotonically increasing 64-bit sequence number used as AEAD nonce entropy.
- The receiver maintains a 64-slot sliding replay window: duplicate or too-old sequence numbers are rejected; reordering of up to 64 messages is allowed (suitable for UDP / multi-path).
- Relay inner plaintexts are tagged: `INNER_DATA` (0x01) application message, `INNER_PING` (0x02) / `INNER_PONG` (0x03) keepalive probes.

## 8. Path selection

- Paths are scored by RTT and loss (effective score = RTT × (1 + 10 × loss)), with hysteresis and a minimum dwell time to prevent flapping.
- Path states: `relay` (initial), `direct` (after punch), with fallback to `relay` if the direct path degrades or drops. Switching is seamless: queued messages are flushed over the new path.

## 9. Security considerations

- **0-RTT early data has no full forward secrecy** and may be replayed within the crash window; application MUST treat early data as idempotent.
- **The relay sees only ciphertext.** The relay cannot decrypt, authenticate, or inspect agent traffic; it only forwards and meters.
- **Post-quantum readiness:** breaking the hybrid session requires breaking both the classical (SM2/ECDH) and the post-quantum (ML-KEM-768) components.
- **Reference implementation scope:** the crypto modules are an architecture-validation skeleton and are NOT formally certified; see `gm-pq-stack` README for the compliance red lines (commercial-crypto product certification, MLPS evaluation).
- Known limitations and open TODOs are tracked in each crate's README.

## 10. Versioning

This document is versioned; breaking changes will be accompanied by a domain-separated protocol label bump.

## Appendix A. v0.3 candidate — explicit DONE message replacing implicit ACK

**Status: design note / candidate. Not part of the current wire format (v0.2).**

### Background: the short-message loss dead-zone (v0.2 problem)

For messages entirely within the unscheduled window (< 10 KB), the receiver issues no GRANT
and reassembles the message from the first packet(s) alone. If such a message's first packet
is lost, the receiver **has never seen the message** and therefore cannot send RESEND; the
sender cannot know the message is lost without some acknowledgment.

v0.2 closes this with an **implicit ACK**: the RPC response doubles as the request's
acknowledgment. The transport keeps the finished request in a `retransmit` window
(`retransmit_timeout`, conservative RTT estimate, default 500 ms) and re-sends chunk 0 if
no `confirm()` arrived; the receiver uses the re-sent chunk 0 to (re)establish reassembly
and drive the rest via GRANT/RESEND. This is entirely sender-side (no wire change) and
provably adds zero extra traffic when there is no loss (unit test `无丢包_confirm后_重发窗口零触发`).

### Why a candidate at all

The implicit-ACK design has three structural costs:

1. **Response loss is handled at the RPC layer, not the transport.** If the response is
   lost, the request's transport message is confirmed anyway, and recovery falls to the
   client's at-least-once retry (`attempt_timeout`) + server idempotent replay. That works,
   but the RPC layer must stay `attempt_timeout > retransmit_timeout + RTT` to avoid racing
   the sender's own poke — a coupling the transport shouldn't need.
2. **Only RPC requests get the window.** `send_vec` (responses) does not retransmit;
   a response whose first packet is lost must wait for the client to re-request. The
   transport is not self-contained.
3. **`confirm()` is an RPC-layer concept.** The transport cannot tell "delivered" from
   "still in flight" without being told by an upper layer.

### Candidate design (v0.3)

- Add a **DONE** control message (`PacketType::Done`), sent by the receiver once it has
  reassembled a complete message: `msg_id` (+ optional cumulative fingerprint/checksum).
- The sender treats DONE as the release condition: removes the message from its state
  immediately (no linger, no retransmit window) — the wire now carries explicit delivery
  confirmation instead of inferring it from an application response.
- This makes request and response loss symmetric: both are transport-confirmed, and the
  RPC layer's `attempt_timeout` becomes a pure backstop for a *lost DONE* (recoverable by
  the existing at-least-once retry) rather than the primary recovery path.

### Trade-offs (why v0.2 shipped without it)

- **Wire change**: new packet type, version/label bump (§10). v0.2 deliberately kept the
  wire format untouched (sender-only fix).
- **More receiver state**: must track delivered `msg_id`s to emit DONE and avoid
  DONE-storms on reordered delivery.
- **DONE loss handling**: a lost DONE reintroduces the window it was meant to remove —
  needs its own re-request or timeout, trading one ack mechanism for another.
- **Idempotent-replay value proposition unchanged**: at-least-once semantics already make
  application-level dedup mandatory; DONE removes transport reliance on it but does not
  remove the application requirement.
