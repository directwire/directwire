# Directwire Protocol Specification (draft v0.1)

> Status: **informative draft**. This document describes the target protocol and the behavior of the reference implementation. It is not yet a normative standard. Comments welcome via issues.

## 1. Scope

This specification defines a transport layer for autonomous agents to discover, authenticate, and communicate with each other using cryptographic identities, without a central server or IP-based addressing as the primary identity.

## 2. Conventions

- Byte order: big-endian unless noted.
- All cryptographic hashes are SM3 (32-byte output).
- "MUST", "MUST NOT", "SHOULD" are to be interpreted as described in RFC 2119.

## 3. Identity

- Each node has an **ed25519 key pair**; the **Node ID** is derived from the public key and is the address used for dialing.
- A node may additionally hold an **SM2 static key** bound to the ed25519 Node ID via a BIND signature. The binding prevents an active MITM from splicing a different SM2 key into the same identity.
- Identity is **public-key-first**: no DNS, no registry, no revocation list in the base protocol. Trust is established by key pinning / out-of-band fingerprint verification (TOFU in the reference implementation; production deployments SHOULD pre-pin peer public keys).

## 4. Transport

- Default transport: UDP.
- A node binds zero or more candidate endpoints (local interface addresses, observed addresses).
- A **relay** provides liveness: it forwards encrypted traffic between peers that cannot establish a direct path, and brokers candidate exchange.

## 5. Hole punching (NAT traversal)

- Peers exchange candidate endpoints via the relay (STUN-like observed address included).
- Each side sends PUNCH messages to the peer's candidate set; a successful exchange establishes a direct path.
- Failure or late arrival of a PUNCH MUST NOT wedge the session: the state machine falls back to the relay path.

## 6. Session establishment

- **Forward-secrecy handshake:** ephemeral X25519 + ML-KEM-768 hybrid key agreement, with the ephemeral keys signed/bound to the ed25519 identity.
- The optional **gm-pq session layer** (feature `gm-pq`) runs a hybrid handshake over the established channel: SM2 + ML-KEM-768 hybrid KEM, stateless cookie challenge for DoS resistance, one-time PSK ticket for 0-RTT resumption, and a client public-key fingerprint binding to prevent ticket theft.
- On success, transport keys are split from the handshake transcript; the transcript hash becomes the **session ID**.

## 7. Message framing

- Messages carry a monotonically increasing 64-bit sequence number used as AEAD nonce entropy.
- The receiver maintains a 64-slot sliding replay window: duplicate or too-old sequence numbers are rejected; reordering of up to 64 messages is allowed (suitable for UDP / multi-path).

## 8. Path selection

- Paths are scored by RTT and loss, with a minimum dwell time to prevent flapping.
- Path states: `relay` (initial), `direct` (after punch), with fallback to `relay` if the direct path degrades.

## 9. Security considerations

- **0-RTT early data has no full forward secrecy** and may be replayed within the crash window; application MUST treat early data as idempotent.
- **The relay sees only ciphertext.** The relay cannot decrypt, authenticate, or inspect agent traffic.
- **Post-quantum readiness:** breaking the hybrid session requires breaking both the classical (SM2/ECDH) and the post-quantum (ML-KEM-768) components.
- Reference implementation notes and known limitations are tracked in the repo.

## 10. Versioning

This document is versioned; breaking changes will be accompanied by a domain-separated protocol label bump.
