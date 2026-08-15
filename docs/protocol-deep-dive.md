# Protocol deep-dive: why Directwire looks the way it does

> _Engineering notes from the Directwire reference implementation._ This is a
> design rationale document — the normative byte-level contract lives in
> [`SPEC.md`](../SPEC.md). Last updated: 2026-08-15, for v0.1.

## The problem we are actually solving

The AI-agent era changes who talks to whom. Today's networking still assumes a
human holds a phone or a server has a domain. An autonomous agent has neither —
and worse, the *agent* is the part that gets impersonated, hijacked, or
poisoned. The networking layer for this era has to answer one question first:

> **Who am I talking to?**

Not "which IP," not "which domain," not "which account on which vendor's
cloud." The only answer that survives inspection by an adversary is a
cryptographic key. So Directwire makes the key the address:

- a node's **NodeId is its ed25519 public key**;
- you dial a peer by its NodeId, nothing else;
- authentication is implicit — proving knowledge of the private key *is*
  speaking as that identity.

There is no DNS, no registry, no certificate authority, no account system. The
identity layer collapses into 32 bytes. That one decision cascades through
every design choice below.

## Threat model

We assume the network is adversarial — any router, any ISP, **and the relay
itself**. The reference threat model grants the attacker:

- full read/write access to the byte stream between any two nodes;
- the ability to run their own relay and peer;
- knowledge of all public keys;
- a future quantum computer.

The attacker does **not** get: either party's private keys, or the ability to
make the relay learn plaintext.

The guarantees we commit to:

| Property | Mechanism |
|---|---|
| Confidentiality | end-to-end AEAD; the relay forwards ciphertext only |
| Authenticity | identity signatures in both handshakes; QUIC cert pinned to NodeId |
| Forward secrecy | ephemeral-DH session keys; hybrid session requires breaking *both* SM2 and ML-KEM-768 |
| Replay protection | 64-bit sequence + 64-slot sliding replay window |
| MITM on identity binding | BIND signature ties the SM2 key to the ed25519 NodeId |

The "relay sees only ciphertext" property deserves emphasis because it is
structural, not a promise. The relay holds no keying material: the session is
established between the two peers *through* the relay, the relay merely
forwards opaque payloads. Even a fully compromised relay cannot decrypt
traffic it forwards — it can only drop it (a liveness attack, which the
direct-path fallback mitigates) or meter it.

## Why hybrid post-quantum, and why SM2

Two separate pressures converge on the same wire format:

1. **Post-quantum migration.** Harvest-now-decrypt-later is a real, current
   threat for long-lived agents: traffic recorded today can be broken once
   Shor-capable hardware exists. ML-KEM-768 (FIPS 203) is the post-quantum
   KEM, and it is already mainstream.
2. **National-crypto compliance.** Regulated deployments (China's MLPS /
   commercial-crypto evaluation, and any market that mandates SM-series
   cryptography) require SM2/SM3/SM4. A transport that can't speak SM-family
   is structurally excluded from those budgets.

Classical-only is unsafe for the first, SM-only is non-interoperable for the
second. So the handshake is **hybrid**: SM2 + ML-KEM-768 combined with a
GHP18-style combiner and SM3 as the random oracle. Breaking the session means
breaking *both* the classical and the post-quantum component — the standard
"strongest wins" hybrid guarantee. The data plane is SM4-GCM (an AEAD in its
own right), so even the bulk traffic stays inside the national-crypto family.

This is the positioning no generic P2P stack has: **the wire format is the
product, and it is simultaneously compliance-ready and quantum-ready.**

## Two paths, one session

The transport has exactly two roles:

- **relay** — liveness. Brokers candidate exchange, forwards ciphertext,
  guarantees reachability behind any NAT.
- **direct** — performance. A hole-punched QUIC path between the peers.

An agent never chooses *which* path; the stack does. Path selection scores each
path by a combined metric `eff = RTT × (1 + 10 × loss)`, switches only when the
better path wins by a 2× margin (hysteresis), and refuses to switch again for a
minimum dwell window. The relay stays warm the whole time, so a direct-path
failure degrades gracefully instead of dropping the session.

The direct path reuses the same UDP socket as hole punching, so the NAT mapping
opened by the punch is the mapping the QUIC connection uses. Both sides
connect simultaneously and the smaller NodeId's outbound connection is
canonical — simultaneous-open needs no client/server role.

## Identity binding under a hybrid identity system

NodeId is ed25519, but the hybrid handshake authenticates an SM2 key. That is
two identity systems glued together — the classic splicing attack is a MITM
who runs two half-handshakes and forwards one side to the other. Directwire's
defense is the **BIND** message: the first ciphertext inside the session is a
signature by the ed25519 NodeId over
`"p2p-mesh/gmpq-bind" || SM3(gm_pk) || node_id || session_id`.

Because `session_id` is derived from the handshake transcript, a spliced
handshake produces *different* session IDs on the two halves — a forwarded
BIND fails the session-ID check. And forging the signature requires the
ed25519 private key. TOFU is the starting trust anchor; production deployments
should pin SM2 keys and drop BIND to a mere consistency check.

## Honest limits (v0.1)

- **Reference crypto is not certified.** `gm-pq-stack` is an
  architecture-validation skeleton; formal certification and MLPS evaluation
  are explicit red lines, not features. See the README.
- **0-RTT resumption exists but is unused in the MVP** — no early data, no
  idempotency surface. It ships for PSK key-rotation experiments only.
- **Identity is not yet persistent or recoverable.** Keys are generated at
  process start; persistence/preloading is a roadmap item.
- **No discovery layer.** This is a transport; rendezvous, capability
  discovery, and agent-facing APIs are ecosystem work, layered on top.

## Where this sits vs. the field

| | Generic P2P (e.g. iroh / libp2p) | Directwire |
|---|---|---|
| Identity | public key | public key (same thesis, different market) |
| Post-quantum session | roadmap, not wire | in the wire (ML-KEM-768) |
| National-crypto family | absent | native (SM2/SM3/SM4-GCM) |
| Compliance markets | excluded by design | the primary wedge |
| Agent-native API | general-purpose | MCP integration (this repo, v0.2 roadmap) |

## The roadmap in one paragraph

v0.1 proved the transport: 77 tests, end-to-end demo, public SPEC, CI green.
The next ecosystem layer is making the wire consumable by agents — MCP
integration so any agent toolchain can dial-and-message by public key — then
identity persistence, then hosted relay infrastructure as the commercial
surface. The wire format is the contract; everything else is convenience.
