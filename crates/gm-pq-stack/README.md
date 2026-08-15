# gm-pq-stack — SM2 + ML-KEM-768 hybrid-handshake secure transport stack

**A hybrid-KEM transport library (Rust, runnable architecture-validation skeleton) combining Chinese national-crypto compliance with post-quantum forward thinking**

## Positioning & the asymmetry

- **Overseas status quo**: the X25519+ML-KEM-768 hybrid handshake is already the default in mainstream browsers, PQ traffic share >60%; NIST plans to deprecate pure-classical algorithms by 2030.
- **Domestic vacuum**: PQ deployment in critical-infrastructure systems (banks, government) ≈ 0%; a domestic PQC national standard is expected only in 2027–2028 — **the standard vacuum IS the monetization window**.
- **Compliance red line**: commercial scenarios must use national-crypto at the algorithm layer (《Commercial Cryptography Administration Regulations》, MLPS GB/T 39786); directly copying the overseas X25519 approach cannot pass review.
- **Play**: overseas Noise/hybrid-handshake **architecture skeleton** + **national-crypto algorithm fill** (SM2/SM3/SM4) + **ML-KEM hybrid**. A compliance dimension-down against overseas schemes, and a PQ dimension-down against pure-national-crypto schemes.

**⚠️ Compliance red line (please read)**

1. This project is a **runnable architecture-validation skeleton**; the crypto modules are not MLPS-certified. Formal commercialization must:
   - Use **commercial-cryptography-product-certified** crypto modules / crypto cards to carry key operations;
   - Complete security evaluation per GB/T 39786 (MLPS);
   - Comply with the 《Commercial Cryptography Administration Regulations》: the development, sale, and use of commercial crypto products are regulated by the national cryptography administration.
2. The hybrid design is a **transitional compatibility strategy**: SM2 guarantees present-day compliance; ML-KEM-768 provides forward protection under the Harvest-Now-Decrypt-Later threat. Once the domestic PQC national standard is published, the PQ component can be swapped in place under the `kem` trait abstraction (see ROADMAP).

## Standards alignment

The SM2 + ML-KEM-768 combination is **not an ad-hoc invention** — it aligns with the
**SM2MLKEM768** hybrid key-exchange registered in the IANA TLS NamedGroup registry
(**id 4590**, proposed by the Chinese cryptographic community, already implemented in
Alibaba Tongsuo and adopted by the ZeroTrust browser). The stack's `sm2+ml-kem-768` suite
string follows that same combined-algorithm semantics.

Where this stack differs from a TLS-KEM library like Tongsuo is **layer position**:

| | Tongsuo / TLS stacks | this stack (`gm-pq-stack`) |
|---|---|---|
| hybrid KEM | SM2MLKEM768 (IANA 4590) | same SM2MLKEM768 combination |
| transport | TLS 1.3 handshake carries the KEM | the hybrid handshake **is** the transport |
| beyond the KEM | TLS record layer (AES-GCM etc.) | SM4-GCM sessions + replay window + cookie anti-DoS + PSK/0-RTT resumption |
| scope | a KEM primitive inside a TLS stack | the complete end-to-end secure-channel layer |

The value the ecosystem gets from this stack is that a deployment can take the *whole*
secure channel (compliant SM2 authentication + PQ forward protection + SM4-GCM + DoS
protection + resumption) in one `kem`-trait-swappable package — the PQ leg swaps in place
to the national algorithm family once the 2027–2029 GM/T standards land, with no handshake
or session-layer changes.

## Market-window data

| metric | value | meaning |
|---|---|---|
| domestic critical-infra PQ deployment | ≈ 0% | standard vacuum, no mature domestic PQC product |
| overseas PQ traffic share | > 60% | the hybrid handshake is the browser default |
| NIST classical-algorithm deprecation | 2030 | ECDH/RSA no longer allowed standalone |
| domestic PQC national standard | expected 2027–2028 | 2–3 year window |
| China commercial crypto market size (2028E) | ≈ RMB 28.5 billion | critical-infra retrofit + MLPS driven |

## Architecture

```
                ┌─────────────────────── gm-pq-stack ───────────────────────┐
                │                                                           │
  app layer ───▶│  Session (SM4-GCM AEAD + 64-slot sliding replay window +   │
                │             sequence nonce)                               │
                │             ▲                                             │
                │   ┌─────────┴──────────┐                                  │
                │   │ handshake (Noise-XX │  msg1 -> e                      │
                │   │  hybrid-KEM-fied)   │  msg2 <- e || ct_ee || AEAD(s_r)│
                │   │  three-message +    │  msg3 -> ct_se||ct_ss||         │
                │   │  mutual auth (SM2   │           AEAD(s_i || sig_sm2)  │
                │   │  transcript sig,    │                                  │
                │   │  possession proof)  │                                  │
                │   └─────────┬──────────┘                                  │
                │             ▼                                             │
                │   ┌──────────────────────┐                                │
                │   │ HybridKem combiner    │  ss = SM3(ss_c||ss_p||        │
                │   │ (X-Wing/GHP18 style)  │       ct_c||ct_p||pk_c||pk_p) │
                │   └───┬──────────────┬───┘                                │
                │       ▼              ▼                                    │
                │  ┌─────────┐   ┌───────────┐                              │
                │  │ Sm2Kem  │   │MlKem768Kem│   ← kem::Kem trait abstraction│
                │  │(ECDH-KEM│   │(FIPS 203, │                              │
                │  │ GB/T    │   │ implicit   │                              │
                │  │ 32918)  │   │ rejection) │                              │
                │  └─────────┘   └───────────┘                              │
                │   base: libsmx (SM2/SM3/SM4-GCM) + ml-kem (RustCrypto)      │
                └───────────────────────────────────────────────────────────┘
```

**Security argument highlights** (see the comments in `src/kem/hybrid.rs`): the combiner follows the X-Wing / GHP18 paradigm;
with SM3 modeled as a random oracle, the combined key is pseudorandom as long as **either** SM2-ECDH or ML-KEM-768
remains IND-CCA secure — an attacker must break both. Ciphertexts and public keys are hashed in, defeating KEM-binding attacks.

## Quick start

```bash
# run tests (46: combiner/handshake/replay/cookie/PSK/trust anchor/key hygiene/integration smoke)
cargo test

# loopback handshake + encrypted echo demo (three-mode timing comparison, release recommended)
cargo run --release --example handshake_echo

# hybrid mode only
cargo run --release --example handshake_echo -- hybrid
```

In code:

```rust
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::handshake::{Initiator, Responder};
use gm_pq_stack::rng::SysRng;

let mut rng = SysRng::new();
let (i_sk, i_pk) = DefaultHybrid::keypair(&mut rng)?;
let (r_sk, r_pk) = DefaultHybrid::keypair(&mut rng)?;

let mut init = Initiator::<DefaultHybrid>::new(i_sk, i_pk);
let mut resp = Responder::<DefaultHybrid>::new(r_sk, r_pk);

let m1 = init.write_msg1(&mut rng)?;        // -> e
resp.read_msg1(&m1)?;
let m2 = resp.write_msg2(&mut rng)?;        // <- e || ct_ee || AEAD(s_r)
init.read_msg2(&m2)?;
let (m3, mut s_i) = init.write_msg3_with_auth(&mut rng)?;  // -> ct_se||ct_ss||AEAD(s_i||sig)
let (mut s_r, peer_pk) = resp.read_msg3_with_auth(&m3)?;   // mutual auth complete

let pkt = s_i.send(b"hello");
assert_eq!(s_r.recv(&pkt)?, b"hello");
```

## Benchmark data (measured locally, release, Windows / x86_64)

| mode | handshake (3 messages + TCP loopback) | 3 encrypted echoes | compliant | post-quantum |
|---|---|---|---|---|
| pure SM2-ECDH | ≈ 3.6 ms | ≈ 1.3 ms | ✅ | ❌ |
| pure ML-KEM-768 | ≈ 0.6 ms | ≈ 0.5 ms | ❌ | ✅ |
| **hybrid (default)** | ≈ 4.2 ms | ≈ 1.9 ms | ✅ | ✅ |

Reference: the overseas TLS 1.3 X25519+ML-KEM-768 hybrid handshake costs ≈ 1–2 ms public-internet RTT overhead (hardware AES/AVX2-assisted).
This skeleton is a pure-Rust software implementation; SM2 scalar multiplication dominates. Moving to a hardware crypto card drops the SM2 side by an order of magnitude.

Versus overseas:

| dimension | overseas X25519+MLKEM768 | this stack SM2+MLKEM768 |
|---|---|---|
| architecture paradigm | Noise/TLS1.3 hybrid handshake | same (XX three-message) |
| classical leg | X25519 (non-compliant) | **SM2 (GB/T 32918, compliant)** |
| transport encryption | AES-GCM/ChaCha20 | **SM4-GCM (compliant)** |
| KDF/hash | SHA-2/HKDF | **SM3-HKDF (compliant)** |
| PQ leg | ML-KEM-768 | ML-KEM-768 (swappable in place after national standard) |

## Directory structure

```
src/
  lib.rs            unified error type and module entry
  rng.rs            system CSPRNG adapter (rand_core 0.6, for libsmx)
  crypto.rs         SM3-HKDF, SM4-GCM AEAD wrappers (keys held as Zeroizing)
  api.rs            minimal downstream integration API (Read+Write byte stream → SecureChannel)
  trust.rs          TrustAnchor trait + public-key pinning-file implementation
  kem/
    mod.rs          Kem trait abstraction + StaticAuth (possession proof) trait + mode enum
    sm2.rs          SM2-ECDH KEM (GB/T 32918)
    mlkem.rs        ML-KEM-768 (FIPS 203)
    hybrid.rs       X-Wing-style hybrid combiner (with a formal-security-argument comment)
  handshake/
    mod.rs          Noise-XX hybrid-KEM three-message state machine (single/mutual auth, PSK mode, 0-RTT)
    session.rs      transport session + 64-slot sliding replay window
    cookie.rs       DoS protection: stateless cookie challenge (WireGuard/DTLS style)
    psk.rs          session-resumption ticket issue/decrypt + one-time ticket cache
tests/
  kem_combiner.rs   combiner correctness + single-leg-broken scenarios + binding (9 cases)
  handshake.rs      handshake state machine/mutual auth/tamper rejection (8 cases)
  replay.rs         replay window + end-to-end replay rejection (7 cases)
  cookie.rs         cookie challenge (binding/expiry/tamper resistance, 6 cases)
  psk.rs            ticket lifecycle + resumption handshake + 0-RTT + replay interception (7 cases)
  trust_anchor.rs   pin-file parsing + handshake admission/denial (6 cases)
  key_hygiene.rs    zeroize compile-time-contract assertions (2 cases)
  api_smoke.rs      integration API end-to-end (full → resumption → ticket-replay fallback, 1 case)
examples/
  handshake_echo.rs loopback handshake + encrypted echo + three-mode timing
docs/
  INTEGRATION.md    downstream integration guide (object-stream / p2p-mesh)
```

## Known limits (outside the skeleton scope)

- ~~static public-key trust anchors are the deployment layer's job~~ → implemented `trust::TrustAnchor` abstraction + public-key pinning file (CA chain validation left as another implementation of the same trait);
- ~~no DoS protection~~ → implemented a WireGuard/DTLS-style stateless cookie challenge (`handshake::cookie`);
- ~~no 0-RTT~~ → implemented PSK session resumption + 0-RTT early data (`handshake::psk`, replay protection = one-time ticket cache);
- crypto modules are not MLPS-certified; encrypted key-at-rest and HSM/crypto-card integration are not implemented;
- MlKemOnly mode has responder-only single-side authentication (a structural limit of KEMs lacking signing, same as TLS 1.3);
- `TicketCache` is an in-memory implementation; clustered deployments need shared storage.

## Second-round hardening additions

| capability | location | note |
|---|---|---|
| DoS cookie challenge | `handshake::cookie` | stateless SM3-HMAC cookie, bound to client_tag + msg1 + timestamp |
| PSK session resumption / 0-RTT | `handshake::psk` | self-encrypted tickets (SM4-GCM) + one-time cache + identity-fingerprint binding |
| trust anchor | `trust` | `TrustAnchor` trait + `PinFileAnchor` (pin file / in-memory construction) |
| key hygiene | whole crate | zeroize: session/shared/ticket keys auto-cleared on drop, compile-time contract tests |
| integration API | `api` + `docs/INTEGRATION.md` | any `Read+Write` byte stream → encrypted session, for object-stream/p2p-mesh integration |
