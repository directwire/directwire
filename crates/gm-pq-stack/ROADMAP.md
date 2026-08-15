# ROADMAP — 12 months (2026-09 → 2027-08)

Guiding principle: **MVP validates the architecture → alpha completes the security surface → beta passes compliance prep → commercialization catches the window**.
Effort unit: person-months (PM).

## Q1 (2026-09 ~ 2026-11) MVP — architecture validation ✅ current position

| milestone | content | effort |
|---|---|---|
| M1.1 hybrid-KEM combiner | SM2-ECDH + ML-KEM-768, X-Wing-style combination, single-leg-broken tests ✅ | 1.5 PM |
| M1.2 Noise-XX hybrid handshake | three-message state machine, SM3-HKDF derivation, SM2 transcript-signature possession proof ✅ | 2 PM |
| M1.3 transport session | SM4-GCM AEAD, sequence nonce, sliding replay window ✅ | 1 PM |
| M1.4 demo + tests | loopback handshake echo, three-mode timing, 24 tests all green ✅ | 1 PM |

**Exit criteria**: `cargo test` all green; loopback hybrid handshake measured < 10ms. (Met.)

## Q2 (2026-12 ~ 2027-02) alpha — completing the security surface

| milestone | content | effort |
|---|---|---|
| M2.1 static-key trust anchor | ~~SM2 certificate-chain validation~~/public-key pinning ✅ (`trust::PinFileAnchor`; CA-chain impl pending) | 2 PM |
| M2.2 DoS protection | ✅ stateless cookie challenge (`handshake::cookie`); uplink rate limiting pending | 1.5 PM |
| M2.3 key management | partially ✅ zeroize crate-wide (`key_hygiene` tests lock the contract); encrypted key-at-rest pending | 1.5 PM |
| M2.4 fuzzing + differential testing | proptest state-machine traversal, differential interop vs GMSSL/OpenSSL national-crypto | 2 PM |
| M2.5 performance baseline | criterion benchmark suite; evaluate SM2 scalar-mul wNAF/batch optimizations | 1 PM |

**Exit criteria**: one third-party code audit; 0 divergence in differential interop tests; handshake P99 < 5ms (pure software).

## Q3 (2027-03 ~ 2027-05) beta — compliance prep and productization

| milestone | content | effort |
|---|---|---|
| M3.1 hardware crypto-module integration | crypto-card/device API adapter layer (SM2/SM4 operations sunk to hardware) | 2.5 PM |
| M3.2 MLPS materials | organize crypto-scheme and key-lifecycle documents per GB/T 39786 | 1.5 PM |
| M3.3 protocol hardening | ✅ 0-RTT PSK session resumption (`handshake::psk` + one-time ticket cache); cipher-suite negotiation pending | 2 PM |
| M3.4 SDK packaging | C ABI + Java/Go bindings (most critical-infra legacy systems are Java) | 2 PM |
| M3.5 pilot customers | 1–2 bank/government PoCs live, collect real traffic profiles | business-led |

**Exit criteria**: pilot PoC passes; MLPS pre-communication done; SDK usable in three languages.

## Q4 (2027-06 ~ 2027-08) commercialization — catching the standard-vacuum window

| milestone | content | effort |
|---|---|---|
| M4.1 commercial-crypto product certification | submit the crypto module for review, obtain the certificate (critical path, keep buffer) | 2 PM + certification cycle |
| M4.2 high-availability deployment | clustered session-ticket encrypted sync, staged upgrade | 1.5 PM |
| M4.3 monitoring + compliance reports | MLPS self-check reports, cipher-suite usage, PQ-migration-readiness dashboard | 1 PM |
| M4.4 domestic PQC tracking | track the domestic PQC national standard, prepare in-place PQ-leg swap (kem trait abstraction already has the seam) | 0.5 PM |
| M4.5 scaled sales | replicate the PoC playbook across critical-infra verticals (banks/government/energy) | business-led |

**Exit criteria**: certification certificate in hand; ≥3 paying critical-infra customers; one PQ-swap drill executed.

## Risks & hedging

1. **Domestic PQC national standard lands early** → kem trait abstraction + combiner modes support in-place swap, ~2 weeks to switch.
2. **MLPS cycle exceeds expectations** → start pre-communication in Q3, run the certification path in parallel.
3. **ML-KEM parameter dispute** (768 vs 1024) → parameter sets made a compile-time optional feature.
4. **SM2 performance bottleneck** → dual-track: pure-software optimization in Q2 + hardware sinking in Q3.
