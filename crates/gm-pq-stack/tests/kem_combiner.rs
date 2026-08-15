//! Correctness of the KEM combiner and "single-point compromise" security tests.
//!
//! The formal argument lives in the src/kem/hybrid.rs module docs; this file turns
//! it into executable assertions:
//! 1. Combiner roundtrip correctness (both sides derive the same hybrid key);
//! 2. The hybrid output depends on BOTH component secrets (substituting any one with a
//!    known value changes the output);
//! 3. Ciphertext/public-key binding (tampering with any public parameter changes the output);
//! 4. The hybrid output is disjoint from either single-component output (hybrid ≠ any single path).

use gm_pq_stack::kem::hybrid::combine;
use gm_pq_stack::kem::{DefaultHybrid, Kem, MlKem768Kem, Sm2Kem};
use gm_pq_stack::rng::SysRng;

fn rng() -> SysRng {
    SysRng::new()
}

#[test]
fn sm2_kem_roundtrip() {
    let mut r = rng();
    let (sk, pk) = Sm2Kem::keypair(&mut r).unwrap();
    let (ct, ss_enc) = Sm2Kem::encapsulate(&mut r, &pk).unwrap();
    let ss_dec = Sm2Kem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_enc, ss_dec, "SM2-ECDH KEM shared secrets must match");
}

#[test]
fn mlkem_roundtrip() {
    let mut r = rng();
    let (sk, pk) = MlKem768Kem::keypair(&mut r).unwrap();
    assert_eq!(pk.len(), 1184);
    let (ct, ss_enc) = MlKem768Kem::encapsulate(&mut r, &pk).unwrap();
    assert_eq!(ct.len(), 1088);
    let ss_dec = MlKem768Kem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_enc, ss_dec, "ML-KEM-768 shared secrets must match");
}

#[test]
fn mlkem_tampered_ciphertext_yields_different_secret() {
    // ML-KEM implicit rejection: a tampered ciphertext does not error, but yields a
    // pseudorandom key (different from the encapsulator's).
    let mut r = rng();
    let (sk, pk) = MlKem768Kem::keypair(&mut r).unwrap();
    let (mut ct, ss_enc) = MlKem768Kem::encapsulate(&mut r, &pk).unwrap();
    ct[0] ^= 0x01;
    let ss_dec = MlKem768Kem::decapsulate(&sk, &ct).unwrap();
    assert_ne!(ss_enc, ss_dec, "shared secret must diverge after tampered ciphertext");
}

#[test]
fn hybrid_roundtrip() {
    let mut r = rng();
    let (sk, pk) = DefaultHybrid::keypair(&mut r).unwrap();
    assert_eq!(pk.len(), 65 + 1184);
    let (ct, ss_enc) = DefaultHybrid::encapsulate(&mut r, &pk).unwrap();
    assert_eq!(ct.len(), 65 + 1088);
    let ss_dec = DefaultHybrid::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_enc, ss_dec, "hybrid KEM shared secrets must match");
}

#[test]
fn hybrid_tampered_ciphertext_fails() {
    let mut r = rng();
    let (sk, pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (ct, ss_enc) = DefaultHybrid::encapsulate(&mut r, &pk).unwrap();

    // Tamper with the SM2 segment
    let mut ct1 = ct.clone();
    ct1[10] ^= 0x01;
    let r1 = DefaultHybrid::decapsulate(&sk, &ct1);
    // A tampered SM2 segment may either make ECDH error or yield a different key; both are safe outcomes
    if let Ok(ss) = r1 {
        assert_ne!(ss, ss_enc);
    }

    // Tamper with the ML-KEM segment
    let mut ct2 = ct.clone();
    ct2[65] ^= 0x01;
    let ss2 = DefaultHybrid::decapsulate(&sk, &ct2).unwrap();
    assert_ne!(ss2, ss_enc, "hybrid key must diverge after tampered ML-KEM segment");
}

/// Scenario A: SM2 is (quantum-)broken — the attacker knows ss_c.
/// Assertion: the combined output is still fully determined by ss_p, which the attacker cannot predict.
#[test]
fn single_point_compromise_classical_broken() {
    let mut r = rng();
    let (sk_p, pk_p) = MlKem768Kem::keypair(&mut r).unwrap();
    let (ct_p, ss_p) = MlKem768Kem::encapsulate(&mut r, &pk_p).unwrap();
    assert_eq!(ss_p, MlKem768Kem::decapsulate(&sk_p, &ct_p).unwrap());

    let attacker_known_ss_c = [0xAA; 32]; // attacker has recovered the classical segment
    let ct_c = vec![0u8; 65];
    let pk_c = vec![0u8; 65];

    let out = combine(
        &attacker_known_ss_c,
        &ct_c,
        &pk_c,
        &ss_p,
        &ct_p,
        &pk_p,
    );
    // Swap in a different PQ shared secret (which the attacker does not know); the output must change
    let other_ss_p = [0xBB; 32];
    let out2 = combine(
        &attacker_known_ss_c,
        &ct_c,
        &pk_c,
        &other_ss_p,
        &ct_p,
        &pk_p,
    );
    assert_ne!(out, out2, "with SM2 broken, the hybrid key must still track the unknown ss_p");
}

/// Scenario B: ML-KEM is broken — the attacker knows ss_p. Symmetric assertion.
#[test]
fn single_point_compromise_pq_broken() {
    let mut r = rng();
    let (sk_c, pk_c) = Sm2Kem::keypair(&mut r).unwrap();
    let (ct_c, ss_c) = Sm2Kem::encapsulate(&mut r, &pk_c).unwrap();
    assert_eq!(ss_c, Sm2Kem::decapsulate(&sk_c, &ct_c).unwrap());

    let attacker_known_ss_p = [0x55; 32];
    let ct_p = vec![0u8; 1088];
    let pk_p = vec![0u8; 1184];

    let out = combine(&ss_c, &ct_c, &pk_c, &attacker_known_ss_p, &ct_p, &pk_p);
    let other_ss_c = [0x77; 32];
    let out2 = combine(&other_ss_c, &ct_c, &pk_c, &attacker_known_ss_p, &ct_p, &pk_p);
    assert_ne!(out, out2, "with ML-KEM broken, the hybrid key must still track the unknown ss_c");
}

/// Ciphertext/public-key binding: any change to a public parameter changes the combined output
/// (defends against re-encapsulation confusion attacks)
#[test]
fn combiner_binds_ciphertexts_and_public_keys() {
    let ss_c = [1u8; 32];
    let ss_p = [2u8; 32];
    let ct_c = vec![3u8; 65];
    let ct_p = vec![4u8; 1088];
    let pk_c = vec![5u8; 65];
    let pk_p = vec![6u8; 1184];

    let base = combine(&ss_c, &ct_c, &pk_c, &ss_p, &ct_p, &pk_p);

    let mut bad_ct_c = ct_c.clone();
    bad_ct_c[0] ^= 1;
    assert_ne!(base, combine(&ss_c, &bad_ct_c, &pk_c, &ss_p, &ct_p, &pk_p));

    let mut bad_ct_p = ct_p.clone();
    bad_ct_p[0] ^= 1;
    assert_ne!(base, combine(&ss_c, &ct_c, &pk_c, &ss_p, &bad_ct_p, &pk_p));

    let mut bad_pk_c = pk_c.clone();
    bad_pk_c[0] ^= 1;
    assert_ne!(base, combine(&ss_c, &ct_c, &bad_pk_c, &ss_p, &ct_p, &pk_p));

    let mut bad_pk_p = pk_p.clone();
    bad_pk_p[0] ^= 1;
    assert_ne!(base, combine(&ss_c, &ct_c, &pk_c, &ss_p, &ct_p, &bad_pk_p));
}

/// The hybrid output differs from either single-path output (SM3 domain separation in effect)
#[test]
fn hybrid_output_differs_from_components() {
    let mut r = rng();
    let (sk, pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (ct, ss_hybrid) = DefaultHybrid::encapsulate(&mut r, &pk).unwrap();
    let ss_hybrid2 = DefaultHybrid::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_hybrid, ss_hybrid2);
    // DefaultHybrid::SecretKey is the concrete HybridSecretKey<Sm2Kem, MlKem768Kem>; fields are directly accessible
    let (ct_c, ct_p) = ct.split_at(65);
    let ss_c = Sm2Kem::decapsulate(&sk.classical, ct_c).unwrap();
    let ss_p = MlKem768Kem::decapsulate(&sk.pq, ct_p).unwrap();
    assert_ne!(ss_hybrid, ss_c);
    assert_ne!(ss_hybrid, ss_p);
}
