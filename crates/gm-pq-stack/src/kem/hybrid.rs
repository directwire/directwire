//! Hybrid KEM combiner: classical KEM (SM2-ECDH) + post-quantum KEM (ML-KEM-768).
//!
//! ## Formal security argument (outline)
//!
//! Combination function:
//! ```text
//! ss = SM3( 0x01 || ss_c || ss_p || ct_c || ct_p || pk_c || pk_p || "gm-pq-stack/hybrid/v1" )
//! ```
//!
//! Per the combiner results of X-Wing (IETF hybrid-KEM draft) and
//! Giacon–Heuer–Poettering 2018 (GHP18):
//!
//! 1. **Two-way indistinguishability**: modeling SM3 as a random oracle (RO), as long as
//!    at least one of ss_c / ss_p is indistinguishable from uniform random for the attacker
//!    (corresponding to that component KEM's IND-CCA security), the combination input
//!    contains high-entropy material the attacker cannot predict, so the SM3 output is
//!    pseudorandom.
//!    ⇒ Breaking the combined KEM requires breaking **both** SM2-ECDH (classical CDH) and
//!    ML-KEM-768 (MLWE) simultaneously.
//!
//! 2. **Ciphertext/public-key binding** (an X-Wing strengthening over the original GHP18
//!    combiner): hashing ct and pk together defends against "KEM binding attacks"
//!    (re-encapsulation / ciphertext substitution where both sides compute the same ss but
//!    the transcripts differ), guaranteeing the combined key is bound to all public
//!    parameters of this handshake.
//!
//! 3. **Single-point break scenarios** (covered by tests/kem_combiner.rs):
//!    - Scenario A: an attacker with a quantum computer recovers ss_c (SM2 broken), but ss_p
//!      is unknown ⇒ the combined output still contains 256 bits of unknown entropy; safe.
//!    - Scenario B: the ML-KEM implementation is broken (side-channel / algorithm), leaking
//!      ss_p while ss_c remains secret ⇒ the combined output stays secure (degrades to the
//!      classical 128-bit strength, on par with the status quo).
//!
//! Limitation: this skeleton does not implement constant-time combination (SM3 itself is
//! constant-time, limiting the impact); production use must go through a certified crypto
//! module recognized by GB/T 39786.

use std::marker::PhantomData;

use crate::crypto::sm3;
use crate::rng::SysRng;
use crate::{Error, Result};

use super::Kem;

/// Combiner domain-separation label
const COMBINER_LABEL: &[u8] = b"gm-pq-stack/hybrid/v1";

/// X-Wing-style combination function (exported standalone so single-point break scenarios are testable)
#[allow(clippy::too_many_arguments)]
pub fn combine(
    ss_c: &[u8; 32],
    ct_c: &[u8],
    pk_c: &[u8],
    ss_p: &[u8; 32],
    ct_p: &[u8],
    pk_p: &[u8],
) -> [u8; 32] {
    sm3(&[
        &[0x01u8],
        ss_c,
        ss_p,
        ct_c,
        ct_p,
        pk_c,
        pk_p,
        COMBINER_LABEL,
    ])
}

/// Hybrid KEM: classical component `C` + post-quantum component `P`
pub struct HybridKem<C: Kem, P: Kem> {
    _c: PhantomData<C>,
    _p: PhantomData<P>,
}

/// Hybrid secret key = both component secret keys
pub struct HybridSecretKey<C: Kem, P: Kem> {
    pub classical: C::SecretKey,
    pub pq: P::SecretKey,
}

// Hand-written Clone: derive would impose spurious constraints on C/P themselves;
// we only constrain the SecretKey types.
impl<C: Kem, P: Kem> Clone for HybridSecretKey<C, P>
where
    C::SecretKey: Clone,
    P::SecretKey: Clone,
{
    fn clone(&self) -> Self {
        HybridSecretKey {
            classical: self.classical.clone(),
            pq: self.pq.clone(),
        }
    }
}

impl<C: Kem, P: Kem> Kem for HybridKem<C, P> {
    const NAME: &'static str = "SM2-ECDH+ML-KEM-768";
    const PUBLIC_KEY_LEN: usize = C::PUBLIC_KEY_LEN + P::PUBLIC_KEY_LEN;
    const CIPHERTEXT_LEN: usize = C::CIPHERTEXT_LEN + P::CIPHERTEXT_LEN;

    type SecretKey = HybridSecretKey<C, P>;

    fn keypair(rng: &mut SysRng) -> Result<(Self::SecretKey, Vec<u8>)> {
        let (sk_c, pk_c) = C::keypair(rng)?;
        let (sk_p, pk_p) = P::keypair(rng)?;
        let mut pk = Vec::with_capacity(Self::PUBLIC_KEY_LEN);
        pk.extend_from_slice(&pk_c);
        pk.extend_from_slice(&pk_p);
        Ok((
            HybridSecretKey {
                classical: sk_c,
                pq: sk_p,
            },
            pk,
        ))
    }

    fn encapsulate(rng: &mut SysRng, peer_public: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        Self::validate_public(peer_public)?;
        let (pk_c, pk_p) = peer_public.split_at(C::PUBLIC_KEY_LEN);

        let (ct_c, ss_c) = C::encapsulate(rng, pk_c)?;
        let (ct_p, ss_p) = P::encapsulate(rng, pk_p)?;

        let ss = combine(&ss_c, &ct_c, pk_c, &ss_p, &ct_p, pk_p);

        let mut ct = Vec::with_capacity(Self::CIPHERTEXT_LEN);
        ct.extend_from_slice(&ct_c);
        ct.extend_from_slice(&ct_p);
        Ok((ct, ss))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<[u8; 32]> {
        if ct.len() != Self::CIPHERTEXT_LEN {
            return Err(Error::InvalidEncoding("invalid hybrid ciphertext length"));
        }
        let (ct_c, ct_p) = ct.split_at(C::CIPHERTEXT_LEN);

        let ss_c = C::decapsulate(&sk.classical, ct_c)?;
        let ss_p = P::decapsulate(&sk.pq, ct_p)?;

        // The decapsulator derives its own public key from the secret key to rebuild the
        // same binding inputs as the encapsulator.
        let pk_c = C::public_of(&sk.classical);
        let pk_p = P::public_of(&sk.pq);
        Ok(combine(&ss_c, ct_c, &pk_c, &ss_p, ct_p, &pk_p))
    }

    fn public_of(sk: &Self::SecretKey) -> Vec<u8> {
        let mut pk = Vec::with_capacity(Self::PUBLIC_KEY_LEN);
        pk.extend_from_slice(&C::public_of(&sk.classical));
        pk.extend_from_slice(&P::public_of(&sk.pq));
        pk
    }

    fn validate_public(pk: &[u8]) -> Result<()> {
        if pk.len() != Self::PUBLIC_KEY_LEN {
            return Err(Error::InvalidEncoding("invalid hybrid public key length"));
        }
        C::validate_public(&pk[..C::PUBLIC_KEY_LEN])?;
        P::validate_public(&pk[C::PUBLIC_KEY_LEN..])?;
        Ok(())
    }
}

/// Proof of possession for the hybrid scheme is provided by the classical component (SM2)'s
/// signature capability. There is currently no production-ready national/standardized PQ
/// signature (both ML-DSA and the national PQC standard are still in progress), so initiator
/// authentication anchors on SM2 — consistent with the compliance baseline that commercial
/// deployments must use national crypto at the algorithm layer.
impl<C, P> super::StaticAuth for HybridKem<C, P>
where
    C: Kem + super::StaticAuth,
    P: Kem,
{
    const SIGNATURE_LEN: usize = C::SIGNATURE_LEN;

    fn sign(sk: &Self::SecretKey, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        C::sign(&sk.classical, transcript_hash)
    }

    fn verify(pk: &[u8], transcript_hash: &[u8; 32], sig: &[u8]) -> Result<()> {
        Self::validate_public(pk)?;
        C::verify(&pk[..C::PUBLIC_KEY_LEN], transcript_hash, sig)
    }
}
