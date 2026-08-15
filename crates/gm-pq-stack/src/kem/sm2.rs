//! SM2-ECDH as a KEM (ephemeral ECDH on the GB/T 32918 curve).
//!
//! KEM-style encapsulation (the classical ECDH-KEM construction, isomorphic to
//! ISO 18033-2 ECIES-KEM):
//! - Encapsulator: generate an ephemeral key pair (d_e, P_e = d_e·G); shared secret ss = (d_e · P_peer).x
//! - Ciphertext is the ephemeral public key P_e (65-byte uncompressed point)
//! - Decapsulator: ss = (d_self · P_e).x
//!
//! Security relies on the CDH assumption on the SM2 curve (256-bit curve, classical
//! security strength ≈128 bits).

use crate::rng::SysRng;
use crate::{Error, Result};
use libsmx::sm2::{self, PrivateKey, key_exchange};

use super::{Kem, StaticAuth};

/// SM2-ECDH KEM
pub struct Sm2Kem;

impl Kem for Sm2Kem {
    const NAME: &'static str = "SM2-ECDH";
    /// Uncompressed point 04||x||y = 65 bytes
    const PUBLIC_KEY_LEN: usize = 65;
    const CIPHERTEXT_LEN: usize = 65;

    type SecretKey = PrivateKey;

    fn keypair(rng: &mut SysRng) -> Result<(Self::SecretKey, Vec<u8>)> {
        let (sk, pk) = sm2::generate_keypair(rng);
        Ok((sk, pk.to_vec()))
    }

    fn encapsulate(rng: &mut SysRng, peer_public: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        Self::validate_public(peer_public)?;
        let peer: &[u8; 65] = peer_public.try_into().unwrap();
        let (eph_sk, eph_pk) = sm2::generate_keypair(rng);
        let ss = key_exchange::ecdh(&eph_sk, peer)?;
        Ok((eph_pk.to_vec(), ss))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<[u8; 32]> {
        Self::validate_public(ct)?;
        let eph_peer: &[u8; 65] = ct.try_into().unwrap();
        Ok(key_exchange::ecdh(sk, eph_peer)?)
    }

    fn public_of(sk: &Self::SecretKey) -> Vec<u8> {
        sk.public_key().to_vec()
    }

    fn validate_public(pk: &[u8]) -> Result<()> {
        if pk.len() != Self::PUBLIC_KEY_LEN {
            return Err(Error::InvalidEncoding("SM2 public key must be a 65-byte uncompressed point"));
        }
        // Validity (on-curve) is checked internally by ecdh; here we only do a length pre-check
        Ok(())
    }
}

impl StaticAuth for Sm2Kem {
    const SIGNATURE_LEN: usize = 64; // SM2 signature r||s

    fn sign(sk: &Self::SecretKey, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        // Sign the transcript hash directly with SM2 (e is already an SM3 output,
        // so no additional Z||M hashing is needed).
        let mut rng = SysRng::new();
        Ok(sm2::sign(transcript_hash, sk, &mut rng).to_vec())
    }

    fn verify(pk: &[u8], transcript_hash: &[u8; 32], sig: &[u8]) -> Result<()> {
        Self::validate_public(pk)?;
        if sig.len() != Self::SIGNATURE_LEN {
            return Err(Error::InvalidEncoding("SM2 signature must be 64 bytes (r||s)"));
        }
        let pub_key: &[u8; 65] = pk.try_into().unwrap();
        let sig_arr: &[u8; 64] = sig.try_into().unwrap();
        sm2::verify(transcript_hash, pub_key, sig_arr).map_err(|_| Error::PeerAuth)
    }
}
