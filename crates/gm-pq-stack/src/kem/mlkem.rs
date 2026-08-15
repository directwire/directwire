//! ML-KEM-768 (FIPS 203) wrapper.
//!
//! Uses the `getrandom` feature of the RustCrypto ml-kem crate: key generation
//! and encapsulation draw from the OS CSPRNG internally, no RNG injection needed.
//!
//! Parameter set 768: public key 1184 B, ciphertext 1088 B, shared secret 32 B,
//! NIST security category 3.

use crate::rng::SysRng;
use crate::{Error, Result};
use ml_kem::kem::{Decapsulate, Encapsulate};
// The Kem trait provides generate_keypair() (getrandom feature)
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Kem as _, KeyExport, MlKem768};

use super::Kem;

/// ML-KEM-768 KEM
pub struct MlKem768Kem;

impl Kem for MlKem768Kem {
    const NAME: &'static str = "ML-KEM-768";
    const PUBLIC_KEY_LEN: usize = 1184;
    const CIPHERTEXT_LEN: usize = 1088;

    type SecretKey = DecapsulationKey768;

    fn keypair(_rng: &mut SysRng) -> Result<(Self::SecretKey, Vec<u8>)> {
        // getrandom feature: uses the OS CSPRNG internally
        let (dk, ek) = MlKem768::generate_keypair();
        Ok((dk, ek.to_bytes().to_vec()))
    }

    fn encapsulate(_rng: &mut SysRng, peer_public: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        Self::validate_public(peer_public)?;
        let ek_bytes = peer_public
            .try_into()
            .map_err(|_| Error::InvalidEncoding("invalid ML-KEM public key length"))?;
        let ek = EncapsulationKey768::new(ek_bytes)
            .map_err(|_| Error::InvalidEncoding("ML-KEM public key decode failed"))?;
        let (ct, ss) = ek.encapsulate();
        Ok((ct.to_vec(), ss.into()))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<[u8; 32]> {
        if ct.len() != Self::CIPHERTEXT_LEN {
            return Err(Error::InvalidEncoding("invalid ML-KEM ciphertext length"));
        }
        let ct_arr = ct.try_into().unwrap();
        // ML-KEM uses implicit rejection: a tampered ciphertext yields a pseudorandom key
        // rather than an error, so the two handshake sides end up with different session keys
        // and the subsequent AEAD authentication necessarily fails.
        Ok(sk.decapsulate(ct_arr).into())
    }

    fn public_of(sk: &Self::SecretKey) -> Vec<u8> {
        // The Decapsulator trait exposes the matching encapsulation key
        ml_kem::kem::Decapsulator::encapsulation_key(sk)
            .to_bytes()
            .to_vec()
    }

    fn validate_public(pk: &[u8]) -> Result<()> {
        if pk.len() != Self::PUBLIC_KEY_LEN {
            return Err(Error::InvalidEncoding(
                "ML-KEM public key must be 1184 bytes",
            ));
        }
        Ok(())
    }
}
