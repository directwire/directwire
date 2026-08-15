//! KEM abstraction layer: unifies the classical (SM2) and post-quantum
//! (ML-KEM-768) interfaces and provides a hybrid combiner.
//!
//! ## Combiner security argument (outline; see the [`hybrid`] module docs for details)
//! Hybrid shared secret = SM3-KDF(ss_c || ss_p || ct_c || ct_p || pk_c || pk_p || domain label).
//! This follows the X-Wing (GHP18 combiner) paradigm: as long as at least one of the
//! component KEMs remains IND-CCA secure, the combined output is indistinguishable from
//! random for the attacker — i.e. the attacker must break both SM2-ECDH and ML-KEM-768.

pub mod hybrid;
pub mod mlkem;
pub mod sm2;

use crate::Result;
use crate::rng::SysRng;

pub use hybrid::HybridKem;
pub use mlkem::MlKem768Kem;
pub use sm2::Sm2Kem;

/// Unified KEM abstraction (public keys / ciphertexts are byte-oriented for direct wire transport)
pub trait Kem {
    /// Scheme name (for logging and mode identification)
    const NAME: &'static str;
    /// Public-key length in bytes
    const PUBLIC_KEY_LEN: usize;
    /// Ciphertext length in bytes
    const CIPHERTEXT_LEN: usize;
    /// Secret-key type (no byte interface exposed, to prevent accidental serialization)
    type SecretKey;

    /// Generate a key pair, returning (secret key, public key bytes)
    fn keypair(rng: &mut SysRng) -> Result<(Self::SecretKey, Vec<u8>)>;

    /// Encapsulate: produce (ciphertext, 32-byte shared secret) for `peer_public`
    fn encapsulate(rng: &mut SysRng, peer_public: &[u8]) -> Result<(Vec<u8>, [u8; 32])>;

    /// Decapsulate: recover the 32-byte shared secret from the ciphertext
    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<[u8; 32]>;

    /// Derive the public-key bytes from the secret key (needed to bind public parameters in the combiner)
    fn public_of(sk: &Self::SecretKey) -> Vec<u8>;

    /// Validate public-key byte format (length + validity), called before the key is mixed into the transcript
    fn validate_public(pk: &[u8]) -> Result<()>;
}

/// Optional capability: initiator proof of possession.
///
/// Pure-KEM Noise XX has a structural limitation: in msg3 the initiator's static public key
/// can be encrypted-and-replayed by anyone, and KEM alone cannot prove the initiator holds the
/// corresponding secret key (a known difficulty of the "se" token once DH is replaced by KEM;
/// discussed in the KEMTLS / Noise-KEM literature).
///
/// Solution: schemes with a signature capability (SM2) sign the transcript hash and transmit
/// it AEAD-encrypted alongside the static public key; pure-PQ modes without signatures
/// (MlKemOnly) provide only responder one-way authentication (matching the browser scenario of
/// TLS 1.3 hybrid modes).
pub trait StaticAuth: Kem {
    /// Signature length in bytes (used for msg3 parsing)
    const SIGNATURE_LEN: usize;
    /// Sign a 32-byte transcript hash
    fn sign(sk: &Self::SecretKey, transcript_hash: &[u8; 32]) -> Result<Vec<u8>>;
    /// Verify a signature (public key is the bytes produced by [`Kem::public_of`])
    fn verify(pk: &[u8], transcript_hash: &[u8; 32], sig: &[u8]) -> Result<()>;
}

/// Convenience alias: default hybrid scheme = SM2-ECDH + ML-KEM-768
pub type DefaultHybrid = HybridKem<Sm2Kem, MlKem768Kem>;

/// Handshake modes (for examples / deployment-side selection)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Pure SM2-ECDH (compliant but no post-quantum capability)
    Sm2Only,
    /// Pure ML-KEM-768 (post-quantum but not compliant at the algorithm layer)
    MlKemOnly,
    /// Hybrid (default, recommended)
    Hybrid,
}

impl Mode {
    pub fn name(&self) -> &'static str {
        match self {
            Mode::Sm2Only => Sm2Kem::NAME,
            Mode::MlKemOnly => MlKem768Kem::NAME,
            Mode::Hybrid => DefaultHybrid::NAME,
        }
    }
}
