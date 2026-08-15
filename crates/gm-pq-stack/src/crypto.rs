//! Cryptographic primitive wrappers: SM3-HKDF, SM4-GCM AEAD.
//!
//! All based on libsmx (GB/T 32905 SM3 / GB/T 32907 SM4 + GCM AEAD).
//! Transport-layer keys are 16 bytes (SM4-128); GCM authentication tags are 16 bytes.

use crate::{Error, Result};
use libsmx::sm3::{Sm3Hasher, hkdf};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Protocol domain-separation label: prefix for SM3-HKDF info, prevents cross-protocol key reuse
pub const KDF_DOMAIN: &str = "gm-pq-stack v0.1";

/// SM3 hash (convenience wrapper)
pub fn sm3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sm3Hasher::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// SM3-HKDF-Extract
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    hkdf::hkdf_extract(salt, ikm)
}

/// SM3-HKDF-Expand (with protocol domain separation)
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut full_info = Vec::with_capacity(KDF_DOMAIN.len() + info.len());
    full_info.extend_from_slice(KDF_DOMAIN.as_bytes());
    full_info.extend_from_slice(info);
    hkdf::hkdf_expand(prk, &full_info, len).expect("valid HKDF output length")
}

/// Extract + Expand in one step
pub fn hkdf_sm3(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, len)
}

/// SM4-GCM AEAD session encryptor.
///
/// Nonce construction: 4-byte fixed zero prefix || 8-byte big-endian sequence
/// number (Noise-style 96-bit nonce). The sequence number increases
/// monotonically, which inherently prevents nonce reuse; replay protection is
/// handled upstream by `handshake::session`. The key is held in [`Zeroizing`]
/// and zeroized on drop.
pub struct Aead {
    key: Zeroizing<[u8; 16]>,
    /// Tx sequence number (monotonically increasing on the encrypting side)
    tx_seq: u64,
}

// Compile-time marker: Aead must zeroize key material on drop
impl ZeroizeOnDrop for Aead {}

impl Aead {
    pub fn new(key: [u8; 16]) -> Self {
        Aead {
            key: Zeroizing::new(key),
            tx_seq: 0,
        }
    }

    fn nonce(seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    /// Encrypt a message, returning `seq(8B) || ciphertext || tag(16B)`
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let seq = self.tx_seq;
        self.tx_seq = self
            .tx_seq
            .checked_add(1)
            .expect("sequence number exhausted (2^64 message ceiling)");
        self.seal_with_seq(seq, aad, plaintext)
    }

    /// Encrypt with a specific sequence number (for tests / replay construction)
    pub fn seal_with_seq(&self, seq: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let (ct, tag) =
            libsmx::sm4::sm4_encrypt_gcm(&self.key, &Self::nonce(seq), aad, plaintext);
        let mut out = Vec::with_capacity(8 + ct.len() + 16);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        out
    }

    /// Decrypt `seq(8B) || ciphertext || tag(16B)`, returning `(seq, plaintext)`.
    /// On authentication failure returns [`Error::AuthFailed`] and no plaintext
    /// (avoids padding/oracle-style misuse).
    pub fn open(&self, aad: &[u8], packet: &[u8]) -> Result<(u64, Vec<u8>)> {
        if packet.len() < 8 + 16 {
            return Err(Error::InvalidEncoding("AEAD packet too short"));
        }
        let seq = u64::from_be_bytes(packet[..8].try_into().unwrap());
        let ct_end = packet.len() - 16;
        let ct = &packet[8..ct_end];
        let tag: &[u8; 16] = packet[ct_end..].try_into().unwrap();
        let pt = libsmx::sm4::sm4_decrypt_gcm(&self.key, &Self::nonce(seq), aad, ct, tag)
            .map_err(|_| Error::AuthFailed)?;
        Ok((seq, pt))
    }
}
