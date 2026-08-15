//! Node identity: NodeId = ed25519 public key (the core of "dial by public key, not by IP")
//!
//! - The 32-byte public key is the globally unique address; a peer's identity is constant across
//!   any path (direct / relay)
//! - Display form: the first 16 hex chars of SHA-256(public key), easy to read in logs / CLIs
//! - Self-signed node certificates live in [`crate::quic`] (certificate public key == identity
//!   public key, so the TLS handshake IS the identity handshake)

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Node ID: ed25519 public key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Display form: the first 16 hex chars of SHA-256(public key)
    pub fn short(&self) -> String {
        let h = Sha256::digest(self.0);
        hex_encode(&h[..8])
    }

    /// Full public-key hex (64 chars; for CLI arguments)
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, IdentityError> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(IdentityError::BadHex);
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] =
                u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| IdentityError::BadHex)?;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

/// Node identity (long-term keypair)
#[derive(Clone)]
pub struct NodeIdentity {
    sk: SigningKey,
}

impl NodeIdentity {
    /// Generate randomly
    pub fn generate() -> Self {
        Self {
            sk: SigningKey::generate(&mut rand_core::OsRng),
        }
    }

    /// Deterministically derive from a 32-byte seed (for reproducible NodeIds in demos)
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(&seed),
        }
    }

    pub fn node_id(&self) -> NodeId {
        NodeId(self.sk.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).to_bytes()
    }

    pub(crate) fn seed_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

/// Verify a signature against a NodeId
pub fn verify(id: &NodeId, msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&id.0) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

#[derive(Debug)]
pub enum IdentityError {
    BadHex,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHex => write!(f, "NodeId hex format error (need 64 hex chars)"),
        }
    }
}

impl std::error::Error for IdentityError {}

pub(crate) fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_roundtrip_and_sign() {
        let id = NodeIdentity::generate();
        let nid = id.node_id();
        // hex roundtrip
        assert_eq!(NodeId::from_hex(&nid.to_hex()).unwrap(), nid);
        // sign / verify
        let sig = id.sign(b"hello");
        assert!(verify(&nid, b"hello", &sig));
        assert!(!verify(&nid, b"tampered", &sig));
        // deterministic seed
        let a = NodeIdentity::from_seed([7u8; 32]);
        let b = NodeIdentity::from_seed([7u8; 32]);
        assert_eq!(a.node_id(), b.node_id());
        // short display form is 16 chars
        assert_eq!(nid.short().len(), 16);
    }
}
