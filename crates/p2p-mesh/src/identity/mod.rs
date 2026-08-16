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
use std::io;
use std::path::Path;
use zeroize::Zeroizing;

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

    /// The ed25519 seed (== the signing key bytes). Wrapped in `Zeroizing` so the buffer is
    /// cleared on drop — the seed IS the identity, never let it linger in plain memory.
    pub(crate) fn seed_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.sk.to_bytes())
    }

    /// Persist the seed to a file (raw 32 bytes == the ed25519 signing key).
    ///
    /// This file IS the identity: keep it in a restricted location. Best-effort `0600`
    /// permissions on Unix; no-op on Windows. Encryption at rest (key wrap) is a
    /// compliance/red-line follow-up, deliberately not implemented here.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let bytes = self.seed_bytes();
        std::fs::write(path.as_ref(), &*bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a persisted seed (must be exactly 32 bytes).
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let raw = Zeroizing::new(std::fs::read(path.as_ref())?);
        if raw.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "identity seed file must be exactly 32 bytes",
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        Ok(Self::from_seed(seed))
    }

    /// Load the seed if present; otherwise generate a fresh identity, persist it, and return it.
    /// This is what makes a NodeId recoverable across process restarts (stable identity).
    pub fn load_or_generate(path: impl AsRef<Path>) -> io::Result<Self> {
        if path.as_ref().exists() {
            Self::load(path)
        } else {
            let id = Self::generate();
            id.save(path)?;
            Ok(id)
        }
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

    #[test]
    fn seed_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dw-identity-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.seed");
        let id = NodeIdentity::from_seed([7u8; 32]);
        id.save(&path).unwrap();
        let loaded = NodeIdentity::load(&path).unwrap();
        assert_eq!(
            loaded.node_id(),
            id.node_id(),
            "load must recover the same identity"
        );
        assert!(id.sign(b"persisted").len() == 64);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_or_wrong_length_errors() {
        let dir = std::env::temp_dir().join(format!("dw-identity-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.seed");
        assert!(
            NodeIdentity::load(&missing).is_err(),
            "missing file must error"
        );
        let bad = dir.join("bad.seed");
        std::fs::write(&bad, [1u8; 31]).unwrap();
        assert!(
            NodeIdentity::load(&bad).is_err(),
            "non-32-byte file must error"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("dw-identity-generate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.seed");
        let a = NodeIdentity::load_or_generate(&path).unwrap();
        let b = NodeIdentity::load_or_generate(&path).unwrap();
        assert_eq!(
            a.node_id(),
            b.node_id(),
            "second load_or_generate must reuse the persisted identity"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
