//! Trust-anchor abstraction: deciding whether a peer's static public key is trusted.
//!
//! The SM2 signature inside the handshake only proves "the peer holds the
//! corresponding private key" (proof of possession). Whether "this public key
//! is the peer we actually want to talk to" is answered by the trust anchor.
//! This module provides a trait abstraction and a public-key pinning file
//! implementation; CA certificate-chain validation can be plugged in as
//! another implementation of the same trait.

use std::collections::HashMap;
use std::path::Path;

use crate::crypto::sm3;
use crate::{Error, Result};

/// Peer role
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The initiator (client)
    Initiator,
    /// The responder (server)
    Responder,
}

/// Trust anchor: decides whether a static public key is trusted in a given role
pub trait TrustAnchor {
    /// Returns Ok(()) if trusted, otherwise Err (which aborts the handshake)
    fn verify(&self, role: Role, static_pk: &[u8]) -> Result<()>;
}

/// Public-key pinning file trust anchor.
///
/// File format (one entry per line, `#` starts a comment):
/// ```text
/// gateway-01  3f2a9c...<64 hex chars of SM3(pubkey)>
/// ```
#[derive(Debug, Default)]
pub struct PinFileAnchor {
    /// SM3(pubkey) fingerprint -> name
    pins: HashMap<[u8; 32], String>,
}

impl PinFileAnchor {
    /// Load from a file
    pub fn from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Self::parse(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Parse from a string (for tests)
    pub fn parse(data: &str) -> Result<Self> {
        let mut pins = HashMap::new();
        for (lineno, line) in data.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (name, hex_fp) = match (parts.next(), parts.next()) {
                (Some(n), Some(h)) => (n, h),
                _ => {
                    return Err(Error::InvalidEncoding(
                        "pin line must be: name fingerprint-hex",
                    ));
                }
            };
            let fp = decode_hex32(hex_fp).ok_or(Error::InvalidEncoding(
                "pin fingerprint must be 64 hex chars (SM3 output)",
            ))?;
            if pins.insert(fp, name.to_string()).is_some() {
                return Err(Error::InvalidEncoding("duplicate pin fingerprint"));
            }
            let _ = lineno;
        }
        if pins.is_empty() {
            return Err(Error::InvalidEncoding("empty pin file"));
        }
        Ok(PinFileAnchor { pins })
    }

    /// Construct directly from a (name, public key) list
    pub fn from_keys<'a>(entries: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let mut pins = HashMap::new();
        for (name, pk) in entries {
            pins.insert(sm3(&[pk]), name.to_string());
        }
        PinFileAnchor { pins }
    }

    /// Returns the name on a hit (for logging)
    pub fn lookup(&self, static_pk: &[u8]) -> Option<&str> {
        self.pins.get(&sm3(&[static_pk])).map(String::as_str)
    }
}

impl TrustAnchor for PinFileAnchor {
    fn verify(&self, _role: Role, static_pk: &[u8]) -> Result<()> {
        if self.lookup(static_pk).is_some() {
            Ok(())
        } else {
            Err(Error::PeerAuth)
        }
    }
}

/// Anchor that explicitly allows everything (**tests / development only**, never in production)
pub struct AllowAllAnchor;

impl TrustAnchor for AllowAllAnchor {
    fn verify(&self, _role: Role, _static_pk: &[u8]) -> Result<()> {
        Ok(())
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
