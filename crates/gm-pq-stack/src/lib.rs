//! # gm-pq-stack — SM2 + ML-KEM-768 hybrid handshake and secure transport
//!
//! Architecture follows the shape of modern Noise-style hybrid handshakes
//! (X25519 + ML-KEM-768, now the browser default). Algorithms are the
//! national-crypto SM2/SM3/SM4 set (compliance baseline) plus ML-KEM-768
//! (post-quantum readiness).
//!
//! ## Modules
//! - [`kem`]: KEM trait abstraction + SM2-ECDH / ML-KEM-768 implementations + hybrid combiner
//! - [`handshake`]: Noise-XX-style three-message handshake (hybrid-KEM variant) + transport session
//!   + cookie challenge (DoS protection) + PSK session resumption (0-RTT)
//! - [`crypto`]: SM3-KDF/HKDF, SM4-GCM AEAD wrappers
//! - [`trust`]: trust-anchor abstraction (public-key pinning)
//! - [`api`]: minimal integration API for downstream projects (any bidirectional byte stream -> encrypted session)
//! - [`rng`]: OS random adapter

pub mod api;
pub mod crypto;
pub mod handshake;
pub mod kem;
pub mod rng;
pub mod trust;

use std::fmt;

/// Library-wide unified error type
#[derive(Debug)]
pub enum Error {
    /// Underlying national-crypto algorithm error (libsmx)
    Sm(libsmx::error::Error),
    /// Malformed public key / ciphertext, or length mismatch
    InvalidEncoding(&'static str),
    /// AEAD authentication failed (possible tampering)
    AuthFailed,
    /// Handshake state machine received an out-of-order / invalid message
    HandshakeState(&'static str),
    /// Replay detected (sequence number already seen in the window)
    Replay,
    /// Peer identity / key verification failed
    PeerAuth,
    /// I/O error
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sm(e) => write!(f, "national-crypto algorithm error: {e:?}"),
            Error::InvalidEncoding(m) => write!(f, "invalid encoding: {m}"),
            Error::AuthFailed => write!(f, "AEAD authentication failed"),
            Error::HandshakeState(m) => write!(f, "handshake state error: {m}"),
            Error::Replay => write!(f, "replayed packet detected"),
            Error::PeerAuth => write!(f, "peer identity verification failed"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<libsmx::error::Error> for Error {
    fn from(e: libsmx::error::Error) -> Self {
        Error::Sm(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
