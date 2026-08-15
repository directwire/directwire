//! DoS protection: stateless cookie challenge (isomorphic to WireGuard / DTLS).
//!
//! ## Mechanism
//!
//! On the first handshake message (msg1) the server **allocates no session state**; instead it
//! replies with a stateless cookie:
//!
//! ```text
//! cookie = ts(8B BE) || SM3-HMAC(server_secret, ts || client_tag || e_i)
//! ```
//!
//! - `client_tag`: transport-layer identity tag (byte representation of the peer IP:port over TCP);
//! - `e_i`: the client's msg1 ephemeral public key — the cookie is bound to this msg1, so an
//!   attacker cannot transplant the cookie to another handshake;
//! - `ts`: issue timestamp; cookies older than the TTL are discarded, preventing hoarded replays.
//!
//! The client must re-send msg1 with the cookie (`msg1' = cookie || e_i`). Until verification
//! passes the server only does two SM3-HMAC computations — **no key generation, no state
//! allocation, no elliptic-curve/lattice math** — so a spoofed-source flood costs the attacker
//! (who never receives a cookie) all of the work.
//!
//! Difference from WireGuard: WireGuard only enables cookies under load; this implementation
//! always enables them (skeleton simplification — the expensive part of the handshake is the
//! KEM, and the cookie cost is negligible).

use zeroize::Zeroizing;

use crate::crypto::sm3;
use crate::{Error, Result};

/// Default cookie validity period (seconds)
pub const DEFAULT_COOKIE_TTL_SECS: u64 = 30;
/// Cookie byte length: 8-byte timestamp + 32-byte HMAC
pub const COOKIE_LEN: usize = 8 + 32;

const HMAC_KEY_LABEL: &[u8] = b"gm-pq-stack/cookie/v1";

/// Server-side cookie issuer/verifier (holds a symmetric secret; itself stateless)
pub struct CookieIssuer {
    secret: Zeroizing<[u8; 32]>,
    ttl_secs: u64,
}

impl CookieIssuer {
    /// Issuer with a freshly generated random secret (process-level; all old cookies invalidate on restart — as intended)
    pub fn new(ttl_secs: u64) -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("CSPRNG unavailable");
        CookieIssuer {
            secret: Zeroizing::new(secret),
            ttl_secs,
        }
    }

    /// Construct with a fixed secret (shared across instances / for tests)
    pub fn from_secret(secret: [u8; 32], ttl_secs: u64) -> Self {
        CookieIssuer {
            secret: Zeroizing::new(secret),
            ttl_secs,
        }
    }

    fn mac(&self, ts: u64, client_tag: &[u8], e_pk: &[u8]) -> [u8; 32] {
        // Key derivation: HMAC key = SM3(label || secret); domain separation prevents cross-protocol misuse
        let key = sm3(&[HMAC_KEY_LABEL, &*self.secret]);
        libsmx::sm3::hmac_sm3(&key, &[&ts.to_be_bytes(), client_tag, e_pk].concat())
    }

    /// Issue a cookie for one msg1
    pub fn issue(&self, client_tag: &[u8], e_pk: &[u8]) -> Vec<u8> {
        let ts = now_secs();
        let tag = self.mac(ts, client_tag, e_pk);
        let mut out = Vec::with_capacity(COOKIE_LEN);
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(&tag);
        out
    }

    /// Verify a cookie: format, freshness, and HMAC must all pass
    pub fn verify(&self, client_tag: &[u8], e_pk: &[u8], cookie: &[u8]) -> Result<()> {
        if cookie.len() != COOKIE_LEN {
            return Err(Error::InvalidEncoding("invalid cookie length"));
        }
        let ts = u64::from_be_bytes(cookie[..8].try_into().unwrap());
        let now = now_secs();
        // Reject expired cookies, and ones "from the future" (5-second clock-skew tolerance)
        if ts > now + 5 || now.saturating_sub(ts) > self.ttl_secs {
            return Err(Error::HandshakeState("cookie expired"));
        }
        let expect = self.mac(ts, client_tag, e_pk);
        // Constant-time comparison (32-byte SM3 output, accumulating XOR over bytes)
        let mut diff = 0u8;
        for (a, b) in expect.iter().zip(&cookie[8..]) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(Error::HandshakeState("cookie verification failed"));
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
