//! PSK session resumption (0-RTT) support: server-issued self-encrypted session tickets.
//!
//! ## Mechanism
//!
//! After a full handshake completes, the server issues a ticket encrypted with a **ticket key**
//! (SM4-GCM, held only by the server):
//!
//! ```text
//! ticket_plain = version(1B) || psk(32B) || ticket_id(16B) || expires_at(8B)
//!              || SM3(client_static_pk)(32B)
//! ticket       = nonce(12B) || SM4-GCM_Enc(ticket_key, ticket_plain) || tag(16B)
//! ```
//!
//! On reconnect the client sends `ticket || e_i || AEAD_psk(early_data)`:
//! - The server decrypts the ticket (symmetric-only, cheap) → extracts the PSK → mixes it into
//!   the chaining key at Noise `psk` token position 0 → runs the normal msg2/msg3 flow;
//! - Early data is encrypted with a key derived from PSK + e_i and arrives with msg1 (0-RTT).
//!
//! ## Replay protection and forward-secrecy notes (important)
//!
//! 1. **One-time tickets**: `ticket_id` is recorded by [`TicketCache`] until expiry; the 0-RTT
//!    data of one ticket is accepted only once; replaying the whole first message is intercepted
//!    by the cache.
//! 2. **Identity binding**: the ticket embeds the SM3 fingerprint of the client's static public
//!    key; if the msg3-verified public key differs from the ticket fingerprint, the session is
//!    rejected — a stolen ticket cannot impersonate another identity.
//! 3. **0-RTT has no full forward secrecy**: early data is protected only by the PSK; a PSK
//!    leak decrypts historical 0-RTT data; and beyond the cache-expiry window (server restart
//!    with a new ticket key invalidates old tickets, an acceptable degradation) there is a
//!    theoretical replay window after a crash. **The application MUST treat 0-RTT data as
//!    idempotent.** Transport keys derived after msg2 enjoy full forward secrecy (ephemeral KEM
//!    keys participate).

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::crypto::sm3;
use crate::{Error, Result};

/// Ticket plaintext length
const TICKET_PLAIN_LEN: usize = 1 + 32 + 16 + 8 + 32;
/// Ticket ciphertext length = nonce(12) + plaintext + tag(16)
pub const TICKET_LEN: usize = 12 + TICKET_PLAIN_LEN + 16;

/// Ticket-key label (SM3-HKDF domain separation)
const TICKET_KEY_INFO: &[u8] = b"ticket-key";

/// Server-side ticket issuer/decryptor
pub struct TicketIssuer {
    key: Zeroizing<[u8; 16]>,
}

/// Decrypted ticket payload
pub struct TicketPayload {
    /// Resumption PSK (zeroized after use)
    pub psk: Zeroizing<[u8; 32]>,
    /// One-time ticket ID
    pub ticket_id: [u8; 16],
    /// Expiry time (unix seconds)
    pub expires_at: u64,
    /// SM3 fingerprint of the client's static public key at issue time
    pub client_pk_fingerprint: [u8; 32],
}

impl TicketIssuer {
    /// Derive the ticket key from a master secret (managed by the deployment, e.g. config file / KMS)
    pub fn from_master(master: &[u8; 32]) -> Self {
        let key: [u8; 16] = crate::crypto::hkdf_expand(&sm3(&[master]), TICKET_KEY_INFO, 16)
            .try_into()
            .unwrap();
        TicketIssuer {
            key: Zeroizing::new(key),
        }
    }

    /// Random ticket key (process-level; all old tickets invalidate on restart)
    pub fn new() -> Self {
        let mut master = [0u8; 32];
        getrandom::fill(&mut master).expect("CSPRNG unavailable");
        Self::from_master(&Zeroizing::new(master))
    }

    /// Issue a ticket for one completed handshake, returning (ticket bytes, PSK).
    /// The PSK goes to both parties: sealed in the ticket by the server, stored by the client.
    pub fn issue(
        &self,
        client_static_pk: &[u8],
        ttl_secs: u64,
    ) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
        let mut plain = Vec::with_capacity(TICKET_PLAIN_LEN);
        let mut psk = [0u8; 32];
        let mut ticket_id = [0u8; 16];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut psk).expect("CSPRNG");
        getrandom::fill(&mut ticket_id).expect("CSPRNG");
        getrandom::fill(&mut nonce).expect("CSPRNG");

        let expires_at = now_secs() + ttl_secs;
        let fp = sm3(&[client_static_pk]);

        plain.push(1u8); // version
        plain.extend_from_slice(&psk);
        plain.extend_from_slice(&ticket_id);
        plain.extend_from_slice(&expires_at.to_be_bytes());
        plain.extend_from_slice(&fp);

        let (ct, tag) = libsmx::sm4::sm4_encrypt_gcm(&self.key, &nonce, b"ticket", &plain);
        let plain = Zeroizing::new(plain);
        drop(plain);

        let mut ticket = Vec::with_capacity(TICKET_LEN);
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&ct);
        ticket.extend_from_slice(&tag);
        (ticket, Zeroizing::new(psk))
    }

    /// Decrypt and validate a ticket (format + freshness). One-time checks are NOT done here —
    /// that is [`TicketCache`]'s job.
    pub fn open(&self, ticket: &[u8]) -> Result<TicketPayload> {
        if ticket.len() != TICKET_LEN {
            return Err(Error::InvalidEncoding("invalid ticket length"));
        }
        let nonce: &[u8; 12] = ticket[..12].try_into().unwrap();
        let ct = &ticket[12..ticket.len() - 16];
        let tag: &[u8; 16] = ticket[ticket.len() - 16..].try_into().unwrap();
        let plain = Zeroizing::new(
            libsmx::sm4::sm4_decrypt_gcm(&self.key, nonce, b"ticket", ct, tag)
                .map_err(|_| Error::AuthFailed)?,
        );
        if plain.len() != TICKET_PLAIN_LEN || plain[0] != 1 {
            return Err(Error::InvalidEncoding("invalid ticket version/length"));
        }
        let expires_at = u64::from_be_bytes(plain[49..57].try_into().unwrap());
        if now_secs() > expires_at {
            return Err(Error::HandshakeState("ticket expired"));
        }
        Ok(TicketPayload {
            psk: Zeroizing::new(plain[1..33].try_into().unwrap()),
            ticket_id: plain[33..49].try_into().unwrap(),
            expires_at,
            client_pk_fingerprint: plain[57..89].try_into().unwrap(),
        })
    }
}

/// One-time ticket cache (replay interception): records ticket_ids until expiry.
/// This skeleton is in-memory; production cluster deployments must swap in shared storage (e.g. Redis).
#[derive(Default)]
pub struct TicketCache {
    seen: HashMap<[u8; 16], u64>,
}

impl TicketCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// First sighting returns Ok and registers the ticket; a repeat (replay) returns Err(Replay).
    pub fn check_and_insert(&mut self, ticket_id: [u8; 16], expires_at: u64) -> Result<()> {
        self.gc();
        if self.seen.contains_key(&ticket_id) {
            return Err(Error::Replay);
        }
        self.seen.insert(ticket_id, expires_at);
        Ok(())
    }

    /// Lazily purge expired entries
    fn gc(&mut self) {
        let now = now_secs();
        self.seen.retain(|_, exp| *exp > now);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
