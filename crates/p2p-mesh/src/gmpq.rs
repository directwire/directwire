//! GM-PQ hybrid channel (national-crypto + post-quantum): SM2 + ML-KEM-768 hybrid handshake + SM4-GCM transport
//!
//! Integration path (the "pocket signaling channel" route described in INTEGRATION.md):
//! the relay's RelayData is a message channel with its own framing, so we use the pure in-memory
//! state machines `gm_pq_stack::handshake::{Initiator, Responder, Session}` directly — each
//! handshake message travels as one RelayData payload (0x47 prefix), **zero blocking threads,
//! zero Read/Write adapters**. The X25519 + ed25519 handshake is kept as a fallback (auto-fallback
//! when the peer lacks support or the handshake times out).
//!
//! ## Identity binding (critical security semantics)
//! The gm-pq static key is an SM2 hybrid keypair — a different identity system from p2p-mesh's
//! NodeId (ed25519). Binding scheme: after the handshake, both sides exchange a BIND message
//! inside the encrypted channel:
//!   `sig = Ed25519.Sign("p2p-mesh/gmpq-bind" || SM3(gm_static_pk) || node_id || session_id)`
//! The session is not considered ready until the signature verifies. Security argument:
//! - session_id is derived from the handshake transcript; a MITM splitting the handshake into
//!   two halves gets different session_ids, so forwarding a BIND is rejected on the session_id
//!   mismatch; forging the signature requires the ed25519 private key;
//! - the gm-pq layer's trust anchor is pluggable: `NodeConfig.gmpq_pin_file` pins the allowed SM2
//!   public keys (TOFU upgraded to explicit pinning); without it, the anchor is AllowAll
//!   (tests/demos only).
//!
//! ## Red-line compliance
//! - client_tag: the relay path has no source-IP semantics, so the peer's NodeId bytes serve as the
//!   source binding (DoS cookies are only weakly relevant behind the relay anyway; kept as
//!   defense-in-depth);
//! - 0-RTT / ticket resumption: the MVP does **not** use it (no early data, no idempotency surface);
//! - TicketCache: no tickets are issued, so the cross-connection sharing question is moot.

use gm_pq_stack::crypto::sm3;
pub use gm_pq_stack::handshake::Session;
use gm_pq_stack::handshake::{Initiator, Responder};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;

pub use gm_pq_stack::handshake::cookie::{CookieIssuer, COOKIE_LEN};
pub use gm_pq_stack::trust::{AllowAllAnchor, PinFileAnchor, TrustAnchor};

use crate::identity::{hex_encode, verify, NodeId, NodeIdentity};

/// GM-PQ channel marker inside a RelayData payload (0x48 is the X25519 handshake; no collision)
pub const GM_TAG: u8 = 0x47; // 'G'

/// GM-PQ channel subtypes
pub const GM_MSG1: u8 = 0x01; // -> e (ephemeral public key)
pub const GM_COOKIE: u8 = 0x02; // <- cookie challenge
pub const GM_MSG1_RETRY: u8 = 0x03; // -> cookie echo || e
pub const GM_MSG2: u8 = 0x04; // <- e_r || ct_ee || AEAD(s_r)
pub const GM_MSG3: u8 = 0x05; // -> ct_se || ct_ss || AEAD(s_i || sig)
pub const GM_DATA: u8 = 0xD0; // session ciphertext (Session::send output, including BIND/inner)
pub const GM_KICK: u8 = 0x4B; // 'K': nudge the peer to start the handshake (when we have the larger NodeId)

/// BIND message prefix (the first encrypted message inside the session)
pub const BIND_PREFIX: &[u8] = b"BND1";

/// GM-PQ identity (SM2 + ML-KEM-768 hybrid static keypair; generated at process level with
/// randomness, bound to the NodeId via the BIND signature. Persistence/preloading is a TODO)
pub struct GmIdentity {
    pub sk: <DefaultHybrid as Kem>::SecretKey,
    pub pk: Vec<u8>,
}

impl GmIdentity {
    pub fn generate() -> Option<Self> {
        let mut rng = SysRng::new();
        DefaultHybrid::keypair(&mut rng)
            .ok()
            .map(|(sk, pk)| Self { sk, pk })
    }
}

pub type GmInitiator = Initiator<DefaultHybrid>;
pub type GmResponder = Responder<DefaultHybrid>;

/// Process-level cookie issuer (DoS challenge)
pub fn new_cookie_issuer() -> CookieIssuer {
    CookieIssuer::new(30)
}

pub fn new_rng() -> SysRng {
    SysRng::new()
}

/// BIND signature: bind the gm static public-key fingerprint + session id to the ed25519 NodeId
pub fn sign_binding(me: &NodeIdentity, gm_pk: &[u8], session_id: &[u8; 32]) -> [u8; 64] {
    me.sign(&binding_msg(gm_pk, &me.node_id(), session_id))
}

pub fn verify_binding(
    peer: &NodeId,
    peer_gm_pk: &[u8],
    session_id: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    verify(peer, &binding_msg(peer_gm_pk, peer, session_id), sig)
}

/// SM3 fingerprint of an SM2 static public key, hex-encoded (64 chars) — the value that goes
/// in a pin-file line (`name <this hex>`, see `PinFileAnchor::parse`). Use this to generate
/// pin files for `NodeConfig.gmpq_pin_file`.
pub fn pin_fingerprint(pk: &[u8]) -> String {
    hex_encode(&sm3(&[pk]))
}

fn binding_msg(gm_pk: &[u8], id: &NodeId, session_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 32 + 32);
    m.extend_from_slice(b"p2p-mesh/gmpq-bind");
    m.extend_from_slice(&sm3(&[gm_pk]));
    m.extend_from_slice(id.as_bytes());
    m.extend_from_slice(session_id);
    m
}

/// Build the BIND plaintext
pub fn build_bind(me: &NodeIdentity, gm_pk: &[u8], session_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + 32 + 64);
    m.extend_from_slice(BIND_PREFIX);
    m.extend_from_slice(me.node_id().as_bytes());
    m.extend_from_slice(&sign_binding(me, gm_pk, session_id));
    m
}

/// Parse and verify a BIND plaintext, returning the peer's NodeId
pub fn parse_bind(
    plaintext: &[u8],
    expected_peer: &NodeId,
    peer_gm_pk: &[u8],
    session_id: &[u8; 32],
) -> Result<NodeId, &'static str> {
    if plaintext.len() != 4 + 32 + 64 || !plaintext.starts_with(BIND_PREFIX) {
        return Err("malformed BIND message");
    }
    let id = NodeId::from_bytes(plaintext[4..36].try_into().unwrap());
    let sig: [u8; 64] = plaintext[36..100].try_into().unwrap();
    if &id != expected_peer {
        return Err("BIND NodeId does not match the expected peer");
    }
    if !verify_binding(&id, peer_gm_pk, session_id, &sig) {
        return Err("BIND signature verification failed (identity binding mismatch / session split by a MITM)");
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_pq_stack::trust::AllowAllAnchor;

    /// Run the full handshake state machine purely in memory (no relay; feed bytes directly),
    /// exercising the driving logic
    #[test]
    fn state_machine_full_handshake_and_binding() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let gm_a = GmIdentity::generate().unwrap();
        let gm_b = GmIdentity::generate().unwrap();
        let cookie = new_cookie_issuer();
        let anchor = AllowAllAnchor;
        let mut rng = new_rng();

        // client(a) -> msg1
        let mut init = GmInitiator::new(gm_a.sk.clone(), gm_a.pk.clone());
        let e_pk = init.write_msg1(&mut rng).unwrap();
        // server(b): cookie challenge
        let ck = cookie.issue(a.node_id().as_bytes(), &e_pk);
        // client: retry
        let mut retry = ck.clone();
        retry.extend_from_slice(&e_pk);
        // server: verify the cookie
        let (echo, e_pk2) = retry.split_at(gm_pq_stack::handshake::cookie::COOKIE_LEN);
        cookie.verify(a.node_id().as_bytes(), e_pk2, echo).unwrap();
        let mut resp = GmResponder::new(gm_b.sk.clone(), gm_b.pk.clone());
        resp.read_msg1(e_pk2).unwrap();
        let m2 = resp.write_msg2(&mut rng).unwrap();
        // client: msg2 -> msg3
        init.read_msg2(&m2).unwrap();
        let (m3, mut sess_a) = init.write_msg3_with_auth(&mut rng, &anchor).unwrap();
        let peer_b_pk = init.peer_static().unwrap().to_vec();
        // server: msg3 -> session
        let (mut sess_b, peer_a_pk) = resp.read_msg3_with_auth(&m3, &anchor).unwrap();
        assert_eq!(
            sess_a.session_id(),
            sess_b.session_id(),
            "both sides' session_ids must match"
        );

        // BIND both ways
        let bind_a = build_bind(&a, &gm_a.pk, sess_a.session_id());
        let bind_b = build_bind(&b, &gm_b.pk, sess_b.session_id());
        let pkt_a = sess_a.send(&bind_a);
        let pkt_b = sess_b.send(&bind_b);
        let got_b = sess_b.recv(&pkt_a).unwrap();
        let got_a = sess_a.recv(&pkt_b).unwrap();
        parse_bind(&got_b, &a.node_id(), &peer_a_pk, sess_b.session_id()).unwrap();
        parse_bind(&got_a, &b.node_id(), &peer_b_pk, sess_a.session_id()).unwrap();

        // Session data both ways
        let ct = sess_a.send(b"inner-data");
        assert_eq!(sess_b.recv(&ct).unwrap(), b"inner-data");

        // Negative: a swapped session_id in BIND (simulating a MITM split) => rejected
        let bad_sig = sign_binding(&a, &gm_a.pk, &[9u8; 32]);
        let mut bad = Vec::new();
        bad.extend_from_slice(BIND_PREFIX);
        bad.extend_from_slice(a.node_id().as_bytes());
        bad.extend_from_slice(&bad_sig);
        assert!(parse_bind(&bad, &a.node_id(), &peer_a_pk, sess_b.session_id()).is_err());
        // Negative: mismatched NodeId in BIND => rejected
        let evil_bind = build_bind(&b, &gm_b.pk, sess_b.session_id());
        assert!(parse_bind(&evil_bind, &a.node_id(), &peer_b_pk, sess_b.session_id()).is_err());
    }
}
