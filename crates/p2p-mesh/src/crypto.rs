//! End-to-end encryption for the relay path: the relay only ever sees ciphertext and public handshake material.
//!
//! Session establishment (Noise IK semantics, forward secrecy):
//! - Each side generates a **fresh ephemeral X25519 keypair** (new per session); the ephemeral public key is
//!   signed by the long-term ed25519 identity key.
//! - initiator -> responder: `[HS, 0x01] | eph_pub_i | sig_i`
//!   sig_i = Sign_i("hs-init"  || eph_pub_i || id_i || id_r)
//! - responder -> initiator: `[HS, 0x02] | eph_pub_r | sig_r`
//!   sig_r = Sign_r("hs-resp"  || eph_pub_r || id_r || id_i)
//! - shared = X25519(eph, eph'); bidirectional keys:
//!   k_i2r = SHA256(domain || shared || "i2r" || id_i || id_r), and k_r2i symmetrically.
//!
//! The signature binds the ephemeral public key to both NodeIds (including the peer's id, which
//! prevents cross-session replay / unknown-key-sharing). Known debts: the ephemeral private key is
//! not zeroized (declared in the README); handshake messages are plaintext (public keys + signatures,
//! no confidentiality needed).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};

use crate::identity::{verify, NodeId, NodeIdentity};

/// First byte of a relay payload: plaintext handshake-message marker (all other payloads are AEAD ciphertext)
pub const HS_TAG: u8 = 0x48; // 'H'
pub const HS_KIND_INIT: u8 = 0x01;
pub const HS_KIND_RESP: u8 = 0x02;

const HS_MSG_LEN: usize = 2 + 32 + 64; // tag+kind | ephemeral public key | signature

/// Bidirectional session cipher (AEAD: ChaCha20-Poly1305; nonce is a monotonic counter carried over an ordered TCP channel)
pub struct SessionCipher {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_ctr: u64,
    recv_ctr: u64,
}

/// In-progress handshake state on our side as initiator
pub struct HsState {
    eph: x25519_dalek::StaticSecret,
    peer: NodeId,
}

#[derive(Debug)]
pub struct CryptoError(pub &'static str);

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto: {}", self.0)
    }
}
impl std::error::Error for CryptoError {}

fn sign_ctx(tag: &[u8], eph_pub: &[u8; 32], from: &NodeId, to: &NodeId) -> Vec<u8> {
    let mut m = Vec::with_capacity(tag.len() + 96);
    m.extend_from_slice(tag);
    m.extend_from_slice(eph_pub);
    m.extend_from_slice(from.as_bytes());
    m.extend_from_slice(to.as_bytes());
    m
}

fn parse_hs_msg(msg: &[u8], kind: u8) -> Result<([u8; 32], [u8; 64]), CryptoError> {
    if msg.len() != HS_MSG_LEN || msg[0] != HS_TAG || msg[1] != kind {
        return Err(CryptoError("malformed handshake message"));
    }
    let eph_pub: [u8; 32] = msg[2..34].try_into().unwrap();
    let sig: [u8; 64] = msg[34..98].try_into().unwrap();
    Ok((eph_pub, sig))
}

fn new_eph() -> (x25519_dalek::StaticSecret, [u8; 32]) {
    let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
    (sk, pk)
}

/// Begin a handshake: returns (state, the plaintext handshake message to send to the peer)
pub fn hs_start(me: &NodeIdentity, peer: &NodeId) -> (HsState, Vec<u8>) {
    let (eph, eph_pub) = new_eph();
    let my_id = me.node_id();
    let sig = me.sign(&sign_ctx(b"p2p-mesh/hs-init", &eph_pub, &my_id, peer));
    let mut msg = Vec::with_capacity(HS_MSG_LEN);
    msg.extend_from_slice(&[HS_TAG, HS_KIND_INIT]);
    msg.extend_from_slice(&eph_pub);
    msg.extend_from_slice(&sig);
    (HsState { eph, peer: *peer }, msg)
}

/// Responder handles init: verify signature -> generate our ephemeral keypair -> derive the session -> return (session, response message)
pub fn hs_accept(
    me: &NodeIdentity,
    peer: &NodeId,
    msg: &[u8],
) -> Result<(SessionCipher, Vec<u8>), CryptoError> {
    let (peer_pub, sig) = parse_hs_msg(msg, HS_KIND_INIT)?;
    if !verify(peer, &sign_ctx(b"p2p-mesh/hs-init", &peer_pub, peer, &me.node_id()), &sig) {
        return Err(CryptoError("hs-init signature verification failed (wrong identity or tampered)"));
    }
    let (eph, eph_pub) = new_eph();
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer_pub));
    // Responder view: send with k_r2i, receive with k_i2r
    let cipher = derive(shared.as_bytes(), peer, &me.node_id(), Role::Responder);
    let sig_r = me.sign(&sign_ctx(b"p2p-mesh/hs-resp", &eph_pub, &me.node_id(), peer));
    let mut resp = Vec::with_capacity(HS_MSG_LEN);
    resp.extend_from_slice(&[HS_TAG, HS_KIND_RESP]);
    resp.extend_from_slice(&eph_pub);
    resp.extend_from_slice(&sig_r);
    // Note: eph is already used for DH; dropped here (known debt: not zeroized)
    Ok((cipher, resp))
}

/// Initiator handles resp: verify signature -> derive the session
pub fn hs_finish(me: &NodeIdentity, hs: HsState, msg: &[u8]) -> Result<SessionCipher, CryptoError> {
    let (peer_pub, sig) = parse_hs_msg(msg, HS_KIND_RESP)?;
    if !verify(&hs.peer, &sign_ctx(b"p2p-mesh/hs-resp", &peer_pub, &hs.peer, &me.node_id()), &sig) {
        return Err(CryptoError("hs-resp signature verification failed (wrong identity or tampered)"));
    }
    let shared = hs.eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer_pub));
    // Initiator view: send with k_i2r, receive with k_r2i
    Ok(derive(shared.as_bytes(), &me.node_id(), &hs.peer, Role::Initiator))
}

enum Role {
    Initiator,
    Responder,
}

/// Derive the bidirectional session from the shared secret (both sides call this and get mirror-image results)
fn derive(shared: &[u8; 32], initiator: &NodeId, responder: &NodeId, role: Role) -> SessionCipher {
    let k_i2r = kdf(shared, b"i2r", initiator, responder);
    let k_r2i = kdf(shared, b"r2i", initiator, responder);
    let (send, recv) = match role {
        Role::Initiator => (k_i2r, k_r2i),
        Role::Responder => (k_r2i, k_i2r),
    };
    SessionCipher {
        send: ChaCha20Poly1305::new((&send).into()),
        recv: ChaCha20Poly1305::new((&recv).into()),
        send_ctr: 0,
        recv_ctr: 0,
    }
}

fn kdf(shared: &[u8; 32], dir: &[u8], i: &NodeId, r: &NodeId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"p2p-mesh/hs-v1");
    h.update(shared);
    h.update(dir);
    h.update(i.as_bytes());
    h.update(r.as_bytes());
    h.finalize().into()
}

fn nonce_bytes(ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

impl SessionCipher {
    /// Encrypt (plaintext -> ciphertext; the relay only ever sees this output)
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ct = self
            .send
            .encrypt(Nonce::from_slice(&nonce_bytes(self.send_ctr)), plaintext)
            .map_err(|_| CryptoError("AEAD encryption failed"))?;
        self.send_ctr += 1;
        Ok(ct)
    }

    /// Decrypt
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pt = self
            .recv
            .decrypt(Nonce::from_slice(&nonce_bytes(self.recv_ctr)), ciphertext)
            .map_err(|_| CryptoError("AEAD decryption failed (tampered or wrong peer identity)"))?;
        self.recv_ctr += 1;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip_and_forward_secrecy() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let (hs_a, init) = hs_start(&a, &b.node_id());
        let (mut sb, resp) = hs_accept(&b, &a.node_id(), &init).unwrap();
        let mut sa = hs_finish(&a, hs_a, &resp).unwrap();
        // Bidirectional traffic
        let c = sa.seal(b"forward secret").unwrap();
        assert_eq!(sb.open(&c).unwrap(), b"forward secret");
        let c2 = sb.seal(b"pong").unwrap();
        assert_eq!(sa.open(&c2).unwrap(), b"pong");

        // Second session (forward secrecy: a fresh ephemeral keypair per session)
        let (hs_a2, init2) = hs_start(&a, &b.node_id());
        let (mut sb2, resp2) = hs_accept(&b, &a.node_id(), &init2).unwrap();
        let mut sa2 = hs_finish(&a, hs_a2, &resp2).unwrap();
        // The new session works both ways (use it first, so the forward-secrecy check
        // below doesn't consume the nonce counter)
        let c3 = sa2.seal(b"y").unwrap();
        assert_eq!(sb2.open(&c3).unwrap(), b"y");
        let c4 = sb2.seal(b"z").unwrap();
        assert_eq!(sa2.open(&c4).unwrap(), b"z");
        // Forward-secrecy semantics: the next session's keys differ (counters synced on both
        // sides; same plaintext at the same nonce position yields different ciphertext
        // => different session keys)
        assert_ne!(sa2.seal(b"same").unwrap(), sa.seal(b"same").unwrap());
    }

    #[test]
    fn handshake_rejects_tamper_and_wrong_party() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let eve = NodeIdentity::generate();

        // Tamper with the ephemeral public key -> the signature breaks
        let (_hs, mut init) = hs_start(&a, &b.node_id());
        init[10] ^= 1;
        assert!(hs_accept(&b, &a.node_id(), &init).is_err());

        // Cross-party replay: an init destined for b cannot fool c
        let (_hs2, init_ab) = hs_start(&a, &b.node_id());
        assert!(hs_accept(&eve, &a.node_id(), &init_ab).is_err());

        // resp verifies its signature too
        let (hs_a, init3) = hs_start(&a, &b.node_id());
        let (_sb3, mut resp3) = hs_accept(&b, &a.node_id(), &init3).unwrap();
        resp3[40] ^= 1;
        assert!(hs_finish(&a, hs_a, &resp3).is_err());
    }

    #[test]
    fn ciphertext_tamper_rejected() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let (hs, init) = hs_start(&a, &b.node_id());
        let (mut sb, resp) = hs_accept(&b, &a.node_id(), &init).unwrap();
        let mut sa = hs_finish(&a, hs, &resp).unwrap();
        let mut bad = sa.seal(b"x").unwrap();
        bad[0] ^= 1;
        assert!(sb.open(&bad).is_err());
    }
}
