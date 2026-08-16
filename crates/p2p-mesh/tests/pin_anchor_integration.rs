//! PinFileAnchor integration: the GM-PQ handshake enforces a configured pin file —
//! TOFU (AllowAll) upgraded to explicit SM2 public-key pinning.
//!
//! Mirrors `gm-pq-stack/tests/trust_anchor.rs` at the p2p-mesh wiring level: full
//! cookie-challenge -> msg2 -> msg3 handshake through `GmInitiator`/`GmResponder`,
//! plus the BIND identity-binding round trip.
//!
//! Only compiled under `--features gm-pq` (the handshake machinery is feature-gated).

#![cfg(feature = "gm-pq")]

use p2p_mesh::gmpq::{
    build_bind, new_cookie_issuer, new_rng, parse_bind, pin_fingerprint, GmIdentity, GmInitiator,
    GmResponder, PinFileAnchor, Session, COOKIE_LEN,
};
use p2p_mesh::identity::NodeIdentity;

/// Drive the full interactive handshake with the given anchors on each side.
/// Returns `(sess_a, peer_b_gm_pk, sess_b, peer_a_gm_pk)`.
fn run_handshake(
    a: &NodeIdentity,
    gm_a: &GmIdentity,
    gm_b: &GmIdentity,
    anchor_a: &PinFileAnchor,
    anchor_b: &PinFileAnchor,
) -> (Session, Vec<u8>, Session, Vec<u8>) {
    let cookie = new_cookie_issuer();
    let mut rng = new_rng();
    let mut init = GmInitiator::new(gm_a.sk.clone(), gm_a.pk.clone());
    let e_pk = init.write_msg1(&mut rng).expect("write msg1");
    // Cookie challenge -> retry
    let ck = cookie.issue(a.node_id().as_bytes(), &e_pk);
    let mut retry = ck.clone();
    retry.extend_from_slice(&e_pk);
    let (echo, e_pk2) = retry.split_at(COOKIE_LEN);
    cookie.verify(a.node_id().as_bytes(), e_pk2, echo).expect("cookie verify");
    let mut resp = GmResponder::new(gm_b.sk.clone(), gm_b.pk.clone());
    resp.read_msg1(e_pk2).expect("read msg1");
    let m2 = resp.write_msg2(&mut rng).expect("write msg2");
    init.read_msg2(&m2).expect("read msg2");
    // Client side verifies the responder's SM2 key against anchor_a
    let (m3, sess_a) = init
        .write_msg3_with_auth(&mut rng, anchor_a)
        .expect("write msg3 (A pins B's SM2 key)");
    let peer_b_pk = init.peer_static().expect("responder static key").to_vec();
    // Server side verifies the initiator's SM2 key against anchor_b
    let (sess_b, peer_a_pk) = resp
        .read_msg3_with_auth(&m3, anchor_b)
        .expect("read msg3 (B pins A's SM2 key)");
    (sess_a, peer_b_pk, sess_b, peer_a_pk)
}

/// Both sides pin each other's SM2 public key: the handshake succeeds and BIND binds
/// the ed25519 NodeId to the SM2 key (splicing MITM defense kept intact).
#[test]
fn mutual_pin_handshake_and_bind() {
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();
    let gm_a = GmIdentity::generate().unwrap();
    let gm_b = GmIdentity::generate().unwrap();
    let anchor_a = PinFileAnchor::from_keys([("peer-b", gm_b.pk.as_slice())]);
    let anchor_b = PinFileAnchor::from_keys([("peer-a", gm_a.pk.as_slice())]);

    let (mut sess_a, peer_b_pk, mut sess_b, peer_a_pk) =
        run_handshake(&a, &gm_a, &gm_b, &anchor_a, &anchor_b);

    // BIND both ways inside the encrypted session
    let bind_a = build_bind(&a, &gm_a.pk, sess_a.session_id());
    let bind_b = build_bind(&b, &gm_b.pk, sess_b.session_id());
    let got_b = sess_b.recv(&sess_a.send(&bind_a)).unwrap();
    let got_a = sess_a.recv(&sess_b.send(&bind_b)).unwrap();
    parse_bind(&got_b, &a.node_id(), &peer_a_pk, sess_b.session_id()).unwrap();
    parse_bind(&got_a, &b.node_id(), &peer_b_pk, sess_a.session_id()).unwrap();

    // Session data flows
    let ct = sess_a.send(b"pinned-data");
    assert_eq!(sess_b.recv(&ct).unwrap(), b"pinned-data");
}

/// Negative: the initiator pins the WRONG key -> write_msg3_with_auth rejects the
/// responder's SM2 key with a peer-auth error (handshake aborts).
#[test]
fn initiator_rejects_unpinned_responder() {
    let a = NodeIdentity::generate();
    let gm_a = GmIdentity::generate().unwrap();
    let gm_b = GmIdentity::generate().unwrap();
    let evil = GmIdentity::generate().unwrap();
    // A pinned a key that is NOT B's -> handshake must fail at the anchor check
    let anchor_a = PinFileAnchor::from_keys([("impostor", evil.pk.as_slice())]);

    let cookie = new_cookie_issuer();
    let mut rng = new_rng();
    let mut init = GmInitiator::new(gm_a.sk.clone(), gm_a.pk.clone());
    let e_pk = init.write_msg1(&mut rng).unwrap();
    let ck = cookie.issue(a.node_id().as_bytes(), &e_pk);
    let mut retry = ck.clone();
    retry.extend_from_slice(&e_pk);
    let (echo, e_pk2) = retry.split_at(COOKIE_LEN);
    cookie.verify(a.node_id().as_bytes(), e_pk2, echo).unwrap();
    let mut resp = GmResponder::new(gm_b.sk.clone(), gm_b.pk.clone());
    resp.read_msg1(e_pk2).unwrap();
    let m2 = resp.write_msg2(&mut rng).unwrap();
    init.read_msg2(&m2).unwrap();
    // B's SM2 key is not pinned -> PeerAuth -> write_msg3_with_auth errors
    assert!(init.write_msg3_with_auth(&mut rng, &anchor_a).is_err());
}

/// Negative: the responder pins the WRONG key -> read_msg3_with_auth rejects the
/// initiator's SM2 key with a peer-auth error.
#[test]
fn responder_rejects_unpinned_initiator() {
    let a = NodeIdentity::generate();
    let gm_a = GmIdentity::generate().unwrap();
    let gm_b = GmIdentity::generate().unwrap();
    let evil = GmIdentity::generate().unwrap();
    // B pinned a key that is NOT A's
    let anchor_a = PinFileAnchor::from_keys([("peer-b", gm_b.pk.as_slice())]);
    let anchor_b = PinFileAnchor::from_keys([("impostor", evil.pk.as_slice())]);

    let cookie = new_cookie_issuer();
    let mut rng = new_rng();
    let mut init = GmInitiator::new(gm_a.sk.clone(), gm_a.pk.clone());
    let e_pk = init.write_msg1(&mut rng).unwrap();
    let ck = cookie.issue(a.node_id().as_bytes(), &e_pk);
    let mut retry = ck.clone();
    retry.extend_from_slice(&e_pk);
    let (echo, e_pk2) = retry.split_at(COOKIE_LEN);
    cookie.verify(a.node_id().as_bytes(), e_pk2, echo).unwrap();
    let mut resp = GmResponder::new(gm_b.sk.clone(), gm_b.pk.clone());
    resp.read_msg1(e_pk2).unwrap();
    let m2 = resp.write_msg2(&mut rng).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, _sess_a) = init.write_msg3_with_auth(&mut rng, &anchor_a).unwrap();
    // A's SM2 key is not pinned -> PeerAuth -> read_msg3_with_auth errors
    assert!(resp.read_msg3_with_auth(&m3, &anchor_b).is_err());
}

/// Ops workflow: `pin_fingerprint` produces the 64-hex value for a pin-file line, and a
/// pin file parsed from that hex string accepts exactly the key it names.
#[test]
fn pin_fingerprint_roundtrips_through_parse() {
    let gm_a = GmIdentity::generate().unwrap();
    let gm_b = GmIdentity::generate().unwrap();

    let fp = pin_fingerprint(&gm_a.pk);
    assert_eq!(fp.len(), 64, "SM3 fingerprint must be 64 hex chars");

    let anchor = PinFileAnchor::parse(&format!("gateway-01 {fp}\n")).unwrap();
    assert!(anchor.lookup(&gm_a.pk).is_some(), "pinned key must resolve");
    assert!(anchor.lookup(&gm_b.pk).is_none(), "unpinned key must not resolve");
}
