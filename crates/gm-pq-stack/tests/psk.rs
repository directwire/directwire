//! PSK session-resumption (0-RTT) tests: ticket lifecycle + resumption handshake + replay interception.

use gm_pq_stack::handshake::psk::{TicketCache, TicketIssuer};
use gm_pq_stack::handshake::{Initiator, Responder};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;
use gm_pq_stack::trust::AllowAllAnchor;

/// Ticket issue/decrypt roundtrip + field correctness
#[test]
fn ticket_roundtrip() {
    let issuer = TicketIssuer::new();
    let client_pk = b"client-static-pk-bytes";
    let (ticket, psk) = issuer.issue(client_pk, 3600);
    let payload = issuer.open(&ticket).unwrap();
    assert_eq!(&*payload.psk, &*psk);
    assert_eq!(
        payload.client_pk_fingerprint,
        gm_pq_stack::crypto::sm3(&[client_pk])
    );
    assert!(payload.expires_at > 0);
}

/// Tampered ticket => AEAD authentication failure
#[test]
fn ticket_tamper_rejected() {
    let issuer = TicketIssuer::new();
    let (mut ticket, _) = issuer.issue(b"pk", 3600);
    ticket[20] ^= 0x01;
    assert!(issuer.open(&ticket).is_err());
}

/// A different ticket key => all old tickets are invalid (server-restart scenario)
#[test]
fn ticket_key_rotation_invalidates() {
    let i1 = TicketIssuer::new();
    let i2 = TicketIssuer::new();
    let (ticket, _) = i1.issue(b"pk", 3600);
    assert!(i2.open(&ticket).is_err());
}

/// One-time cache: the same ticket ID is a replay the second time
#[test]
fn ticket_cache_rejects_replay() {
    let mut cache = TicketCache::new();
    let id = [42u8; 16];
    let exp = u64::MAX; // never expires
    cache.check_and_insert(id, exp).unwrap();
    assert!(cache.check_and_insert(id, exp).is_err(), "replayed ticket must be intercepted");
    // A different ID is unaffected
    cache.check_and_insert([43u8; 16], exp).unwrap();
}

/// Full PSK resumption handshake: both sides derive matching sessions; 0-RTT early data arrives
#[test]
fn psk_resumption_handshake_with_early_data() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (r_sk, r_pk) = DefaultHybrid::keypair(&mut r).unwrap();

    // The server issues a ticket for the client (simulating after a previous full handshake)
    let issuer = TicketIssuer::new();
    let (ticket, psk) = issuer.issue(&i_pk, 3600);

    // ── resumption handshake ──
    let mut init = Initiator::<DefaultHybrid>::new_with_psk(i_sk, i_pk.clone(), &psk);
    let e_pk = init.write_msg1(&mut r).unwrap();
    let enc_early = init.seal_early_data(b"GET /idempotent").unwrap();

    // Server: open ticket + one-time check + read msg1 + decrypt early data
    let payload = issuer.open(&ticket).unwrap();
    let mut cache = TicketCache::new();
    cache
        .check_and_insert(payload.ticket_id, payload.expires_at)
        .unwrap();
    let mut resp = Responder::<DefaultHybrid>::new_with_psk(r_sk, r_pk, &payload.psk);
    resp.read_msg1(&e_pk).unwrap();
    let early = resp.open_early_data(&enc_early).unwrap();
    assert_eq!(early, b"GET /idempotent", "0-RTT early data must match");

    let m2 = resp.write_msg2(&mut r).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, mut s_i) = init
        .write_msg3_with_auth(&mut r, &AllowAllAnchor)
        .unwrap();
    let (mut s_r, authed_pk) = resp.read_msg3_with_auth(&m3, &AllowAllAnchor).unwrap();

    assert_eq!(authed_pk, i_pk);
    assert_eq!(s_i.session_id(), s_r.session_id());

    // A resumed session can communicate normally
    let pkt = s_i.send(b"resumed hello");
    assert_eq!(s_r.recv(&pkt).unwrap(), b"resumed hello");

    // Using the same ticket again => intercepted by the cache (0-RTT replay protection)
    assert!(cache
        .check_and_insert(payload.ticket_id, payload.expires_at)
        .is_err());
}

/// PSK mismatch => the two sides' keys diverge => AEAD failure (wrong-ticket / forgery scenario)
#[test]
fn psk_mismatch_fails() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (r_sk, r_pk) = DefaultHybrid::keypair(&mut r).unwrap();

    let psk_a = [1u8; 32];
    let psk_b = [2u8; 32]; // the server holds a different PSK

    let mut init = Initiator::<DefaultHybrid>::new_with_psk(i_sk, i_pk, &psk_a);
    let mut resp = Responder::<DefaultHybrid>::new_with_psk(r_sk, r_pk, &psk_b);

    let m1 = init.write_msg1(&mut r).unwrap();
    resp.read_msg1(&m1).unwrap();
    let m2 = resp.write_msg2(&mut r).unwrap();
    init.read_msg2(&m2).unwrap();
    // Different PSKs => different ck => AEAD(s_r) decryption authentication fails
    assert!(init
        .write_msg3_with_auth(&mut r, &AllowAllAnchor)
        .is_err());
}

/// Calling the early-data interface outside PSK mode => the state machine rejects it
#[test]
fn early_data_requires_psk_mode_ordering() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let init = Initiator::<DefaultHybrid>::new(i_sk, i_pk);
    // Encrypting early data before writing msg1 => error
    assert!(init.seal_early_data(b"x").is_err());
}
