//! Trust-anchor tests: pin-file parsing + handshake integration (correct pin passes / wrong pin rejects).

use gm_pq_stack::crypto::sm3;
use gm_pq_stack::handshake::{Initiator, Responder};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;
use gm_pq_stack::trust::{AllowAllAnchor, PinFileAnchor, Role, TrustAnchor};

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn pin_file_parse_and_verify() {
    let fp1 = sm3(&[b"server-key-01"]);
    let fp2 = sm3(&[b"client-key-07"]);
    let text = format!(
        "# test pin file\n\
         gateway-01  {}\n\
         \n\
         client-07   {}   # extra tokens after the fingerprint are ignored\n",
        hex32(&fp1),
        hex32(&fp2)
    );
    let anchor = PinFileAnchor::parse(&text).unwrap();
    anchor.verify(Role::Responder, b"server-key-01").unwrap();
    anchor.verify(Role::Initiator, b"client-key-07").unwrap();
    assert!(anchor.verify(Role::Responder, b"evil-key").is_err());
    assert_eq!(anchor.lookup(b"server-key-01"), Some("gateway-01"));
}

#[test]
fn pin_file_rejects_garbage() {
    assert!(PinFileAnchor::parse("").is_err(), "empty file rejected");
    assert!(PinFileAnchor::parse("# comments only\n").is_err());
    assert!(
        PinFileAnchor::parse("name-only\n").is_err(),
        "missing fingerprint rejected"
    );
    assert!(
        PinFileAnchor::parse("n abc123\n").is_err(),
        "invalid hex rejected"
    );
    let fp = hex32(&sm3(&[b"k"]));
    assert!(
        PinFileAnchor::parse(&format!("a {fp}\nb {fp}\n")).is_err(),
        "duplicate fingerprint rejected"
    );
}

#[test]
fn pin_file_from_disk() {
    // Write to a temp directory and load back (never touches system dirs)
    let dir = std::env::temp_dir().join(format!("gm-pq-pin-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pins.txt");
    let fp = hex32(&sm3(&[b"disk-key"]));
    std::fs::write(&path, format!("disk-01 {fp}\n")).unwrap();
    let anchor = PinFileAnchor::from_file(&path).unwrap();
    anchor.verify(Role::Responder, b"disk-key").unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

/// End-to-end: a correct pin lets the handshake through; a wrong pin aborts it
#[test]
fn handshake_with_pin_anchor() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (r_sk, r_pk) = DefaultHybrid::keypair(&mut r).unwrap();

    // Each side pins the other's public key
    let client_anchor = PinFileAnchor::from_keys([("server", &r_pk[..])]);
    let server_anchor = PinFileAnchor::from_keys([("client", &i_pk[..])]);

    let mut init = Initiator::<DefaultHybrid>::new(i_sk, i_pk);
    let mut resp = Responder::<DefaultHybrid>::new(r_sk, r_pk);
    let m1 = init.write_msg1(&mut r).unwrap();
    resp.read_msg1(&m1).unwrap();
    let m2 = resp.write_msg2(&mut r).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, s_i) = init.write_msg3_with_auth(&mut r, &client_anchor).unwrap();
    let (s_r, _) = resp.read_msg3_with_auth(&m3, &server_anchor).unwrap();
    assert_eq!(s_i.session_id(), s_r.session_id());
}

#[test]
fn handshake_rejected_by_wrong_pin() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (r_sk, r_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (_evil_sk, evil_pk) = DefaultHybrid::keypair(&mut r).unwrap();

    // The client pins a different public key => the server's real key is not trusted
    let client_anchor = PinFileAnchor::from_keys([("someone-else", &evil_pk[..])]);

    let mut init = Initiator::<DefaultHybrid>::new(i_sk, i_pk);
    let mut resp = Responder::<DefaultHybrid>::new(r_sk, r_pk);
    let m1 = init.write_msg1(&mut r).unwrap();
    resp.read_msg1(&m1).unwrap();
    let m2 = resp.write_msg2(&mut r).unwrap();
    init.read_msg2(&m2).unwrap();
    let err = match init.write_msg3_with_auth(&mut r, &client_anchor) {
        Ok(_) => panic!("wrong pin must abort the handshake"),
        Err(e) => e,
    };
    assert!(
        format!("{err}").contains("identity"),
        "should be a peer identity verification failure: {err}"
    );
}

/// AllowAllAnchor explicitly allows everything (tests only)
#[test]
fn allow_all_anchor_accepts() {
    AllowAllAnchor.verify(Role::Initiator, b"anything").unwrap();
}
