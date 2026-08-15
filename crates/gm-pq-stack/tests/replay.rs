//! Replay-protection tests: sliding-window semantics + end-to-end session replay rejection.

use gm_pq_stack::handshake::session::ReplayWindow;
use gm_pq_stack::handshake::{Initiator, Responder, Session};
use gm_pq_stack::kem::{Kem, Sm2Kem};
use gm_pq_stack::rng::SysRng;

#[test]
fn window_accepts_in_order() {
    let mut w = ReplayWindow::new();
    for seq in 0..100u64 {
        w.check_and_mark(seq).unwrap();
    }
}

#[test]
fn window_rejects_exact_replay() {
    let mut w = ReplayWindow::new();
    w.check_and_mark(7).unwrap();
    assert!(
        w.check_and_mark(7).is_err(),
        "exact replay must be rejected"
    );
}

#[test]
fn window_allows_reorder_within_window() {
    let mut w = ReplayWindow::new();
    w.check_and_mark(10).unwrap();
    // Reordering within the window is allowed
    w.check_and_mark(8).unwrap();
    w.check_and_mark(9).unwrap();
    // But the same sequence number cannot arrive twice
    assert!(w.check_and_mark(8).is_err());
}

#[test]
fn window_rejects_too_old() {
    let mut w = ReplayWindow::new();
    w.check_and_mark(0).unwrap();
    w.check_and_mark(1000).unwrap(); // window slides to 1000
    assert!(
        w.check_and_mark(0).is_err(),
        "old sequence slid out of the window must be rejected"
    );
    assert!(w.check_and_mark(999).is_ok(), "still inside the window");
}

#[test]
fn window_large_jump() {
    let mut w = ReplayWindow::new();
    w.check_and_mark(5).unwrap();
    // A jump wider than the window resets the bitmap; all old sequence numbers are void
    w.check_and_mark(10_000).unwrap();
    assert!(w.check_and_mark(5).is_err());
    assert!(w.check_and_mark(10_000).is_err());
}

/// End-to-end: replaying an already-received packet on a real session must be rejected
#[test]
fn session_rejects_replayed_packet() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = Sm2Kem::keypair(&mut r).unwrap();
    let (r_sk, r_pk) = Sm2Kem::keypair(&mut r).unwrap();

    let mut init = Initiator::<Sm2Kem>::new(i_sk, i_pk);
    let mut resp = Responder::<Sm2Kem>::new(r_sk, r_pk);
    let m1 = init.write_msg1(&mut r).unwrap();
    resp.read_msg1(&m1).unwrap();
    let m2 = resp.write_msg2(&mut r).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, mut s_i) = init.write_msg3(&mut r).unwrap();
    let mut s_r = resp.read_msg3(&m3).unwrap();

    let pkt = s_i.send(b"IMPORTANT-INSTRUCTION");
    // First delivery: accepted
    assert_eq!(s_r.recv(&pkt).unwrap(), b"IMPORTANT-INSTRUCTION");
    // Second delivery: replay => rejected (the instruction is not executed twice)
    assert!(s_r.recv(&pkt).is_err(), "replayed packet must be rejected");
}

/// Session-id consistency = handshake key confirmation (identical only if both transcripts match exactly)
#[test]
fn session_id_is_transcript_bound() {
    let mut r = SysRng::new();
    let (i_sk, i_pk) = Sm2Kem::keypair(&mut r).unwrap();
    let (r_sk, r_pk) = Sm2Kem::keypair(&mut r).unwrap();
    let mut init = Initiator::<Sm2Kem>::new(i_sk, i_pk);
    let mut resp = Responder::<Sm2Kem>::new(r_sk, r_pk);
    let m1 = init.write_msg1(&mut r).unwrap();
    resp.read_msg1(&m1).unwrap();
    let m2 = resp.write_msg2(&mut r).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, s_i) = init.write_msg3(&mut r).unwrap();
    let s_r: Session = resp.read_msg3(&m3).unwrap();
    assert_eq!(s_i.session_id(), s_r.session_id());

    // A different handshake => a different session id (ephemeral-key freshness)
    let (s_i2, s_r2) = {
        let mut r = SysRng::new();
        let (i_sk, i_pk) = Sm2Kem::keypair(&mut r).unwrap();
        let (r_sk, r_pk) = Sm2Kem::keypair(&mut r).unwrap();
        let mut init = Initiator::<Sm2Kem>::new(i_sk, i_pk);
        let mut resp = Responder::<Sm2Kem>::new(r_sk, r_pk);
        let m1 = init.write_msg1(&mut r).unwrap();
        resp.read_msg1(&m1).unwrap();
        let m2 = resp.write_msg2(&mut r).unwrap();
        init.read_msg2(&m2).unwrap();
        let (m3, s_i) = init.write_msg3(&mut r).unwrap();
        (s_i, resp.read_msg3(&m3).unwrap())
    };
    assert_ne!(s_i.session_id(), s_i2.session_id());
    assert_eq!(s_i2.session_id(), s_r2.session_id());
}
