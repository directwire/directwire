//! Integration-API smoke tests: the downstream contract (a bidirectional byte stream -> encrypted session).
//!
//! Scenario: full handshake (cookie challenge) -> encrypted echo -> ticket resumption (0-RTT early data)
//!       -> replaying the same ticket (server cache intercepts; the client auto-falls-back to a full handshake).

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use gm_pq_stack::api::{
    ServerConfig, client_connect_full, client_connect_resume, server_accept,
};
use gm_pq_stack::handshake::cookie::CookieIssuer;
use gm_pq_stack::handshake::psk::{TicketCache, TicketIssuer};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;
use gm_pq_stack::trust::PinFileAnchor;

struct ServerReport {
    resumed: bool,
    early_data: Option<Vec<u8>>,
    session_id: [u8; 32],
    peer_static: Vec<u8>,
}

fn dial(addr: std::net::SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s
}

#[test]
fn api_end_to_end_full_resume_replay() {
    let mut r = SysRng::new();
    let (server_sk, server_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let (client_sk, client_pk) = DefaultHybrid::keypair(&mut r).unwrap();
    let client_anchor = PinFileAnchor::from_keys([("server", &server_pk[..])]);
    let server_anchor = PinFileAnchor::from_keys([("client", &client_pk[..])]);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_pk_for_thread = server_pk.clone();

    // Server: one thread accepts 3 connections in order (full / resume / replay-fallback)
    let server = std::thread::spawn(move || {
        let cookie = CookieIssuer::new(30);
        let tickets = TicketIssuer::new();
        let mut cache = TicketCache::new();
        let mut reports = Vec::new();
        for _ in 0..3 {
            let (s, peer) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            let tag = peer.to_string().into_bytes();
            let mut cfg = ServerConfig {
                cookie: &cookie,
                tickets: &tickets,
                cache: &mut cache,
                anchor: &server_anchor,
                client_tag: &tag,
                ticket_ttl_secs: 3600,
            };
            let out = server_accept(s, server_sk.clone(), server_pk_for_thread.clone(), &mut cfg).unwrap();
            let report = ServerReport {
                resumed: out.resumed,
                early_data: out.early_data,
                session_id: *out.channel.session_id(),
                peer_static: out.channel.peer_static_key().to_vec(),
            };
            // Echo one message and finish
            let mut ch = out.channel;
            let m = ch.recv_msg().unwrap();
            ch.send_msg(&m).unwrap();
            reports.push(report);
        }
        reports
    });

    // ── connection 1: full handshake (cookie challenge) ──
    let out1 = client_connect_full(
        dial(addr),
        client_sk.clone(),
        client_pk.clone(),
        &client_anchor,
    )
    .unwrap();
    assert!(!out1.resumed);
    let (ticket, psk) = out1.resumption.expect("the server must push a resumption ticket");
    let mut ch1 = out1.channel;
    assert_eq!(ch1.peer_static_key(), &server_pk[..], "peer public key from the client's perspective");
    ch1.send_msg(b"hello-1").unwrap();
    assert_eq!(ch1.recv_msg().unwrap(), b"hello-1");
    let sid1 = *ch1.session_id();

    // ── connection 2: ticket resumption + 0-RTT early data ──
    let out2 = client_connect_resume(
        dial(addr),
        client_sk.clone(),
        client_pk.clone(),
        &client_anchor,
        &ticket,
        &psk,
        Some(b"IDEMPOTENT-OP"),
    )
    .unwrap();
    assert!(out2.resumed, "connection 2 must take the resumption path");
    assert!(out2.early_data_accepted, "early data must be accepted");
    let mut ch2 = out2.channel;
    ch2.send_msg(b"hello-2").unwrap();
    assert_eq!(ch2.recv_msg().unwrap(), b"hello-2");

    // ── connection 3: replaying the same ticket => server intercepts => auto-fallback to a full handshake ──
    let out3 = client_connect_resume(
        dial(addr),
        client_sk,
        client_pk.clone(),
        &client_anchor,
        &ticket,
        &psk,
        Some(b"REPLAYED-OP"),
    )
    .unwrap();
    assert!(!out3.resumed, "a replayed ticket must be rejected and fall back to a full handshake");
    assert!(!out3.early_data_accepted);
    let mut ch3 = out3.channel;
    ch3.send_msg(b"hello-3").unwrap();
    assert_eq!(ch3.recv_msg().unwrap(), b"hello-3");

    let reports = server.join().unwrap();
    assert!(!reports[0].resumed);
    assert!(reports[1].resumed, "from the server's perspective, connection 2 is a resumed session");
    assert_eq!(
        reports[1].early_data.as_deref(),
        Some(b"IDEMPOTENT-OP".as_slice()),
        "the server must receive the 0-RTT early data"
    );
    assert!(!reports[2].resumed, "a replayed ticket must not resume successfully");
    assert_eq!(reports[2].early_data, None, "replayed early data must not be delivered");

    // Session ids are consistent, mutually distinct, and the peer public keys are correct
    assert_eq!(reports[0].session_id, sid1);
    assert_ne!(reports[0].session_id, reports[1].session_id);
    assert_ne!(reports[1].session_id, reports[2].session_id);
    for rp in &reports {
        assert_eq!(rp.peer_static, client_pk, "peer public key from the server's perspective");
    }
}
