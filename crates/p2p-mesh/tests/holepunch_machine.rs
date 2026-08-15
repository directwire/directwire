//! Hole-punch state-machine transition tests (pure logic, no IO) + loopback UDP-driven integration tests

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::holepunch::{
    decode_punch_packet, drive, encode_punch_packet, PunchAction, PunchEvent, PunchMachine,
    PunchState,
};
use p2p_mesh::identity::NodeIdentity;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn state_happy_path() {
    let mut m = PunchMachine::new(5);
    assert_eq!(m.state(), &PunchState::Idle);

    // Begin punching -> wait for candidate addresses
    assert!(m.handle(PunchEvent::Begin).is_empty());
    assert_eq!(m.state(), &PunchState::WaitCandidates);

    // relay brokered candidates -> immediately simultaneous-open
    let acts = m.handle(PunchEvent::Candidates(vec![addr(1001), addr(1002)]));
    assert_eq!(m.state(), &PunchState::Punching);
    assert_eq!(
        acts,
        vec![
            PunchAction::SendPunch(addr(1001)),
            PunchAction::SendPunch(addr(1002))
        ]
    );

    // PUNCH packet from the peer -> direct established
    let acts = m.handle(PunchEvent::PacketFrom(addr(1002)));
    assert_eq!(m.state(), &PunchState::Direct(addr(1002)));
    assert_eq!(acts, vec![PunchAction::Established(addr(1002))]);

    // events after the terminal state are ignored
    assert!(m.handle(PunchEvent::Tick).is_empty());
    assert!(m.handle(PunchEvent::Candidates(vec![addr(9)])).is_empty());
}

#[test]
fn state_timeout_fallback() {
    let mut m = PunchMachine::new(3);
    m.handle(PunchEvent::Begin);
    m.handle(PunchEvent::Candidates(vec![addr(1001)]));
    // 2 retransmissions, the 3rd Tick triggers the timeout
    assert_eq!(
        m.handle(PunchEvent::Tick),
        vec![PunchAction::SendPunch(addr(1001))]
    );
    assert_eq!(
        m.handle(PunchEvent::Tick),
        vec![PunchAction::SendPunch(addr(1001))]
    );
    assert_eq!(m.handle(PunchEvent::Tick), vec![PunchAction::FallbackToRelay]);
    assert_eq!(m.state(), &PunchState::Failed);
    // Failed terminal state: subsequent events ignored
    assert!(m.handle(PunchEvent::PacketFrom(addr(1001))).is_empty());
}

#[test]
fn punch_packet_codec() {
    let id = NodeIdentity::generate().node_id();
    let p = encode_punch_packet(&id);
    assert_eq!(decode_punch_packet(&p), Some(id));
    assert_eq!(decode_punch_packet(b"PMP2...................."), None);
    assert_eq!(decode_punch_packet(b"short"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_punch_establishes_direct() {
    // both sides simultaneous-open on loopback: both directions must punch through
    let ida = NodeIdentity::generate().node_id();
    let idb = NodeIdentity::generate().node_id();
    let sa = tokio::net::UdpSocket::bind(addr(0)).await.unwrap();
    let sb = tokio::net::UdpSocket::bind(addr(0)).await.unwrap();
    let a_local = sa.local_addr().unwrap();
    let b_local = sb.local_addr().unwrap();

    let (ra, rb) = tokio::join!(
        drive(&sa, &ida, &idb, vec![b_local], Duration::from_millis(50), 40),
        drive(&sb, &idb, &ida, vec![a_local], Duration::from_millis(50), 40),
    );
    // each side's observed peer address should equal the other's local address (no translation on loopback)
    assert_eq!(ra.unwrap(), Some(b_local));
    assert_eq!(rb.unwrap(), Some(a_local));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_punch_timeout_fallback() {
    // the peer's candidate address is unreachable (unbound port) => timeout fallback
    let ida = NodeIdentity::generate().node_id();
    let idb = NodeIdentity::generate().node_id();
    let sa = tokio::net::UdpSocket::bind(addr(0)).await.unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        drive(&sa, &ida, &idb, vec![addr(1)], Duration::from_millis(30), 5),
    )
    .await
    .expect("driver must not hang")
    .unwrap();
    assert_eq!(r, None);
}
