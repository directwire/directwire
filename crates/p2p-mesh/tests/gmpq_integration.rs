//! GM-PQ channel integration tests (feature = "gm-pq"):
//! 1. relay fallback: the GM-PQ hybrid handshake establishes a session, messages reach via the relay
//! 2. when the peer lacks GM-PQ support, a timeout falls back to X25519
//! 3. punch upgrade to direct still works (Relay -> Direct switch)

#![cfg(feature = "gm-pq")]

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::node::{Node, NodeConfig, NodeEvent};
use p2p_mesh::path::PathKind;
use p2p_mesh::relay::RelayServer;
use p2p_mesh::NodeIdentity;

// Generous budget: the GM-PQ fallback has a fixed 3s handshake timeout, and
// these tests run under heavy parallel load in CI (oversubscribed runners make
// timer jitter much worse than on a dev machine).
const T: Duration = Duration::from_secs(30);

async fn spawn_relay() -> SocketAddr {
    let server = RelayServer::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        server.serve().await.unwrap();
    });
    addr
}

async fn wait_event(n: &mut Node, pred: impl Fn(&NodeEvent) -> bool, what: &str) -> NodeEvent {
    tokio::time::timeout(T, async {
        loop {
            match n.next_event().await {
                Some(ev) if pred(&ev) => return ev,
                Some(_) => continue,
                None => panic!("event channel closed while waiting for {what}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// relay fallback + GM-PQ hybrid handshake: both sides establish a sm2+ml-kem-768+sm4-gcm session and can send/receive
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gmpq_relay_fallback() {
    let relay_addr = spawn_relay().await;
    let ia = NodeIdentity::from_seed([11u8; 32]);
    let ib = NodeIdentity::from_seed([12u8; 32]);
    let idb = ib.node_id();

    let mut cfg_a = NodeConfig::new(relay_addr);
    cfg_a.enable_punch = false;
    cfg_a.gmpq = true;
    let mut cfg_b = NodeConfig::new(relay_addr);
    cfg_b.enable_punch = false;
    cfg_b.gmpq = true;

    let mut a = Node::start(ia, cfg_a).await.unwrap();
    let mut b = Node::start(ib, cfg_b).await.unwrap();

    a.connect_peer(idb).await;
    a.send_to(idb, b"gmpq-relay-hello".to_vec()).await;

    // b: first the GM-PQ session-ready event, then the relay message (aggregate wait)
    tokio::time::timeout(T, async {
        let (mut got_ready, mut got_msg) = (false, false);
        while !(got_ready && got_msg) {
            match b.next_event().await {
                Some(NodeEvent::SessionReady { suite, .. }) => {
                    assert_eq!(suite, "sm2+ml-kem-768+sm4-gcm");
                    got_ready = true;
                }
                Some(NodeEvent::Message { via, payload, from }) if !got_msg => {
                    assert_eq!(via, PathKind::Relay);
                    assert_eq!(payload, b"gmpq-relay-hello");
                    assert_eq!(from, a.node_id());
                    got_msg = true;
                }
                Some(_) => {}
                None => panic!("b event channel closed"),
            }
        }
    })
    .await
    .expect("b-side: GM-PQ session ready + relay message");

    // a: should also see the GM-PQ session ready
    wait_event(
        &mut a,
        |e| {
            matches!(
                e,
                NodeEvent::SessionReady {
                    suite: "sm2+ml-kem-768+sm4-gcm",
                    ..
                }
            )
        },
        "a-side GM-PQ session ready",
    )
    .await;

    // reverse send also goes through the GM-PQ channel
    b.send_to(a.node_id(), b"gmpq-reply".to_vec()).await;
    wait_event(
        &mut a,
        |e| matches!(e, NodeEvent::Message { .. }),
        "a receives reply",
    )
    .await;
}

/// peer has GM-PQ off: after the 3s timeout, fall back to X25519+ed25519; messages still reach
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gmpq_fallback_to_x25519() {
    let relay_addr = spawn_relay().await;
    let ia = NodeIdentity::from_seed([13u8; 32]);
    let ib = NodeIdentity::from_seed([14u8; 32]);
    let idb = ib.node_id();

    let mut cfg_a = NodeConfig::new(relay_addr);
    cfg_a.enable_punch = false;
    cfg_a.gmpq = true; // only a enables GM-PQ
    let mut cfg_b = NodeConfig::new(relay_addr);
    cfg_b.enable_punch = false;

    let mut a = Node::start(ia, cfg_a).await.unwrap();
    let mut b = Node::start(ib, cfg_b).await.unwrap();

    a.connect_peer(idb).await;
    a.send_to(idb, b"fallback works".to_vec()).await;

    // b receives the message via the X25519 session
    match wait_event(
        &mut b,
        |e| matches!(e, NodeEvent::Message { .. }),
        "b receives message",
    )
    .await
    {
        NodeEvent::Message { payload, .. } => assert_eq!(payload, b"fallback works"),
        _ => unreachable!(),
    }
    // a eventually establishes the X25519 session (GM-PQ timed out and fell back)
    wait_event(
        &mut a,
        |e| {
            matches!(
                e,
                NodeEvent::SessionReady {
                    suite: "x25519+ed25519",
                    ..
                }
            )
        },
        "a falls back to the X25519 session",
    )
    .await;
}

/// punch upgrade: the GM-PQ session is established over the relay; after punching succeeds the path still switches to direct
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gmpq_punch_then_upgrade_to_direct() {
    let relay_addr = spawn_relay().await;
    let ia = NodeIdentity::from_seed([15u8; 32]);
    let ib = NodeIdentity::from_seed([16u8; 32]);
    let ida = ia.node_id();
    let idb = ib.node_id();

    let mut cfg_a = NodeConfig::new(relay_addr);
    cfg_a.probe_interval = Duration::from_millis(300);
    cfg_a.gmpq = true;
    let mut cfg_b = NodeConfig::new(relay_addr);
    cfg_b.probe_interval = Duration::from_millis(300);
    cfg_b.gmpq = true;

    let mut a = Node::start(ia, cfg_a).await.unwrap();
    let mut b = Node::start(ib, cfg_b).await.unwrap();

    a.connect_peer(idb).await;
    a.send_to(idb, b"gmpq-msg-1-via-relay".to_vec()).await;

    // b-side aggregate wait: first relay message + punch success + direct ready
    tokio::time::timeout(T, async {
        let (mut got_msg, mut got_punch, mut got_direct) = (false, false, false);
        while !(got_msg && got_punch && got_direct) {
            match b.next_event().await {
                Some(NodeEvent::Message { via, payload, .. }) if !got_msg => {
                    assert_eq!(via, PathKind::Relay, "must use relay before punching");
                    assert_eq!(payload, b"gmpq-msg-1-via-relay");
                    got_msg = true;
                }
                Some(NodeEvent::PunchResult {
                    direct: Some(_), ..
                }) => got_punch = true,
                Some(NodeEvent::DirectReady { .. }) => got_direct = true,
                Some(_) => {}
                None => panic!("b event channel closed"),
            }
        }
    })
    .await
    .expect("b-side: first relay message + punch + direct ready");

    // a-side aggregate wait: punch + direct ready + path switched to Direct
    tokio::time::timeout(T, async {
        let (mut got_punch, mut got_direct, mut got_switch) = (false, false, false);
        while !(got_punch && got_direct && got_switch) {
            match a.next_event().await {
                Some(NodeEvent::PunchResult {
                    direct: Some(_), ..
                }) => got_punch = true,
                Some(NodeEvent::DirectReady { .. }) => got_direct = true,
                Some(NodeEvent::PathSwitch { from, to, .. }) if to == PathKind::Direct => {
                    assert_eq!(from, PathKind::Relay);
                    got_switch = true;
                }
                Some(_) => {}
                None => panic!("a event channel closed"),
            }
        }
    })
    .await
    .expect("a-side: punch + direct ready + path switched to Direct");

    // after the switch, messages take the direct path
    a.send_to(idb, b"gmpq-msg-2-via-direct".to_vec()).await;
    match wait_event(
        &mut b,
        |e| {
            matches!(
                e,
                NodeEvent::Message {
                    via: PathKind::Direct,
                    ..
                }
            )
        },
        "b receives message via direct",
    )
    .await
    {
        NodeEvent::Message { from, payload, .. } => {
            assert_eq!(from, ida);
            assert_eq!(payload, b"gmpq-msg-2-via-direct");
        }
        _ => unreachable!(),
    }

    b.send_to(ida, b"gmpq-reply".to_vec()).await;
    wait_event(
        &mut a,
        |e| matches!(e, NodeEvent::Message { .. }),
        "a receives reply",
    )
    .await;
}
