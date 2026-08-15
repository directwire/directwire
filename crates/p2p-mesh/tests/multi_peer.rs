//! Multi-peer concurrency tests: one node punches/connects/transmits to several peers at once;
//! connection management converges on a unified peer table (each with its own session/path/direct connection).

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::node::{Node, NodeConfig, NodeEvent};
use p2p_mesh::path::PathKind;
use p2p_mesh::relay::RelayServer;
use p2p_mesh::NodeIdentity;

const T: Duration = Duration::from_secs(15);

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

async fn wait_event(
    n: &mut Node,
    pred: impl Fn(&NodeEvent) -> bool,
    what: &str,
) -> NodeEvent {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn concurrent_multi_peer_direct() {
    let relay_addr = spawn_relay().await;
    let ia = NodeIdentity::from_seed([10u8; 32]);
    let ib = NodeIdentity::from_seed([11u8; 32]);
    let ic = NodeIdentity::from_seed([12u8; 32]);
    let idb = ib.node_id();
    let idc = ic.node_id();
    let ida = ia.node_id();

    let mut cfg = NodeConfig::new(relay_addr);
    cfg.probe_interval = Duration::from_millis(300);
    let mut a = Node::start(ia, cfg.clone()).await.unwrap();
    let mut b = Node::start(ib, cfg.clone()).await.unwrap();
    let mut c = Node::start(ic, cfg).await.unwrap();

    // initiate punching to both peers concurrently
    a.connect_peer(idb).await;
    a.connect_peer(idc).await;

    // both peers should punch through + QUIC direct ready + switch to direct
    // (aggregate wait: event order is nondeterministic, cannot wait per peer serially)
    let mut punched = std::collections::HashSet::new();
    let mut direct_ready = std::collections::HashSet::new();
    let mut switched = std::collections::HashSet::new();
    tokio::time::timeout(T, async {
        while switched.len() < 2 {
            match a.next_event().await {
                Some(NodeEvent::PunchResult { peer, direct: Some(_) }) => {
                    punched.insert(peer);
                }
                Some(NodeEvent::DirectReady { peer }) => {
                    direct_ready.insert(peer);
                }
                Some(NodeEvent::PathSwitch { peer, to: PathKind::Direct, .. })
                    if punched.contains(&peer) && direct_ready.contains(&peer) =>
                {
                    switched.insert(peer);
                }
                Some(_) => {}
                None => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("a should complete punch + direct + switch with both b and c");
    assert_eq!(punched.len(), 2);
    assert_eq!(direct_ready.len(), 2);

    // bidirectional messages: a -> b and a -> c both take the direct path, with no cross-talk
    a.send_to(idb, b"for-b".to_vec()).await;
    a.send_to(idc, b"for-c".to_vec()).await;

    match wait_event(&mut b, |e| matches!(e, NodeEvent::Message { via: PathKind::Direct, .. }), "b receives direct message").await {
        NodeEvent::Message { payload, .. } => assert_eq!(payload, b"for-b"),
        _ => unreachable!(),
    }
    match wait_event(&mut c, |e| matches!(e, NodeEvent::Message { via: PathKind::Direct, .. }), "c receives direct message").await {
        NodeEvent::Message { payload, .. } => assert_eq!(payload, b"for-c"),
        _ => unreachable!(),
    }

    // return trip: b -> a and c -> a each use their own peer session
    b.send_to(ida, b"from-b".to_vec()).await;
    c.send_to(ida, b"from-c".to_vec()).await;
    let mut got = 0;
    while got < 2 {
        match wait_event(&mut a, |e| matches!(e, NodeEvent::Message { .. }), "a receives return messages").await {
            NodeEvent::Message { payload, .. } => {
                assert!(payload == b"from-b" || payload == b"from-c");
                got += 1;
            }
            _ => unreachable!(),
        }
    }
}
