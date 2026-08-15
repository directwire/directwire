//! Relay integration tests (loopback TCP): registration, observed echo, brokering, ciphertext forwarding, traffic accounting, fallback correctness

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::identity::NodeIdentity;
use p2p_mesh::proto::{Frame, CAND_PUNCH, CAND_QUIC};
use p2p_mesh::relay::{RelayClient, RelayServer};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_forwards_ciphertext_and_counts_traffic() {
    let relay_addr = spawn_relay().await;
    let ida = NodeIdentity::generate().node_id();
    let idb = NodeIdentity::generate().node_id();

    let (mut ca, _obs_a) = RelayClient::connect(relay_addr, ida, vec![]).await.unwrap();
    let (mut cb, _obs_b) = RelayClient::connect(relay_addr, idb, vec![]).await.unwrap();

    // a -> b sends "ciphertext" (the relay has no way to know its content; simulate ciphertext here)
    let ciphertext = vec![0xabu8; 100];
    ca.send_data(idb, ciphertext.clone()).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), cb.recv())
        .await
        .expect("relay forwarding timed out")
        .unwrap();
    match got {
        Frame::RelayData { to, from, payload } => {
            assert_eq!(to, idb);
            assert_eq!(from, ida); // the relay overwrites `from` from the connection identity
            assert_eq!(payload, ciphertext);
        }
        other => panic!("expected RelayData, got {:?}", other),
    }

    // Traffic accounting: b downlink 100B, a uplink 100B, 1 message
    ca.stats_query().await.unwrap();
    let report = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(Frame::StatsReport { text }) = ca.recv().await {
                break text;
            }
        }
    })
    .await
    .expect("stats query timed out");
    assert!(report.contains(&format!("{}", ida)), "report should contain a: {}", report);
    assert!(report.contains(&format!("{}", idb)), "report should contain b: {}", report);
    assert!(report.contains("msgs=1"), "should count 1 message: {}", report);
    assert!(report.contains("up=100B"), "a uplink 100B: {}", report);
    assert!(report.contains("down=100B"), "b downlink 100B: {}", report);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_echoes_observed_address() {
    // STUN-like: the relay echoes the observed client address
    let relay_addr = spawn_relay().await;
    let ida = NodeIdentity::generate().node_id();
    let (_ca, observed) = RelayClient::connect(relay_addr, ida, vec![]).await.unwrap();
    assert!(observed.ip().is_loopback(), "loopback observed should be 127.0.0.1");
    assert_ne!(observed.port(), 0, "observed should carry the real source port");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_brokers_candidate_exchange() {
    let relay_addr = spawn_relay().await;
    let ida = NodeIdentity::generate().node_id();
    let idb = NodeIdentity::generate().node_id();
    let a_cand = vec![
        (SocketAddr::from(([127, 0, 0, 1], 40001)), CAND_PUNCH),
        (SocketAddr::from(([127, 0, 0, 1], 40002)), CAND_QUIC),
    ];
    let b_cand = vec![
        (SocketAddr::from(([127, 0, 0, 1], 50001)), CAND_PUNCH),
        (SocketAddr::from(([127, 0, 0, 1], 50002)), CAND_QUIC),
    ];

    let (mut ca, _) = RelayClient::connect(relay_addr, ida, a_cand.clone()).await.unwrap();
    let (mut cb, _) = RelayClient::connect(relay_addr, idb, b_cand.clone()).await.unwrap();

    ca.punch_request(idb).await.unwrap();

    // Both sides should receive Exchange carrying the other side's candidates (with type labels)
    let ea = tokio::time::timeout(Duration::from_secs(5), ca.recv())
        .await
        .unwrap()
        .unwrap();
    let eb = tokio::time::timeout(Duration::from_secs(5), cb.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ea, Frame::Exchange { peer: idb, cands: b_cand });
    assert_eq!(eb, Frame::Exchange { peer: ida, cands: a_cand });

    // Re-registration: after updating candidates, brokering should use the new list
    let a_cand2 = vec![(SocketAddr::from(([127, 0, 0, 1], 40011)), CAND_PUNCH)];
    ca.update_addrs(a_cand2.clone()).await.unwrap();
    cb.punch_request(ida).await.unwrap();
    let ea2 = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ca.recv().await {
                Some(Frame::Exchange { cands, .. }) => break cands,
                Some(_) => continue,
                None => panic!("connection closed"),
            }
        }
    })
    .await
    .unwrap();
    let eb2 = tokio::time::timeout(Duration::from_secs(5), cb.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(eb2, Frame::Exchange { cands, .. } if cands == a_cand2));
    assert!(!ea2.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_rejects_unknown_target() {
    let relay_addr = spawn_relay().await;
    let ida = NodeIdentity::generate().node_id();
    let ghost = NodeIdentity::generate().node_id();
    let (mut ca, _) = RelayClient::connect(relay_addr, ida, vec![]).await.unwrap();

    // Forwarding to an offline node -> Error
    ca.send_data(ghost, b"x".to_vec()).await.unwrap();
    let f = tokio::time::timeout(Duration::from_secs(5), ca.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(f, Frame::Error { .. }), "expected Error, got {:?}", f);
}
