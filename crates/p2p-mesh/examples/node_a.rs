//! node-a: the initiator. First communicates via the relay, switches to direct after punching succeeds, prints path switches and latency comparison.
//! usage: cargo run --example node_a -- --peer <node-b NodeId hex> [--relay 127.0.0.1:9100] [--seed 1 | --key-file path]

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::node::{Node, NodeConfig, NodeEvent};
use p2p_mesh::path::PathKind;
use p2p_mesh::{NodeId, NodeIdentity};

fn arg_flag(name: &str) -> Option<String> {
    std::env::args()
        .position(|a| a == name)
        .and_then(|i| std::env::args().nth(i + 1))
}

#[tokio::main]
async fn main() {
    let relay: SocketAddr = arg_flag("--relay")
        .and_then(|s| s.parse().ok())
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 9100)));
    let peer_hex = arg_flag("--peer").expect("missing --peer <node-b NodeId hex>");
    let peer = NodeId::from_hex(&peer_hex).expect("bad --peer format");

    let identity = match arg_flag("--key-file") {
        // Stable identity across restarts: load the seed if present, else generate + persist it
        Some(path) => {
            let id = NodeIdentity::load_or_generate(&path).expect("load/generate identity key file");
            println!("[node-a] identity from key file {} = {}", path, id.node_id());
            id
        }
        None => {
            let seed: u8 = arg_flag("--seed").and_then(|s| s.parse().ok()).unwrap_or(1);
            let id = NodeIdentity::from_seed([seed; 32]);
            println!("[node-a] identity from --seed {} = {}", seed, id.node_id());
            id
        }
    };
    let mut cfg = NodeConfig::new(relay);
    cfg.probe_interval = Duration::from_millis(500);
    #[cfg(feature = "gm-pq")]
    {
        cfg.gmpq = std::env::args().any(|a| a == "--gmpq");
        if cfg.gmpq {
            println!("[node-a] GM-PQ channel enabled (relay path will use the sm2+ml-kem-768 hybrid handshake)");
        }
    }
    let mut node = Node::start(identity, cfg)
        .await
        .expect("node-a start failed");
    println!(
        "[node-a] NodeId = {}, target peer = {}",
        node.node_id(),
        peer
    );

    // 1) before punching, send 3 messages via the relay
    node.connect_peer(peer).await;
    for i in 1..=3 {
        node.send_to(peer, format!("hello-{i}").into_bytes()).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    // 2) collect events: punch/switch/probe; after the direct path is up, send 3 more
    let mut relay_rtt: Vec<f64> = Vec::new();
    let mut direct_rtt: Vec<f64> = Vec::new();
    let mut switched = false;
    let mut sent_after_switch = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);

    while std::time::Instant::now() < deadline {
        let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(2), node.next_event()).await
        else {
            continue;
        };
        match ev {
            NodeEvent::PunchResult { direct, .. } => {
                println!("[node-a] punch result direct={:?}", direct)
            }
            NodeEvent::DirectReady { .. } => println!("[node-a] QUIC direct ready"),
            NodeEvent::SessionReady { peer, suite } => {
                println!(
                    "[node-a] encrypted session ready peer={} suite={}",
                    peer, suite
                )
            }
            NodeEvent::PathSwitch { from, to, .. } => {
                println!("[node-a] *** path switch {:?} -> {:?} ***", from, to);
                if to == PathKind::Direct {
                    switched = true;
                }
            }
            NodeEvent::RttSample { path, rtt_ms, .. } => match path {
                PathKind::Relay => relay_rtt.push(rtt_ms),
                PathKind::Direct => direct_rtt.push(rtt_ms),
            },
            NodeEvent::Message { from, via, payload } => {
                println!(
                    "[node-a] received from={} via={:?} text={:?}",
                    from,
                    via,
                    String::from_utf8_lossy(&payload)
                );
            }
            NodeEvent::Log(m) => println!("[node-a] log: {m}"),
            _ => {}
        }
        // after the switch succeeds, send 3 more over the direct path, then collect 2s of probes and wrap up
        if switched && !sent_after_switch {
            sent_after_switch = true;
            for i in 4..=6 {
                node.send_to(peer, format!("hello-{i}").into_bytes()).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        if sent_after_switch && direct_rtt.len() >= 3 {
            break;
        }
    }

    // 3) latency comparison
    let avg = |v: &[f64]| {
        if v.is_empty() {
            f64::NAN
        } else {
            v.iter().sum::<f64>() / v.len() as f64
        }
    };
    println!(
        "\n========== latency comparison (loopback measured, {} / {} samples) ==========",
        relay_rtt.len(),
        direct_rtt.len()
    );
    println!("  relay  path avg RTT : {:.2} ms", avg(&relay_rtt));
    println!("  direct path avg RTT: {:.2} ms", avg(&direct_rtt));
    println!(
        "  path switch         : {}",
        if switched {
            "relay -> direct succeeded"
        } else {
            "not triggered (still on relay)"
        }
    );
    println!("==========================================================");
    println!("note: on loopback both are sub-millisecond; on the public internet see README: direct 1-5ms vs relay 10-50ms.");
}
