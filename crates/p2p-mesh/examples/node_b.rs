//! node-b: the passive side. Registers to the relay, waits for node-a to punch, auto-acks.
//! usage: cargo run --example node_b -- [--relay 127.0.0.1:9100] [--seed 2]

use std::net::SocketAddr;

use p2p_mesh::node::{Node, NodeConfig, NodeEvent};
use p2p_mesh::NodeIdentity;

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
    let seed: u8 = arg_flag("--seed").and_then(|s| s.parse().ok()).unwrap_or(2);

    let identity = NodeIdentity::from_seed([seed; 32]);
    let mut cfg = NodeConfig::new(relay);
    cfg.probe_interval = std::time::Duration::from_millis(500);
    #[cfg(feature = "gm-pq")]
    {
        cfg.gmpq = std::env::args().any(|a| a == "--gmpq");
        if cfg.gmpq {
            eprintln!("[node-b] GM-PQ channel enabled (relay path will use the sm2+ml-kem-768 hybrid handshake)");
        }
    }
    let mut node = Node::start(identity, cfg)
        .await
        .expect("node-b start failed");
    // Diagnostics go to stderr: unbuffered even when redirected, so scripts can
    // read the NodeId promptly (stdout becomes block-buffered on a pipe).
    eprintln!(
        "[node-b] NodeId = {} (hex: {})",
        node.node_id(),
        node.node_id().to_hex()
    );
    eprintln!("[node-b] waiting for punch and messages...");

    while let Some(ev) = node.next_event().await {
        match ev {
            NodeEvent::PunchResult { peer, direct } => {
                eprintln!("[node-b] punch result peer={} direct={:?}", peer, direct)
            }
            NodeEvent::DirectReady { peer } => {
                eprintln!("[node-b] QUIC direct ready peer={}", peer)
            }
            NodeEvent::SessionReady { peer, suite } => {
                eprintln!(
                    "[node-b] encrypted session ready peer={} suite={}",
                    peer, suite
                )
            }
            NodeEvent::PathSwitch { peer, from, to } => {
                eprintln!(
                    "[node-b] * path switch peer={} {:?} -> {:?}",
                    peer, from, to
                )
            }
            NodeEvent::RttSample { path, rtt_ms, .. } => {
                eprintln!("[node-b] probe {:?} rtt={:.2}ms", path, rtt_ms)
            }
            NodeEvent::Message { from, via, payload } => {
                let text = String::from_utf8_lossy(&payload);
                eprintln!(
                    "[node-b] message from={} via={:?} text={:?}",
                    from, via, text
                );
                node.send_to(from, format!("ack:{text}").into_bytes()).await;
            }
            NodeEvent::Log(m) => eprintln!("[node-b] log: {m}"),
            _ => {}
        }
    }
}
