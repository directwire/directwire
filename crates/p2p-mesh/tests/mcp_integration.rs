//! MCP integration tests (feature `mcp`): the agent-native server is a real mesh
//! node — it must dial peers, exchange messages end-to-end, and speak the MCP
//! stdio wire protocol over newline-delimited JSON-RPC.

#![cfg(feature = "mcp")]

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::mcp::{handle_line, McpMeshServer, PROTOCOL_VERSION, SERVER_NAME};
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

/// The MCP server is a real mesh node: it dials an ordinary node, sends a
/// message that arrives, and receives the reply through `peer_recv`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_node_exchanges_messages_with_ordinary_node() {
    let relay_addr = spawn_relay().await;
    let ia = NodeIdentity::from_seed([20u8; 32]);
    let ib = NodeIdentity::from_seed([21u8; 32]);
    let idb = ib.node_id();

    let cfg = NodeConfig::new(relay_addr);
    let server = McpMeshServer::new(ia, cfg.clone()).await.unwrap();
    let mut b = Node::start(ib, cfg).await.unwrap();

    // dial by public key
    let note = server.peer_connect(idb).await.unwrap();
    assert!(note.contains("punching/connecting"), "note: {note}");

    // a -> b
    let sent = server.peer_send(idb, b"mcp-hello".to_vec()).await.unwrap();
    assert!(sent.contains("sent 9 bytes"), "sent: {sent}");
    match wait_event(
        &mut b,
        |e| matches!(e, NodeEvent::Message { .. }),
        "b receives mcp-hello",
    )
    .await
    {
        NodeEvent::Message { from, payload, .. } => {
            assert_eq!(from, server.node_id());
            assert_eq!(payload, b"mcp-hello");
        }
        _ => unreachable!(),
    }

    // b -> a, received via the MCP tool with a timeout
    b.send_to(server.node_id(), b"mcp-reply".to_vec()).await;
    let (from, payload) = server.peer_recv(Some(5_000)).await.unwrap();
    assert_eq!(from, idb);
    assert_eq!(payload, b"mcp-reply");
}

/// The wire protocol: initialize / tools/list / tools/call over JSON-RPC 2.0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_protocol_handshake_and_tools() {
    let relay_addr = spawn_relay().await;
    let cfg = NodeConfig::new(relay_addr);
    let server = McpMeshServer::new(NodeIdentity::generate(), cfg)
        .await
        .unwrap();

    // initialize
    let r = handle_line(
        &server,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    )
    .await
    .unwrap();
    assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(r["result"]["serverInfo"]["name"], SERVER_NAME);
    assert_eq!(r["id"], 1);

    // notification: no reply
    assert!(handle_line(
        &server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await
    .is_none());

    // tools/list
    let r = handle_line(&server, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .await
        .unwrap();
    let tools = r["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    assert!(tools.iter().any(|t| t["name"] == "peer_status"));

    // tools/call peer_status -> identity
    let r = handle_line(
        &server,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"peer_status","arguments":{}}}"#,
    )
    .await
    .unwrap();
    let text = r["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.starts_with("node_id="), "status: {text}");

    // tools/call with a bad target -> isError result (not a JSON-RPC error)
    let r = handle_line(
        &server,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"peer_connect","arguments":{"target":"nope"}}}"#,
    )
    .await
    .unwrap();
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("64-char hex"));

    // unknown method -> JSON-RPC error
    let r = handle_line(&server, r#"{"jsonrpc":"2.0","id":5,"method":"bogus"}"#)
        .await
        .unwrap();
    assert_eq!(r["error"]["code"], -32601);
}

/// MCP message takes the direct path after punching (the agent gets the same
/// data plane as any mesh node, plus the relay guarantees liveness).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_node_upgrades_to_direct_path() {
    let relay_addr = spawn_relay().await;
    let ia = NodeIdentity::from_seed([22u8; 32]);
    let ib = NodeIdentity::from_seed([23u8; 32]);
    let idb = ib.node_id();

    let mut cfg = NodeConfig::new(relay_addr);
    cfg.probe_interval = Duration::from_millis(300);
    let server = McpMeshServer::new(ia, cfg.clone()).await.unwrap();
    let mut b = Node::start(ib, cfg).await.unwrap();

    server.peer_connect(idb).await.unwrap();
    // Kick off the relay path so b has a first message while punching proceeds.
    server
        .peer_send(idb, b"first-via-relay".to_vec())
        .await
        .unwrap();
    // b-side: first relay message + punch + direct ready + path switched to direct
    tokio::time::timeout(T, async {
        let (mut got_msg, mut got_switch) = (false, false);
        while !(got_msg && got_switch) {
            match b.next_event().await {
                Some(NodeEvent::Message { via, payload, .. }) if !got_msg => {
                    assert_eq!(via, PathKind::Relay, "first message must use the relay");
                    assert_eq!(payload, b"first-via-relay");
                    got_msg = true;
                }
                Some(NodeEvent::PathSwitch {
                    to: PathKind::Direct,
                    ..
                }) => got_switch = true,
                Some(_) => {}
                None => panic!("b event channel closed"),
            }
        }
    })
    .await
    .expect("b-side: relay message + switch to direct");

    // after the switch, the agent's message flows over the direct path
    server
        .peer_send(idb, b"over-direct".to_vec())
        .await
        .unwrap();
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
        "b receives direct message",
    )
    .await
    {
        NodeEvent::Message { payload, .. } => assert_eq!(payload, b"over-direct"),
        _ => unreachable!(),
    }
}
