//! Agent-native MCP server (feature `mcp`)
//!
//! Exposes the mesh as MCP tools over stdio so any MCP-capable agent can dial
//! peers and exchange messages by public key. Zero framework: implements the
//! minimal MCP stdio subset directly (newline-delimited JSON-RPC 2.0), so the
//! feature adds exactly one dependency (`serde_json`).
//!
//! Tools:
//! - `peer_connect(target)` — start hole punching + session with a peer
//! - `peer_send(target, payload)` — send a message
//! - `peer_recv(timeout_ms)` — wait for the next inbound message
//! - `peer_status()` — this node's identity
//!
//! Run with:
//! ```text
//! cargo run -p p2p-mesh --features mcp --example mcp_server -- --relay 127.0.0.1:9100
//! ```
//! then point an MCP client at the binary with stdio transport.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::io::AsyncBufReadExt;
use tokio::sync::Mutex;

use crate::node::{Node, NodeConfig, NodeEvent};
use crate::{NodeId, NodeIdentity};

/// MCP protocol version this server speaks
pub const PROTOCOL_VERSION: &str = "2024-11-05";
/// Server name reported to the MCP client
pub const SERVER_NAME: &str = "directwire-mcp";
/// Server version reported to the MCP client
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// Standard JSON-RPC 2.0 error codes
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;
/// JSON-RPC application error range (reserved for tool-level timeouts etc.)
const APP_ERROR: i64 = -32000;

/// A JSON-RPC 2.0 error
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn err(code: i64, message: impl Into<String>) -> Value {
    json!({ "code": code, "message": message.into() })
}

// ---------------------------------------------------------------------------
// The server: a mesh Node wrapped for MCP tool dispatch
// ---------------------------------------------------------------------------

/// MCP server wrapping a mesh [`Node`].
///
/// `connect_peer` / `send_to` / `node_id` are `&self` methods on `Node`, so the
/// node only needs a lock when a tool call uses it; `peer_recv` drains events.
#[derive(Clone)]
pub struct McpMeshServer {
    node: Arc<Mutex<Node>>,
    id: NodeId,
}

impl McpMeshServer {
    /// Start a node and wrap it in the MCP server.
    pub async fn new(identity: NodeIdentity, cfg: NodeConfig) -> std::io::Result<Self> {
        let node = Node::start(identity, cfg).await?;
        let id = node.node_id();
        Ok(Self {
            node: Arc::new(Mutex::new(node)),
            id,
        })
    }

    /// This node's public-key identity (64-char hex).
    pub fn node_id(&self) -> NodeId {
        self.id
    }

    /// Dial a peer by public key (starts hole punching + session establishment).
    pub async fn peer_connect(&self, target: NodeId) -> Result<String, RpcError> {
        self.node.lock().await.connect_peer(target).await;
        Ok(format!("punching/connecting to peer {}", target))
    }

    /// Send a payload to a peer (delivered direct when possible, else relay).
    pub async fn peer_send(&self, target: NodeId, payload: Vec<u8>) -> Result<String, RpcError> {
        let n = payload.len();
        self.node.lock().await.send_to(target, payload).await;
        Ok(format!("sent {n} bytes to peer {}", target))
    }

    /// Wait for the next inbound message from any peer.
    pub async fn peer_recv(&self, timeout_ms: Option<u64>) -> Result<(NodeId, Vec<u8>), RpcError> {
        let fut = async {
            let mut node = self.node.lock().await;
            loop {
                match node.next_event().await {
                    Some(NodeEvent::Message { from, payload, .. }) => return Ok((from, payload)),
                    // Skip lifecycle events; we only surface messages to the agent.
                    Some(_) => continue,
                    None => return Err(RpcError::new(INTERNAL_ERROR, "node event stream closed")),
                }
            }
        };
        match timeout_ms {
            Some(ms) if ms > 0 => {
                match tokio::time::timeout(Duration::from_millis(ms), fut).await {
                    Ok(r) => r,
                    Err(_) => Err(RpcError::new(APP_ERROR, "timed out waiting for a message")),
                }
            }
            _ => fut.await,
        }
    }
}

// ---------------------------------------------------------------------------
// MCP wire handling (newline-delimited JSON-RPC 2.0)
// ---------------------------------------------------------------------------

fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    })
}

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "peer_connect",
                "description": "Begin a session with a peer by its 64-char hex public key (NodeId). Starts NAT hole punching and falls back to the relay if no direct path opens.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "peer NodeId as 64-char hex (ed25519 public key)"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "peer_send",
                "description": "Send an encrypted message to a peer. Delivered over the direct path when one is established, otherwise over the relay.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "peer NodeId as 64-char hex"},
                        "payload": {"type": "string", "description": "message text"}
                    },
                    "required": ["target", "payload"]
                }
            },
            {
                "name": "peer_recv",
                "description": "Wait for the next inbound message from any peer. Returns the sender NodeId and the message text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "timeout_ms": {"type": "integer", "description": "optional timeout in milliseconds; default blocks indefinitely"}
                    }
                }
            },
            {
                "name": "peer_status",
                "description": "Report this node's identity: the 64-char hex NodeId and its short display form.",
                "inputSchema": {"type": "object", "properties": {}}
            }
        ]
    })
}

fn parse_target(s: &str) -> Result<NodeId, String> {
    NodeId::from_hex(s).map_err(|_| {
        format!(
            "'target' must be a 64-char hex NodeId, got {:?}",
            &s[..s.len().min(16)]
        )
    })
}

/// Dispatch a `tools/call`. Returns a tool result (with `isError`) rather than a
/// JSON-RPC error so the agent sees the failure text in-band.
async fn call_tool(server: &McpMeshServer, name: &str, args: &Value) -> Value {
    match call_tool_inner(server, name, args).await {
        Ok(text) => tool_result(text, false),
        Err(text) => tool_result(format!("error: {text}"), true),
    }
}

async fn call_tool_inner(
    server: &McpMeshServer,
    name: &str,
    args: &Value,
) -> Result<String, String> {
    let arg = |k: &str| args.get(k).and_then(|v| v.as_str());
    match name {
        "peer_status" => Ok(format!(
            "node_id={} node_short={}",
            server.node_id().to_hex(),
            server.node_id().short()
        )),
        "peer_connect" => {
            let target = arg("target").ok_or("missing string arg 'target'")?;
            let id = parse_target(target)?;
            server.peer_connect(id).await.map_err(|e| e.message)
        }
        "peer_send" => {
            let target = arg("target").ok_or("missing string arg 'target'")?;
            let payload = arg("payload").ok_or("missing string arg 'payload'")?;
            let id = parse_target(target)?;
            server
                .peer_send(id, payload.as_bytes().to_vec())
                .await
                .map_err(|e| e.message)
        }
        "peer_recv" => {
            let timeout = args.get("timeout_ms").and_then(|v| v.as_u64());
            match server.peer_recv(timeout).await {
                Ok((from, payload)) => Ok(format!(
                    "from={} payload={}",
                    from.to_hex(),
                    String::from_utf8_lossy(&payload)
                )),
                Err(e) => Err(e.message),
            }
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

/// Handle one newline-delimited JSON-RPC message. Returns `None` for
/// notifications (nothing to reply) and `Some(response)` otherwise.
pub async fn handle_line(server: &McpMeshServer, line: &str) -> Option<Value> {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return Some(json!({"jsonrpc":"2.0","id":null,"error":err(PARSE_ERROR,"parse error")}));
        }
    };
    let id = v.get("id").cloned();
    let is_notification = id.is_none();
    let method = v.get("method").and_then(|m| m.as_str());
    let Some(method) = method else {
        return Some(
            json!({"jsonrpc":"2.0","id":id,"error":err(INVALID_REQUEST,"invalid request")}),
        );
    };
    let params = v.get("params").cloned().unwrap_or(Value::Null);

    let result: Result<Value, RpcError> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })),
        // Lifecycle / capability notifications need no response.
        "notifications/initialized" if is_notification => return None,
        "ping" => Ok(Value::Object(Map::new())),
        "tools/list" => Ok(tools_list()),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            Ok(call_tool(server, name, &args).await)
        }
        // Unknown notifications are ignored per the MCP spec; unknown methods error.
        _ if is_notification => return None,
        _ => Err(RpcError::new(METHOD_NOT_FOUND, "method not found")),
    };

    let id = match id {
        Some(id) => id,
        None => return None, // notification: nothing to reply
    };
    Some(match result {
        Ok(r) => json!({"jsonrpc":"2.0","id":id,"result":r}),
        Err(e) => json!({"jsonrpc":"2.0","id":id,"error":err(e.code, e.message)}),
    })
}

/// Run the MCP stdio loop: read newline-delimited JSON-RPC from stdin, write
/// responses to stdout, log operator diagnostics to stderr.
pub async fn run(identity: NodeIdentity, cfg: NodeConfig) -> std::io::Result<()> {
    let relay_addr = cfg.relay_addr;
    let server = McpMeshServer::new(identity, cfg).await?;
    // Startup diagnostics go to stderr so they never pollute the JSON stream.
    eprintln!("directwire-mcp: node_id={}", server.node_id().to_hex());
    eprintln!("directwire-mcp: node_short={}", server.node_id().short());
    eprintln!("directwire-mcp: relay={relay_addr}");

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            break; // client closed the pipe
        }
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(resp) = handle_line(&server, line).await {
            let s = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
            println!("{s}");
            std::io::stdout().flush().ok();
        }
    }
    eprintln!("directwire-mcp: stdin closed, shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_accepts_64_hex_and_rejects_short() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(parse_target(hex).is_ok());
        assert!(parse_target("not-hex").is_err());
        assert!(parse_target("").is_err());
    }

    #[test]
    fn tools_list_has_four_tools_with_schemas() {
        let v = tools_list();
        let tools = v["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
        for t in tools {
            assert!(t["name"].is_string());
            assert!(t["inputSchema"]["type"].as_str() == Some("object"));
        }
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            ["peer_connect", "peer_send", "peer_recv", "peer_status"]
        );
    }

    #[test]
    fn parse_error_line_returns_parse_error() {
        // handle_line needs a server; the error path is reached before any server use,
        // so we can hand a dangling reference through a cheap fake.
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Use a stack server that is never touched on the error path.
        rt.block_on(async {
            // Build a real server on a throwaway node so handle_line's signature is real.
            // (The parse-error path never dereferences it.)
            let node = fake_server().await;
            let r = handle_line(&node, "{not json").await.unwrap();
            assert_eq!(r["error"]["code"], PARSE_ERROR);
            assert_eq!(r["error"]["message"], "parse error");
        });
    }

    /// A real mesh server on a real relay (loopback) so `Node::start` can connect.
    async fn fake_server() -> McpMeshServer {
        let server =
            crate::relay::RelayServer::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            server.serve().await.unwrap();
        });
        let cfg = NodeConfig::new(addr);
        McpMeshServer::new(NodeIdentity::generate(), cfg)
            .await
            .unwrap()
    }

    #[test]
    fn initialize_and_method_not_found_over_wire() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = fake_server().await;
            let r = handle_line(
                &server,
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            )
            .await
            .unwrap();
            assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
            assert_eq!(r["result"]["serverInfo"]["name"], SERVER_NAME);
            assert_eq!(r["id"], 1);

            let r = handle_line(&server, r#"{"jsonrpc":"2.0","id":2,"method":"bogus"}"#)
                .await
                .unwrap();
            assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
        });
    }

    #[test]
    fn notifications_get_no_reply() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = fake_server().await;
            let r = handle_line(
                &server,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            )
            .await;
            assert!(r.is_none());
        });
    }
}
