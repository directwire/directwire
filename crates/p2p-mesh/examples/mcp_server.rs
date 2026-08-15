//! MCP stdio server example: expose a mesh node to any MCP-capable agent.
//!
//! ```text
//! # terminal 1 — relay
//! cargo run -p p2p-mesh --example relay -- --port 9100
//! # terminal 2 — this MCP server (identity printed on stderr)
//! cargo run -p p2p-mesh --features mcp --example mcp_server -- --relay 127.0.0.1:9100
//! ```
//!
//! Then point an MCP client (e.g. Claude Desktop) at this binary over stdio.
//! The agent can dial any peer by its 64-char hex public key, send messages,
//! and receive replies — no accounts, no IP addressing.

#[cfg(feature = "mcp")]
use p2p_mesh::mcp;
#[cfg(feature = "mcp")]
use p2p_mesh::{NodeConfig, NodeIdentity};

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let relay = args
        .iter()
        .position(|a| a == "--relay")
        .and_then(|i| args.get(i + 1))
        .ok_or("usage: mcp_server --relay HOST:PORT [--seed N] [--gm-pq]")?;
    let relay_addr: std::net::SocketAddr = relay.parse()?;

    let seed = args
        .iter()
        .position(|a| a == "--seed")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u8>().ok());
    let identity = match seed {
        Some(n) => NodeIdentity::from_seed([n; 32]),
        None => NodeIdentity::generate(),
    };

    let mut cfg = NodeConfig::new(relay_addr);
    cfg.gmpq = args.iter().any(|a| a == "--gm-pq");

    mcp::run(identity, cfg).await?;
    Ok(())
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!(
        "mcp_server requires the 'mcp' feature: \
         cargo run -p p2p-mesh --features mcp --example mcp_server"
    );
}
