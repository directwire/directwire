//! relay process: encrypted transit + hole-punch brokering + traffic accounting
//! usage: cargo run --example relay -- [--port 9100]

use std::net::SocketAddr;
use std::time::Duration;

use p2p_mesh::relay::RelayServer;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .position(|a| a == "--port")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(9100);

    let server = RelayServer::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .expect("relay bind failed");
    let addr = server.local_addr().unwrap();
    let handle = server.handle();
    println!("[relay] listening on {addr} (forwards ciphertext only, cannot read content)");

    tokio::spawn(async move {
        server.serve().await.unwrap();
    });

    let mut t = tokio::time::interval(Duration::from_secs(5));
    loop {
        t.tick().await;
        println!("[relay] traffic stats: {}", handle.stats_text());
    }
}
