//! p2p-mesh: iroh-style public-key-direct networking stack (MVP)
//!
//! Architecture paradigm (isomorphic to iroh v1.0): **dial by public key, not by IP**
//! - [`identity`]: NodeId = ed25519 public key (SHA-256 hash for display); self-signed certificates
//! - [`relay`]: encrypted relay — forwards ciphertext only, brokens hole-punch handshakes,
//!   and meters traffic per node
//! - [`holepunch`]: NAT traversal state machine (simultaneous-open), falling back to the relay on timeout
//! - [`path`]: path manager — direct + relay paths coexist, periodic latency probing, seamless switching
//! - [`quic`]: QUIC direct-connect layer — certificate public key == NodeId, TLS 1.3 handshake IS the identity handshake
//! - [`node`]: assembly of the above (actor model)
//!
//! Typical usage: see `examples/` (three-process demo: node-a / node-b / relay).

pub mod crypto;
#[cfg(feature = "gm-pq")]
pub mod gmpq;
pub mod holepunch;
pub mod identity;
pub mod node;
pub mod path;
pub mod proto;
pub mod quic;
pub mod relay;

pub use identity::{NodeId, NodeIdentity};
pub use node::{Node, NodeConfig, NodeEvent};
pub use path::PathKind;
