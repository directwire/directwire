//! Encrypted relay: forwards ciphertext only, brokers handshakes (cross-sends both sides' candidates), and meters traffic per node
//!
//! Role: the fallback path when hole punching fails (iroh's DERP counterpart).
//! The relay cannot read RelayData.payload at all (end-to-end AEAD ciphertext, see [`crate::crypto`]).

mod client;
mod server;

pub use client::RelayClient;
pub use server::{NodeTraffic, RelayHandle, RelayServer};
