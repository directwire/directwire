//! Transport session after the handshake: SM4-GCM encryption + sequence-number replay window.
//!
//! Replay-protection model (consistent with the Noise transport phase):
//! - Every packet carries a monotonically increasing 64-bit sequence number, which also seeds
//!   the GCM nonce entropy;
//! - The receiver maintains a 64-slot sliding window: duplicate sequence numbers and numbers too
//!   old to be in the window are rejected;
//! - Reordering within the window (≤64 packets) is allowed, suiting UDP / multi-path scenarios;
//!   strictly ordered scenarios (TCP) also pass (the window degrades to expected-sequence checking).

use crate::crypto::Aead;
use crate::{Error, Result};

/// Replay window width (slots)
pub const WINDOW_SIZE: u64 = 64;

/// Sliding replay window
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest sequence number seen
    highest: u64,
    /// Bitmap: bit i means sequence (highest - i) has been received
    bitmap: u64,
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    /// Check whether a sequence number is fresh; mark it and return Ok if so; replay / too-old returns Err(Replay)
    pub fn check_and_mark(&mut self, seq: u64) -> Result<()> {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1; // bit0 = highest itself
            return Ok(());
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = seq;
            return Ok(());
        }
        let delta = self.highest - seq;
        if delta >= WINDOW_SIZE {
            return Err(Error::Replay); // too old, slid out of the window
        }
        let bit = 1u64 << delta;
        if self.bitmap & bit != 0 {
            return Err(Error::Replay); // duplicate
        }
        self.bitmap |= bit;
        Ok(())
    }
}

/// Bidirectional transport session (one per completed handshake)
pub struct Session {
    tx: Aead,
    rx: Aead,
    window: ReplayWindow,
    /// Session identifier = final handshake transcript hash, identical on both sides; useful for log correlation / key confirmation
    session_id: [u8; 32],
}

impl Session {
    pub fn new(tx_key: [u8; 16], rx_key: [u8; 16], session_id: [u8; 32]) -> Self {
        Session {
            tx: Aead::new(tx_key),
            rx: Aead::new(rx_key),
            window: ReplayWindow::new(),
            session_id,
        }
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Encrypt one application message
    pub fn send(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.tx.seal(&self.session_id, plaintext)
    }

    /// Decrypt one application message; authentication failure or a replay-window hit both error out
    pub fn recv(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let (seq, pt) = self.rx.open(&self.session_id, packet)?;
        self.window.check_and_mark(seq)?;
        Ok(pt)
    }
}
