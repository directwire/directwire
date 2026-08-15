//! NAT traversal state machine (IO-free core + UDP driver)
//!
//! Flow (isomorphic to iroh / Tailscale):
//! 1. Both sides register their local UDP candidates with the relay (Hello)
//! 2. One side sends PunchRequest; the relay cross-sends both sides' candidates (Exchange)
//! 3. Both sides send PUNCH packets to all of the peer's candidates simultaneously (simultaneous-open:
//!    the outbound packets open mappings in each NAT; inbound packets are then admitted)
//! 4. A peer PUNCH packet received => Direct(src); timeout => Failed (the upper layer falls back to the relay)
//!
//! The state machine itself does no IO, which keeps it deterministically unit-testable;
//! [`drive`] drives it with a tokio UdpSocket.

use std::net::SocketAddr;
use std::time::Duration;

use crate::identity::NodeId;

/// Hole-punch packet magic + sender NodeId (32 bytes)
pub const PUNCH_MAGIC: &[u8; 4] = b"PMP1";
pub const PUNCH_PACKET_LEN: usize = 4 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchState {
    Idle,
    /// Started; waiting for the relay to deliver the peer's candidates
    WaitCandidates,
    /// In simultaneous-open (periodically sending PUNCH to all candidates)
    Punching,
    /// Direct path established (the peer PUNCH packet's source address is the usable direct address)
    Direct(SocketAddr),
    /// Timed out and failed; should fall back to the relay
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchEvent {
    /// Start punching (PunchRequest already sent)
    Begin,
    /// The relay brokered the peer's candidate addresses
    Candidates(Vec<SocketAddr>),
    /// A peer PUNCH packet was received (with its source address)
    PacketFrom(SocketAddr),
    /// Retransmission timer fired
    Tick,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchAction {
    /// Send a PUNCH packet to that candidate address
    SendPunch(SocketAddr),
    /// Direct path established
    Established(SocketAddr),
    /// Hole punching failed; fall back to the relay
    FallbackToRelay,
}

pub struct PunchMachine {
    state: PunchState,
    peer_addrs: Vec<SocketAddr>,
    attempts: u32,
    max_attempts: u32,
}

impl PunchMachine {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            state: PunchState::Idle,
            peer_addrs: Vec::new(),
            attempts: 0,
            max_attempts,
        }
    }

    pub fn state(&self) -> &PunchState {
        &self.state
    }

    /// Purely functional transition: feed events -> get actions (no IO whatsoever)
    pub fn handle(&mut self, ev: PunchEvent) -> Vec<PunchAction> {
        match (&self.state, ev) {
            (PunchState::Idle, PunchEvent::Begin) => {
                self.state = PunchState::WaitCandidates;
                vec![]
            }
            (PunchState::WaitCandidates | PunchState::Punching, PunchEvent::Candidates(addrs)) => {
                self.peer_addrs = addrs;
                self.attempts = 1;
                self.state = PunchState::Punching;
                self.peer_addrs.iter().map(|a| PunchAction::SendPunch(*a)).collect()
            }
            (PunchState::WaitCandidates | PunchState::Punching, PunchEvent::PacketFrom(src)) => {
                self.state = PunchState::Direct(src);
                vec![PunchAction::Established(src)]
            }
            (PunchState::Punching, PunchEvent::Tick) => {
                if self.attempts >= self.max_attempts {
                    self.state = PunchState::Failed;
                    return vec![PunchAction::FallbackToRelay];
                }
                self.attempts += 1;
                self.peer_addrs.iter().map(|a| PunchAction::SendPunch(*a)).collect()
            }
            // Direct/Failed are terminal states; all other combinations are ignored
            _ => vec![],
        }
    }
}

pub fn encode_punch_packet(id: &NodeId) -> Vec<u8> {
    let mut p = Vec::with_capacity(PUNCH_PACKET_LEN);
    p.extend_from_slice(PUNCH_MAGIC);
    p.extend_from_slice(id.as_bytes());
    p
}

/// Parse a PUNCH packet, returning the sender's NodeId
pub fn decode_punch_packet(buf: &[u8]) -> Option<NodeId> {
    if buf.len() != PUNCH_PACKET_LEN || &buf[..4] != PUNCH_MAGIC {
        return None;
    }
    Some(NodeId::from_bytes(buf[4..36].try_into().ok()?))
}

/// UDP driver: drives the state machine until Direct or Failed
pub async fn drive(
    socket: &tokio::net::UdpSocket,
    our_id: &NodeId,
    peer_id: &NodeId,
    peer_addrs: Vec<SocketAddr>,
    tick: Duration,
    max_attempts: u32,
) -> std::io::Result<Option<SocketAddr>> {
    let mut m = PunchMachine::new(max_attempts);
    m.handle(PunchEvent::Begin);
    let actions = m.handle(PunchEvent::Candidates(peer_addrs));
    let packet = encode_punch_packet(our_id);
    let mut buf = [0u8; 2048];
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut pending: Vec<PunchAction> = actions;
    loop {
        // Execute backlogged actions
        for a in pending.drain(..) {
            match a {
                PunchAction::SendPunch(addr) => {
                    let _ = socket.send_to(&packet, addr).await;
                }
                PunchAction::Established(addr) => return Ok(Some(addr)),
                PunchAction::FallbackToRelay => return Ok(None),
            }
        }
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                // During punching the peer's port may be closed/unreachable; Windows surfaces
                // ICMP port-unreachable as ConnectionReset on recv — normal noise, ignore and continue
                let Ok((n, src)) = recv else { continue };
                if decode_punch_packet(&buf[..n]) == Some(*peer_id) {
                    pending = m.handle(PunchEvent::PacketFrom(src));
                }
                // Non-peer packets (or early QUIC packets) are ignored
            }
            _ = ticker.tick() => {
                pending = m.handle(PunchEvent::Tick);
            }
        }
    }
}

// ---------- candidate collection (STUN-like, local side) ----------

/// Enumerate this host's IPv4 NIC addresses (best-effort, no third-party dependencies):
/// 1. the UDP-connect trick gets the primary egress NIC address (no real traffic is produced)
/// 2. hostname resolution returns all registered addresses (multi-NIC)
pub fn local_ipv4_addrs() -> Vec<std::net::Ipv4Addr> {
    use std::net::{IpAddr, ToSocketAddrs};
    let mut out: Vec<std::net::Ipv4Addr> = Vec::new();
    // Primary egress NIC
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(la) = s.local_addr() {
                if let IpAddr::V4(v4) = la.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        out.push(v4);
                    }
                }
            }
        }
    }
    // All NICs (hostname -> getaddrinfo; works best-effort on Windows/Unix)
    if let Ok(h) = std::process::Command::new("hostname").output() {
        let name = String::from_utf8_lossy(&h.stdout).trim().to_string();
        if !name.is_empty() {
            if let Ok(iter) = (name.as_str(), 0u16).to_socket_addrs() {
                for a in iter {
                    if let IpAddr::V4(v4) = a.ip() {
                        if !v4.is_loopback() && !v4.is_unspecified() && !out.contains(&v4) {
                            out.push(v4);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Build the candidate list: loopback + each NIC IP + observed (the public address echoed by the
/// relay), expanding every IP into two candidates (hole-punch port and QUIC port)
pub fn build_candidates(
    punch_port: u16,
    quic_port: u16,
    extra_ips: &[std::net::Ipv4Addr],
    observed: Option<SocketAddr>,
) -> crate::proto::Candidates {
    let mut ips: Vec<std::net::Ipv4Addr> = vec![std::net::Ipv4Addr::LOCALHOST];
    for ip in extra_ips {
        if !ips.contains(ip) {
            ips.push(*ip);
        }
    }
    if let Some(o) = observed {
        if let std::net::IpAddr::V4(v4) = o.ip() {
            if !ips.contains(&v4) {
                ips.push(v4);
            }
        }
    }
    let mut cands = Vec::with_capacity(ips.len() * 2);
    for ip in ips {
        cands.push((SocketAddr::from((ip, punch_port)), crate::proto::CAND_PUNCH));
        cands.push((SocketAddr::from((ip, quic_port)), crate::proto::CAND_QUIC));
    }
    cands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ip_enum_does_not_panic() {
        // Must not panic in any environment; the result may be empty (e.g. offline containers)
        let ips = local_ipv4_addrs();
        for ip in &ips {
            assert!(!ip.is_loopback() && !ip.is_unspecified());
        }
    }

    #[test]
    fn candidates_cover_loopback_nic_and_observed() {
        let cands = build_candidates(
            1000,
            2000,
            &[std::net::Ipv4Addr::new(192, 168, 1, 5)],
            Some(SocketAddr::from(([203, 0, 113, 9], 40000))),
        );
        // loopback + NIC + observed, 2 each (punch/quic)
        assert_eq!(cands.len(), 6);
        assert!(cands.contains(&(SocketAddr::from(([127, 0, 0, 1], 1000)), crate::proto::CAND_PUNCH)));
        assert!(cands.contains(&(SocketAddr::from(([192, 168, 1, 5], 2000)), crate::proto::CAND_QUIC)));
        assert!(cands.contains(&(SocketAddr::from(([203, 0, 113, 9], 1000)), crate::proto::CAND_PUNCH)));
        // Dedup: no duplicate when observed and NIC share the same IP
        let c2 = build_candidates(1, 2, &[std::net::Ipv4Addr::new(10, 0, 0, 1)], Some(SocketAddr::from(([10, 0, 0, 1], 9))));
        assert_eq!(c2.len(), 4);
    }
}
