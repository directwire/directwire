//! Node orchestration: the assembly point of relay session + hole punching + QUIC direct + path management
//!
//! Runtime model: a single actor task owns all state; external code drives it through the [`Node`]
//! handle (send commands, receive events).
//! Socket layout (supports concurrent multi-peer):
//! - punch socket: a resident bare UDP socket; the actor's built-in punch scheduler dispatches
//!   PUNCH packets by the sender's NodeId
//! - QUIC endpoint socket: created at startup (resident accept loop); after a successful hole
//!   punch, both sides connect/accept
//! Data plane:
//! - relay path: app message -> ephemeral-DH-session AEAD ciphertext -> RelayData -> relay forwarding
//! - direct path: app message -> QUIC bi stream (TLS 1.3, certificate public key == NodeId)
//! Known debt: on real NATs the hole-punch socket and the QUIC socket are separate, so the QUIC
//! port's mapping must be opened by the simultaneous-open QUIC Initial itself (works on
//! loopback/LAN/full-cone NAT); the complete solution reuses the same socket for hole-punch
//! packets and QUIC (iroh's approach), see the README TODO.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::crypto::{self, HsState, SessionCipher, HS_KIND_INIT, HS_KIND_RESP, HS_TAG};
#[cfg(feature = "gm-pq")]
use crate::gmpq;
use crate::holepunch::{self, PunchAction, PunchEvent, PunchMachine};
use crate::identity::{NodeId, NodeIdentity};
use crate::path::{PathKind, PathManager, PathSample};
use crate::proto::{Frame, CAND_PUNCH, CAND_QUIC};
use crate::quic;
use crate::relay::RelayClient;

/// Inner tags inside the relay payload (the AEAD plaintext layer, invisible to the relay)
const INNER_DATA: u8 = 0x01;
const INNER_PING: u8 = 0x02;
const INNER_PONG: u8 = 0x03;

/// Loss-statistics window (last N ping outcomes)
const LOSS_WINDOW: usize = 20;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub relay_addr: SocketAddr,
    /// Extra advertised candidate addresses (None = auto-collect: loopback + local NICs + observed)
    pub advertise_addrs: Option<crate::proto::Candidates>,
    /// Whether to hole punch (false => force relay-only, for testing the fallback path)
    pub enable_punch: bool,
    /// Hole-punch retransmission interval
    pub punch_tick: Duration,
    /// Max hole-punch attempts (total timeout ≈ tick * max_attempts)
    pub punch_max_attempts: u32,
    /// Dual-path probe interval
    pub probe_interval: Duration,
    /// Prefer the national-crypto PQ hybrid handshake on the relay path (effective only when
    /// compiled with feature=gm-pq; auto-fallback to X25519+ed25519 when the peer lacks support
    /// or the handshake times out)
    pub gmpq: bool,
}

impl NodeConfig {
    pub fn new(relay_addr: SocketAddr) -> Self {
        Self {
            relay_addr,
            advertise_addrs: None,
            enable_punch: true,
            punch_tick: Duration::from_millis(100),
            punch_max_attempts: 20,
            probe_interval: Duration::from_millis(1000),
            gmpq: false,
        }
    }
}

/// Node events (for examples / tests to observe)
#[derive(Debug)]
pub enum NodeEvent {
    Registered {
        relay: SocketAddr,
        observed: SocketAddr,
    },
    PunchStarted {
        peer: NodeId,
    },
    /// Punch result: Some(addr) = a direct address opened; None = timed out, fell back to the relay
    PunchResult {
        peer: NodeId,
        direct: Option<SocketAddr>,
    },
    /// QUIC direct connection ready
    DirectReady {
        peer: NodeId,
    },
    /// Path switch (seamless: messages remain reachable across the switch)
    PathSwitch {
        peer: NodeId,
        from: PathKind,
        to: PathKind,
    },
    /// Probe sample (with loss rate)
    RttSample {
        peer: NodeId,
        path: PathKind,
        rtt_ms: f64,
        loss_pct: f64,
    },
    /// Relay-path encrypted session ready (suite: "x25519+ed25519" or "sm2+ml-kem-768+sm4-gcm")
    SessionReady {
        peer: NodeId,
        suite: &'static str,
    },
    Message {
        from: NodeId,
        via: PathKind,
        payload: Vec<u8>,
    },
    Log(String),
}

enum NodeCmd {
    ConnectPeer {
        peer: NodeId,
    },
    SendTo {
        peer: NodeId,
        payload: Vec<u8>,
    },
    ProbeTick,
    /// GM-PQ handshake timeout check (generation guards against stale timers)
    #[cfg(feature = "gm-pq")]
    GmCheck {
        peer: NodeId,
        gen: u64,
    },
    Shutdown,
}

enum QuicEv {
    /// A new QUIC connection; bool = whether it is our outbound (used for simultaneous-open dedup)
    Conn(quinn::Connection, bool),
    /// Connection closed (carries the stable_id so a replaced new connection is not wrongly cleared)
    ConnClosed(NodeId, usize),
}

/// Node handle
pub struct Node {
    id: NodeId,
    cmd: mpsc::Sender<NodeCmd>,
    events: mpsc::Receiver<NodeEvent>,
    actor: tokio::task::JoinHandle<()>,
}

impl Node {
    /// Start the node: bind the hole-punch / QUIC UDP sockets, connect to the relay, and register candidate addresses
    pub async fn start(identity: NodeIdentity, cfg: NodeConfig) -> io::Result<Self> {
        let id = identity.node_id();
        // Hole-punch socket (resident)
        let punch_sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let punch_port = punch_sock.local_addr()?.port();
        // QUIC socket: the endpoint is created at startup (shared by multiple peers)
        let quic_sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let quic_port = quic_sock.local_addr()?.port();
        let endpoint = quic::endpoint_from_socket(quic_sock.into_std()?, &identity)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Candidate addresses: loopback + local NICs (observed is re-registered after HelloAck)
        let ips = holepunch::local_ipv4_addrs();
        let cands = cfg
            .advertise_addrs
            .clone()
            .unwrap_or_else(|| holepunch::build_candidates(punch_port, quic_port, &ips, None));

        let (relay, observed) = RelayClient::connect(cfg.relay_addr, id, cands).await?;
        // STUN-like: add the observed public IP to the candidates and re-register
        if observed.ip().is_ipv4()
            && !ips.contains(&match observed.ip() {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(_) => unreachable!(),
            })
        {
            let cands = holepunch::build_candidates(punch_port, quic_port, &ips, Some(observed));
            relay.update_addrs(cands).await.ok();
        }

        let (cmd_tx, cmd_rx) = mpsc::channel::<NodeCmd>(256);
        let (ev_tx, ev_rx) = mpsc::channel::<NodeEvent>(256);
        let (qtx, qrx) = mpsc::channel::<QuicEv>(64);

        ev_tx
            .send(NodeEvent::Registered {
                relay: cfg.relay_addr,
                observed,
            })
            .await
            .ok();

        // QUIC accept loop (resident)
        {
            let ep = endpoint.clone();
            let qtx = qtx.clone();
            tokio::spawn(async move {
                while let Some(incoming) = ep.accept().await {
                    match incoming.await {
                        Ok(c) => {
                            let _ = qtx.send(QuicEv::Conn(c, false)).await;
                        }
                        Err(_) => {}
                    }
                }
            });
        }

        // Periodic probe timer -> actor
        let probe = cfg.probe_interval;
        if !probe.is_zero() {
            let cmd = cmd_tx.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(probe);
                loop {
                    t.tick().await;
                    if cmd.send(NodeCmd::ProbeTick).await.is_err() {
                        break;
                    }
                }
            });
        }

        // GM-PQ identity and cookie issuer (feature gm-pq and configured enabled)
        #[cfg(feature = "gm-pq")]
        let (gm_id, gm_cookie) = if cfg.gmpq {
            (
                gmpq::GmIdentity::generate(),
                Some(gmpq::new_cookie_issuer()),
            )
        } else {
            (None, None)
        };
        #[cfg(feature = "gm-pq")]
        if cfg.gmpq && gm_id.is_none() {
            ev_tx
                .send(NodeEvent::Log(
                    "GM-PQ identity generation failed, falling back to X25519".into(),
                ))
                .await
                .ok();
        }

        let mut actor = Actor {
            identity,
            #[cfg(feature = "gm-pq")]
            gm_id,
            #[cfg(feature = "gm-pq")]
            gm_cookie,
            cfg,
            relay,
            punch_sock: Arc::new(punch_sock),
            endpoint,
            peers: HashMap::new(),
            punching: HashMap::new(),
            punch_reply_budget: HashMap::new(),
            ping_seq: 0,
            events: ev_tx,
            cmd_rx,
            #[cfg(feature = "gm-pq")]
            cmd_tx: cmd_tx.clone(),
            quic_rx: qrx,
            quic_tx: qtx,
        };
        let actor_handle = tokio::spawn(async move { actor.run().await });
        Ok(Self {
            id,
            cmd: cmd_tx,
            events: ev_rx,
            actor: actor_handle,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.id
    }

    /// Connect to a peer (exchange candidate addresses via the relay and hole punch)
    pub async fn connect_peer(&self, peer: NodeId) {
        let _ = self.cmd.send(NodeCmd::ConnectPeer { peer }).await;
    }

    /// Send an application message (routed over the current preferred path)
    pub async fn send_to(&self, peer: NodeId, payload: Vec<u8>) {
        let _ = self.cmd.send(NodeCmd::SendTo { peer, payload }).await;
    }

    pub async fn next_event(&mut self) -> Option<NodeEvent> {
        self.events.recv().await
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd.send(NodeCmd::Shutdown).await;
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.actor.abort();
    }
}

/// GM-PQ session state machine (driven inside the actor; messages are RelayData payloads)
#[cfg(feature = "gm-pq")]
enum GmState {
    /// We are the server (larger NodeId): KICK sent, waiting for the peer's MSG1
    ServerWaitMsg1,
    /// server: cookie challenge sent, waiting for MSG1_RETRY
    ServerWaitRetry { e_pk: Vec<u8> },
    /// server: MSG2 sent, waiting for MSG3
    ServerWaitMsg3 { resp: gmpq::GmResponder },
    /// client: MSG1 sent, waiting for the cookie challenge
    ClientWaitCookie {
        init: gmpq::GmInitiator,
        e_pk: Vec<u8>,
    },
    /// client: cookie echoed, waiting for MSG2
    ClientWaitMsg2 { init: gmpq::GmInitiator },
    /// Handshake complete (Session ready); BIND sent but not yet verified (waiting for the peer's BIND)
    ReadyUnbound {
        session: gm_pq_stack::handshake::Session,
        peer_gm_pk: Vec<u8>,
    },
    /// BIND verified both ways; the channel is usable
    Ready {
        session: gm_pq_stack::handshake::Session,
    },
}

#[cfg(feature = "gm-pq")]
struct GmPeer {
    state: GmState,
}

/// Unified peer-table entry: session encryption, handshake state, paths, direct connection, probe/loss stats
struct Peer {
    /// Established ephemeral-DH session (forward secrecy, X25519 path)
    session: Option<SessionCipher>,
    /// GM-PQ session (feature gm-pq; preferred over X25519)
    #[cfg(feature = "gm-pq")]
    gm: Option<GmPeer>,
    /// GM-PQ already failed (fell back to X25519; do not retry)
    #[cfg(feature = "gm-pq")]
    gm_failed: bool,
    /// GM-PQ handshake generation (guards stale timeout timers)
    #[cfg(feature = "gm-pq")]
    gm_gen: u64,
    /// Our in-progress handshake as initiator
    hs: Option<HsState>,
    /// Pending inner plaintexts awaiting handshake completion
    pending: VecDeque<Vec<u8>>,
    paths: PathManager,
    /// Direct connection + whether it is outbound (simultaneous-open dedup: both sides converge to one)
    direct: Option<(quinn::Connection, bool)>,
    /// Peer QUIC candidate addresses (connect targets after a successful hole punch)
    quic_cands: Vec<SocketAddr>,
    /// Relay ping in-flight table
    pings: HashMap<u64, Instant>,
    /// Relay loss window (true = pong received)
    ping_outcomes: VecDeque<bool>,
    /// QUIC cumulative counters (for interval loss)
    last_direct_counters: Option<(u64, u64)>, // (sent_packets, lost_packets)
}

impl Peer {
    fn new() -> Self {
        Self {
            session: None,
            #[cfg(feature = "gm-pq")]
            gm: None,
            #[cfg(feature = "gm-pq")]
            gm_failed: false,
            #[cfg(feature = "gm-pq")]
            gm_gen: 0,
            hs: None,
            pending: VecDeque::new(),
            paths: PathManager::new(Instant::now()),
            direct: None,
            quic_cands: Vec::new(),
            pings: HashMap::new(),
            ping_outcomes: VecDeque::new(),
            last_direct_counters: None,
        }
    }

    fn relay_loss_pct(&self) -> f64 {
        if self.ping_outcomes.is_empty() {
            return 0.0;
        }
        let lost = self.ping_outcomes.iter().filter(|&&ok| !ok).count();
        lost as f64 / self.ping_outcomes.len() as f64 * 100.0
    }
}

/// In-progress hole-punch job (actor-built-in scheduling, PUNCH packets dispatched by NodeId)
struct PunchJob {
    machine: PunchMachine,
}

struct Actor {
    identity: NodeIdentity,
    /// GM-PQ identity (SM2+ML-KEM static keypair) and cookie issuer (feature gm-pq)
    #[cfg(feature = "gm-pq")]
    gm_id: Option<gmpq::GmIdentity>,
    #[cfg(feature = "gm-pq")]
    gm_cookie: Option<gmpq::CookieIssuer>,
    cfg: NodeConfig,
    relay: RelayClient,
    punch_sock: Arc<UdpSocket>,
    endpoint: quinn::Endpoint,
    peers: HashMap<NodeId, Peer>,
    punching: HashMap<NodeId, PunchJob>,
    /// Hole-punch reply budget (we reply to late peer packets after we have already completed)
    punch_reply_budget: HashMap<NodeId, u8>,
    ping_seq: u64,
    events: mpsc::Sender<NodeEvent>,
    cmd_rx: mpsc::Receiver<NodeCmd>,
    #[cfg(feature = "gm-pq")]
    cmd_tx: mpsc::Sender<NodeCmd>,
    quic_rx: mpsc::Receiver<QuicEv>,
    quic_tx: mpsc::Sender<QuicEv>,
}

impl Actor {
    async fn emit(&self, ev: NodeEvent) {
        let _ = self.events.send(ev).await;
    }

    fn ensure_peer(&mut self, peer: NodeId) -> &mut Peer {
        self.peers.entry(peer).or_insert_with(Peer::new)
    }

    async fn run(&mut self) {
        let mut punch_buf = [0u8; 2048];
        let mut punch_tick = tokio::time::interval(self.cfg.punch_tick);
        punch_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(NodeCmd::ConnectPeer { peer }) => self.on_connect_peer(peer).await,
                    Some(NodeCmd::SendTo { peer, payload }) => self.on_send_to(peer, payload).await,
                    Some(NodeCmd::ProbeTick) => self.on_probe_tick().await,
                    #[cfg(feature = "gm-pq")]
                    Some(NodeCmd::GmCheck { peer, gen }) => self.on_gm_check(peer, gen).await,
                    Some(NodeCmd::Shutdown) | None => break,
                },
                frame = self.relay.recv() => match frame {
                    Some(f) => self.on_relay_frame(f).await,
                    None => {
                        self.emit(NodeEvent::Log("relay connection dropped".into())).await;
                        break;
                    }
                },
                qev = self.quic_rx.recv() => match qev {
                    Some(QuicEv::Conn(c, outgoing)) => self.on_new_conn(c, outgoing).await,
                    Some(QuicEv::ConnClosed(p, sid)) => self.on_conn_closed(p, sid).await,
                    None => {}
                },
                // Hole-punch socket receive (resident; PUNCH packets dispatched to the matching state machine by sender NodeId)
                recv = self.punch_sock.recv_from(&mut punch_buf) => {
                    if let Ok((n, src)) = recv {
                        if let Some(from) = holepunch::decode_punch_packet(&punch_buf[..n]) {
                            self.on_punch_packet(from, src).await;
                        }
                    }
                }
                // Hole-punch retransmission schedule
                _ = punch_tick.tick() => {
                    self.on_punch_tick().await;
                }
            }
        }
    }

    // ---------- hole-punch scheduling (actor-built-in, safe across concurrent peers) ----------

    fn punch_send(&self, to: SocketAddr) {
        let packet = holepunch::encode_punch_packet(&self.identity.node_id());
        let sock = Arc::clone(&self.punch_sock);
        tokio::spawn(async move {
            let _ = sock.send_to(&packet, to).await;
        });
    }

    async fn apply_punch_actions(&mut self, peer: NodeId, actions: Vec<PunchAction>) {
        for a in actions {
            match a {
                PunchAction::SendPunch(addr) => self.punch_send(addr),
                PunchAction::Established(src) => {
                    self.punching.remove(&peer);
                    self.on_punch_done(peer, Some(src)).await;
                }
                PunchAction::FallbackToRelay => {
                    self.punching.remove(&peer);
                    self.on_punch_done(peer, None).await;
                }
            }
        }
    }

    async fn on_punch_packet(&mut self, from: NodeId, src: SocketAddr) {
        if let Some(job) = self.punching.get_mut(&from) {
            let actions = job.machine.handle(PunchEvent::PacketFrom(src));
            self.apply_punch_actions(from, actions).await;
            return;
        }
        // No matching job (we already completed, or never started): if we know the peer, reply with
        // a PUNCH packet — after our own state machine completes we stop sending periodic packets,
        // and a late peer needs the reply to finish punching.
        // The reply budget prevents infinite ping-pong (one punch during connect is enough).
        if self.peers.contains_key(&from) {
            let left = self.punch_reply_budget.entry(from).or_insert(5);
            if *left > 0 {
                *left -= 1;
                self.punch_send(src);
            }
        }
    }

    async fn on_punch_tick(&mut self) {
        let peers: Vec<NodeId> = self.punching.keys().copied().collect();
        for peer in peers {
            if let Some(job) = self.punching.get_mut(&peer) {
                let actions = job.machine.handle(PunchEvent::Tick);
                self.apply_punch_actions(peer, actions).await;
            }
        }
    }

    // ---------- control plane ----------

    async fn on_connect_peer(&mut self, peer: NodeId) {
        if peer == self.identity.node_id() {
            self.emit(NodeEvent::Log("cannot connect to self".into()))
                .await;
            return;
        }
        self.ensure_peer(peer);
        if self.cfg.enable_punch && !self.punching.contains_key(&peer) {
            if let Err(e) = self.relay.punch_request(peer).await {
                self.emit(NodeEvent::Log(format!("PunchRequest failed: {e}")))
                    .await;
                return;
            }
            self.emit(NodeEvent::PunchStarted { peer }).await;
        }
    }

    async fn on_relay_frame(&mut self, f: Frame) {
        match f {
            Frame::Exchange { peer, cands } => {
                {
                    let p = self.ensure_peer(peer);
                    p.quic_cands = cands
                        .iter()
                        .filter(|(_, k)| *k == CAND_QUIC)
                        .map(|(a, _)| *a)
                        .collect();
                }
                if !self.cfg.enable_punch || self.punching.contains_key(&peer) {
                    return;
                }
                let punch_addrs: Vec<SocketAddr> = cands
                    .iter()
                    .filter(|(_, k)| *k == CAND_PUNCH)
                    .map(|(a, _)| *a)
                    .collect();
                if punch_addrs.is_empty() {
                    self.emit(NodeEvent::Log(format!(
                        "peer has no hole-punch candidate addresses (peer={peer})"
                    )))
                    .await;
                    return;
                }
                let mut machine = PunchMachine::new(self.cfg.punch_max_attempts);
                machine.handle(PunchEvent::Begin);
                let actions = machine.handle(PunchEvent::Candidates(punch_addrs));
                self.punching.insert(peer, PunchJob { machine });
                self.emit(NodeEvent::PunchStarted { peer }).await;
                self.apply_punch_actions(peer, actions).await;
            }
            Frame::RelayData { from, payload, .. } => self.on_relay_data(from, payload).await,
            Frame::Error { msg } => {
                self.emit(NodeEvent::Log(format!("relay error: {msg}")))
                    .await;
            }
            _ => {}
        }
    }

    // ---------- relay data plane (GM-PQ / X25519 dual-stack handshake + ciphertext) ----------

    /// Send inner plaintext: GM-PQ ready > X25519 session > queue and start a handshake
    async fn relay_send_inner(&mut self, pid: NodeId, inner: Vec<u8>) {
        self.ensure_peer(pid);
        // GM-PQ ready channel
        #[cfg(feature = "gm-pq")]
        {
            let gm_ready = matches!(
                self.peers
                    .get(&pid)
                    .and_then(|p| p.gm.as_ref().map(|g| &g.state)),
                Some(GmState::Ready { .. })
            );
            if gm_ready {
                let p = self.peers.get_mut(&pid).unwrap();
                if let Some(GmPeer {
                    state: GmState::Ready { session },
                }) = p.gm.as_mut()
                {
                    let pkt = session.send(&inner);
                    let mut payload = Vec::with_capacity(pkt.len() + 2);
                    payload.extend_from_slice(&[gmpq::GM_TAG, gmpq::GM_DATA]);
                    payload.extend_from_slice(&pkt);
                    let _ = self.relay.send_data(pid, payload).await;
                }
                return;
            }
        }
        let p = self.peers.get_mut(&pid).unwrap();
        if let Some(sess) = p.session.as_mut() {
            match sess.seal(&inner) {
                Ok(ct) => {
                    let _ = self.relay.send_data(pid, ct).await;
                }
                Err(e) => {
                    let msg = format!("encryption failed: {e}");
                    let _ = self.events.send(NodeEvent::Log(msg)).await;
                }
            }
            return;
        }
        // No usable session: queue + start a handshake (GM-PQ preferred, X25519 fallback)
        p.pending.push_back(inner);
        #[cfg(feature = "gm-pq")]
        {
            if self.cfg.gmpq && !p.gm_failed && self.gm_id.is_some() {
                if p.gm.is_none() {
                    self.gm_start(pid).await;
                }
                return;
            }
        }
        let p = self.peers.get_mut(&pid).unwrap();
        if p.hs.is_none() {
            let (hs, msg) = crypto::hs_start(&self.identity, &pid);
            p.hs = Some(hs);
            let _ = self.relay.send_data(pid, msg).await; // plaintext handshake (public key + signature)
        }
    }

    /// Flush the pending queue once the session is ready (triggered by GM-PQ or X25519)
    async fn flush_pending(&mut self, pid: NodeId) {
        let pending: Vec<Vec<u8>> = {
            let p = self.peers.get_mut(&pid).unwrap();
            p.pending.drain(..).collect()
        };
        for inner in pending {
            self.relay_send_inner(pid, inner).await;
        }
    }

    /// Unified dispatch for decrypted inner plaintext (shared by the X25519 and GM-PQ channels)
    async fn on_plain_inner(&mut self, from: NodeId, inner: Vec<u8>) {
        match inner.first().copied() {
            Some(INNER_DATA) => {
                self.emit(NodeEvent::Message {
                    from,
                    via: PathKind::Relay,
                    payload: inner[1..].to_vec(),
                })
                .await;
            }
            Some(INNER_PING) if inner.len() >= 9 => {
                let mut pong = vec![INNER_PONG];
                pong.extend_from_slice(&inner[1..9]);
                self.relay_send_inner(from, pong).await;
            }
            Some(INNER_PONG) if inner.len() >= 9 => {
                let id = u64::from_be_bytes(inner[1..9].try_into().unwrap());
                let p = self.peers.get_mut(&from).unwrap();
                if let Some(t0) = p.pings.remove(&id) {
                    let rtt = t0.elapsed();
                    let rtt_ms = rtt.as_secs_f64() * 1000.0;
                    if p.ping_outcomes.len() >= LOSS_WINDOW {
                        p.ping_outcomes.pop_front();
                    }
                    p.ping_outcomes.push_back(true);
                    let loss = p.relay_loss_pct() / 100.0;
                    let sw = p.paths.on_sample(
                        PathKind::Relay,
                        PathSample {
                            rtt: Some(rtt),
                            loss: Some(loss),
                        },
                        Instant::now(),
                    );
                    let loss_pct = loss * 100.0;
                    self.emit(NodeEvent::RttSample {
                        peer: from,
                        path: PathKind::Relay,
                        rtt_ms,
                        loss_pct,
                    })
                    .await;
                    if let Some(sw) = sw {
                        self.emit(NodeEvent::PathSwitch {
                            peer: from,
                            from: sw.from,
                            to: sw.to,
                        })
                        .await;
                    }
                }
            }
            _ => {}
        }
    }

    async fn on_relay_data(&mut self, from: NodeId, payload: Vec<u8>) {
        self.ensure_peer(from);
        // GM-PQ channel frame
        #[cfg(feature = "gm-pq")]
        if payload.first() == Some(&gmpq::GM_TAG) {
            let kind = payload.get(1).copied().unwrap_or(0);
            self.on_gm_frame(from, kind, &payload[2..]).await;
            return;
        }
        // X25519 plaintext handshake message
        if payload.first() == Some(&HS_TAG) {
            match payload.get(1).copied() {
                Some(HS_KIND_INIT) => {
                    let me = self.identity.node_id();
                    let p = self.peers.get_mut(&from).unwrap();
                    if p.session.is_some() {
                        return; // session already exists; ignore a duplicate init
                    }
                    // Simultaneous initiation: the side with the smaller NodeId is the initiator;
                    // the larger side drops its own handshake
                    if p.hs.is_some() && me < from {
                        return;
                    }
                    match crypto::hs_accept(&self.identity, &from, &payload) {
                        Ok((cipher, resp)) => {
                            let p = self.peers.get_mut(&from).unwrap();
                            p.session = Some(cipher);
                            p.hs = None;
                            let _ = self.relay.send_data(from, resp).await;
                            self.emit(NodeEvent::SessionReady {
                                peer: from,
                                suite: "x25519+ed25519",
                            })
                            .await;
                            self.flush_pending(from).await;
                        }
                        Err(e) => {
                            self.emit(NodeEvent::Log(format!("handshake init rejected: {e}")))
                                .await;
                        }
                    }
                }
                Some(HS_KIND_RESP) => {
                    let p = self.peers.get_mut(&from).unwrap();
                    if p.session.is_some() {
                        return;
                    }
                    let Some(hs) = p.hs.take() else { return };
                    match crypto::hs_finish(&self.identity, hs, &payload) {
                        Ok(cipher) => {
                            let p = self.peers.get_mut(&from).unwrap();
                            p.session = Some(cipher);
                            self.emit(NodeEvent::SessionReady {
                                peer: from,
                                suite: "x25519+ed25519",
                            })
                            .await;
                            self.flush_pending(from).await;
                        }
                        Err(e) => {
                            self.emit(NodeEvent::Log(format!("handshake resp rejected: {e}")))
                                .await;
                        }
                    }
                }
                _ => {
                    self.emit(NodeEvent::Log("unknown handshake message".into()))
                        .await;
                }
            }
            return;
        }
        // AEAD ciphertext (X25519 session)
        let p = self.peers.get_mut(&from).unwrap();
        let Some(sess) = p.session.as_mut() else {
            self.emit(NodeEvent::Log(
                "ciphertext arrived before the handshake completed; dropping".into(),
            ))
            .await;
            return;
        };
        let inner = match sess.open(&payload) {
            Ok(p) => p,
            Err(e) => {
                self.emit(NodeEvent::Log(format!(
                    "relay ciphertext decrypt failed: {e}"
                )))
                .await;
                return;
            }
        };
        self.on_plain_inner(from, inner).await;
    }

    // ---------- direct path ----------

    async fn on_punch_done(&mut self, peer: NodeId, addr: Option<SocketAddr>) {
        match addr {
            Some(src) => {
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.paths.on_direct_up();
                }
                self.emit(NodeEvent::PunchResult {
                    peer,
                    direct: Some(src),
                })
                .await;
                // Pick the QUIC connect target: prefer the QUIC candidate sharing the punched IP
                let target = {
                    let p = self.peers.get(&peer).unwrap();
                    p.quic_cands
                        .iter()
                        .copied()
                        .find(|a| a.ip() == src.ip())
                        .or_else(|| p.quic_cands.first().copied())
                };
                let Some(target) = target else {
                    self.emit(NodeEvent::Log(format!(
                        "peer has no QUIC candidate addresses (peer={peer})"
                    )))
                    .await;
                    return;
                };
                // simultaneous-open: both sides connect to each other's QUIC candidate address
                let ep = self.endpoint.clone();
                let id = self.identity.clone();
                let qtx = self.quic_tx.clone();
                tokio::spawn(async move {
                    match quic::simultaneous_open(
                        &ep,
                        &id,
                        peer,
                        target,
                        8,
                        Duration::from_millis(200),
                    )
                    .await
                    {
                        Ok(conn) => {
                            let _ = qtx.send(QuicEv::Conn(conn, true)).await;
                        }
                        Err(_) => {}
                    }
                });
            }
            None => {
                self.emit(NodeEvent::PunchResult { peer, direct: None })
                    .await;
                self.emit(NodeEvent::Log(format!(
                    "hole punching timed out, falling back to relay (peer={peer})"
                )))
                .await;
            }
        }
    }

    async fn on_new_conn(&mut self, conn: quinn::Connection, outgoing: bool) {
        let Some(peer_id) = quic::conn_peer_id(&conn) else {
            conn.close(0u32.into(), b"no identity");
            return;
        };
        self.ensure_peer(peer_id);
        // simultaneous-open dedup: both sides converge by the same rule —
        // the smaller NodeId's outbound connection is the canonical one; the rest close
        let prefer_outgoing = self.identity.node_id() < peer_id;
        let peer = self.peers.get_mut(&peer_id).unwrap();
        let first = peer.direct.is_none();
        if let Some((old, old_outgoing)) = &peer.direct {
            let old_preferred = *old_outgoing == prefer_outgoing;
            let new_preferred = outgoing == prefer_outgoing;
            if old_preferred || !new_preferred {
                conn.close(0u32.into(), b"duplicate");
                return;
            }
            // The new connection is the canonical one: replace and close the old one
            old.close(0u32.into(), b"superseded");
        }
        peer.paths.on_direct_up();
        peer.direct = Some((conn.clone(), outgoing));
        if first {
            self.emit(NodeEvent::DirectReady { peer: peer_id }).await;
        }
        // Stream read loop
        let sid = conn.stable_id();
        let ev_tx = self.events.clone();
        let qtx = self.quic_tx.clone();
        tokio::spawn(async move {
            loop {
                match conn.accept_bi().await {
                    Ok((_send, recv)) => {
                        let ev_tx = ev_tx.clone();
                        tokio::spawn(async move {
                            if let Ok(payload) = quic::read_msg(recv).await {
                                let _ = ev_tx
                                    .send(NodeEvent::Message {
                                        from: peer_id,
                                        via: PathKind::Direct,
                                        payload,
                                    })
                                    .await;
                            }
                        });
                    }
                    Err(_) => {
                        let _ = qtx.send(QuicEv::ConnClosed(peer_id, sid)).await;
                        break;
                    }
                }
            }
        });
    }

    async fn on_conn_closed(&mut self, peer: NodeId, sid: usize) {
        if let Some(p) = self.peers.get_mut(&peer) {
            // Only clear the currently-held connection (a replaced old connection's close must not clear it)
            let current = p.direct.as_ref().map(|(c, _)| c.stable_id());
            if current == Some(sid) {
                p.direct = None;
                if let Some(sw) = p.paths.on_direct_down(Instant::now()) {
                    self.emit(NodeEvent::PathSwitch {
                        peer,
                        from: sw.from,
                        to: sw.to,
                    })
                    .await;
                }
            }
        }
    }

    async fn on_send_to(&mut self, peer: NodeId, payload: Vec<u8>) {
        self.ensure_peer(peer);
        let active = self.peers.get(&peer).unwrap().paths.active();
        if active == PathKind::Direct {
            let conn = self
                .peers
                .get(&peer)
                .and_then(|p| p.direct.as_ref().map(|(c, _)| c.clone()));
            if let Some(conn) = conn {
                match quic::write_msg(&conn, &payload).await {
                    Ok(()) => return,
                    Err(e) => {
                        // Direct failed: immediately fall back to the relay (seamless switch semantics)
                        self.emit(NodeEvent::Log(format!(
                            "direct send failed, falling back to relay: {e}"
                        )))
                        .await;
                        let p = self.peers.get_mut(&peer).unwrap();
                        p.direct = None;
                        if let Some(sw) = p.paths.on_direct_down(Instant::now()) {
                            self.emit(NodeEvent::PathSwitch {
                                peer,
                                from: sw.from,
                                to: sw.to,
                            })
                            .await;
                        }
                    }
                }
            }
        }
        // Relay path (temporary-DH-session AEAD encryption; if not ready, queue and handshake first)
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.push(INNER_DATA);
        inner.extend_from_slice(&payload);
        self.relay_send_inner(peer, inner).await;
    }

    async fn on_probe_tick(&mut self) {
        let mut pending_events: Vec<NodeEvent> = Vec::new();
        let peer_ids: Vec<NodeId> = self.peers.keys().copied().collect();
        for pid in peer_ids {
            // Direct path: QUIC carries its own RTT + loss counters (interval difference)
            let direct_sample = self
                .peers
                .get(&pid)
                .and_then(|p| p.direct.as_ref().map(|(c, _)| c.stats()));
            if let Some(stats) = direct_sample {
                let p = self.peers.get_mut(&pid).unwrap();
                let (sent, lost) = (stats.path.sent_packets, stats.path.lost_packets);
                let interval_loss = match p.last_direct_counters {
                    Some((s0, l0)) => {
                        let ds = sent.saturating_sub(s0);
                        let dl = lost.saturating_sub(l0);
                        if ds > 0 {
                            dl as f64 / ds as f64
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };
                p.last_direct_counters = Some((sent, lost));
                let rtt = stats.path.rtt;
                let sw = p.paths.on_sample(
                    PathKind::Direct,
                    PathSample {
                        rtt: Some(rtt),
                        loss: Some(interval_loss),
                    },
                    Instant::now(),
                );
                pending_events.push(NodeEvent::RttSample {
                    peer: pid,
                    path: PathKind::Direct,
                    rtt_ms: rtt.as_secs_f64() * 1000.0,
                    loss_pct: interval_loss * 100.0,
                });
                if let Some(sw) = sw {
                    pending_events.push(NodeEvent::PathSwitch {
                        peer: pid,
                        from: sw.from,
                        to: sw.to,
                    });
                }
            }
            // Relay path: expired pings count as loss; send a new ping (skip probing if the session is not ready)
            let expired: Vec<u64> = {
                let p = self.peers.get(&pid).unwrap();
                let limit = self.cfg.probe_interval * 3;
                p.pings
                    .iter()
                    .filter(|(_, t0)| t0.elapsed() > limit)
                    .map(|(id, _)| *id)
                    .collect()
            };
            if !expired.is_empty() {
                let p = self.peers.get_mut(&pid).unwrap();
                for id in expired {
                    p.pings.remove(&id);
                    if p.ping_outcomes.len() >= LOSS_WINDOW {
                        p.ping_outcomes.pop_front();
                    }
                    p.ping_outcomes.push_back(false);
                }
            }
            let p = self.peers.get(&pid).unwrap();
            let has_session = p.session.is_some();
            #[cfg(feature = "gm-pq")]
            let has_session = has_session
                || matches!(p.gm.as_ref().map(|g| &g.state), Some(GmState::Ready { .. }));
            if has_session {
                self.ping_seq += 1;
                let id = self.ping_seq;
                let mut ping = vec![INNER_PING];
                ping.extend_from_slice(&id.to_be_bytes());
                let p = self.peers.get_mut(&pid).unwrap();
                p.pings.insert(id, Instant::now());
                self.relay_send_inner(pid, ping).await;
            }
        }
        for ev in pending_events {
            self.emit(ev).await;
        }
    }
}

// ---------- GM-PQ channel (feature gm-pq): the state machine is driven directly by the actor ----------
//
// Messages are RelayData payloads: `[GM_TAG, subtype] || body`. Role rule: the smaller NodeId is
// the client (initiator), the larger is the server (responder). On peer lack of support or timeout
// (3s), fall back to X25519.

#[cfg(feature = "gm-pq")]
impl Actor {
    /// Send one GM-PQ channel frame via the relay
    async fn gm_send(&mut self, peer: NodeId, kind: u8, body: &[u8]) {
        let mut payload = Vec::with_capacity(body.len() + 2);
        payload.extend_from_slice(&[gmpq::GM_TAG, kind]);
        payload.extend_from_slice(body);
        let _ = self.relay.send_data(peer, payload).await;
    }

    /// Start the GM-PQ handshake (idempotent: no duplicate start when state already exists)
    async fn gm_start(&mut self, peer: NodeId) {
        let me = self.identity.node_id();
        let Some(gm) = self.gm_id.as_ref() else {
            return;
        };
        {
            let p = self.peers.get(&peer).unwrap();
            if p.gm.is_some() || p.gm_failed {
                return;
            }
        }
        if me < peer {
            // We are the client: send MSG1
            let mut init = gmpq::GmInitiator::new(gm.sk.clone(), gm.pk.clone());
            let mut rng = gmpq::new_rng();
            match init.write_msg1(&mut rng) {
                Ok(e_pk) => {
                    let p = self.peers.get_mut(&peer).unwrap();
                    p.gm = Some(GmPeer {
                        state: GmState::ClientWaitCookie {
                            init,
                            e_pk: e_pk.clone(),
                        },
                    });
                    self.gm_send(peer, gmpq::GM_MSG1, &e_pk).await;
                }
                Err(_) => {
                    self.peers.get_mut(&peer).unwrap().gm_failed = true;
                }
            }
        } else {
            // We are the server: send a KICK to wake the peer, wait for MSG1
            let p = self.peers.get_mut(&peer).unwrap();
            p.gm = Some(GmPeer {
                state: GmState::ServerWaitMsg1,
            });
            self.gm_send(peer, gmpq::GM_KICK, &[]).await;
        }
        // Handshake timeout -> fall back to X25519
        let gen = {
            let p = self.peers.get_mut(&peer).unwrap();
            p.gm_gen += 1;
            p.gm_gen
        };
        let cmd = self.cmd_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _ = cmd.send(NodeCmd::GmCheck { peer, gen }).await;
        });
    }

    /// GM-PQ timeout check: if not ready, discard and fall back to X25519 (pending preserved)
    async fn on_gm_check(&mut self, peer: NodeId, gen: u64) {
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        if p.gm_gen != gen {
            return; // stale timer
        }
        let ready = matches!(p.gm.as_ref().map(|g| &g.state), Some(GmState::Ready { .. }));
        if ready || p.gm.is_none() {
            return;
        }
        p.gm = None;
        p.gm_failed = true;
        self.emit(NodeEvent::Log(format!(
            "GM-PQ handshake timed out, falling back to X25519+ed25519 (peer={peer})"
        )))
        .await;
        // Start a supplementary X25519 handshake if pending is backlogged
        let need_hs = {
            let p = self.peers.get(&peer).unwrap();
            !p.pending.is_empty() && p.hs.is_none() && p.session.is_none()
        };
        if need_hs {
            let (hs, msg) = crypto::hs_start(&self.identity, &peer);
            let p = self.peers.get_mut(&peer).unwrap();
            p.hs = Some(hs);
            let _ = self.relay.send_data(peer, msg).await;
        }
    }

    /// GM-PQ channel frame dispatch
    async fn on_gm_frame(&mut self, from: NodeId, kind: u8, body: &[u8]) {
        // Not enabled / no identity: ignore (the peer will time out and fall back to X25519)
        if !self.cfg.gmpq || self.gm_id.is_none() {
            return;
        }
        let me = self.identity.node_id();
        match kind {
            gmpq::GM_KICK => {
                // Peer woke us: as the smaller NodeId we initiate as client
                let p = self.peers.get(&from).unwrap();
                if p.gm.is_none() && !p.gm_failed {
                    if me < from {
                        self.gm_start(from).await;
                    } else {
                        // We are the server: enter wait-for-MSG1
                        self.peers.get_mut(&from).unwrap().gm = Some(GmPeer {
                            state: GmState::ServerWaitMsg1,
                        });
                    }
                }
            }
            gmpq::GM_MSG1 => {
                if me < from {
                    return; // role violation: the smaller NodeId must not receive MSG1
                }
                let p = self.peers.get_mut(&from).unwrap();
                if p.gm.is_some()
                    && !matches!(p.gm.as_ref().unwrap().state, GmState::ServerWaitMsg1)
                {
                    return; // already in progress
                }
                let cookie = self
                    .gm_cookie
                    .as_ref()
                    .unwrap()
                    .issue(from.as_bytes(), body);
                p.gm = Some(GmPeer {
                    state: GmState::ServerWaitRetry {
                        e_pk: body.to_vec(),
                    },
                });
                self.gm_send(from, gmpq::GM_COOKIE, &cookie).await;
            }
            gmpq::GM_COOKIE => {
                let Some(GmPeer {
                    state: GmState::ClientWaitCookie { init, e_pk },
                }) = self.peers.get_mut(&from).unwrap().gm.take()
                else {
                    return;
                };
                let mut retry = body.to_vec();
                retry.extend_from_slice(&e_pk);
                self.peers.get_mut(&from).unwrap().gm = Some(GmPeer {
                    state: GmState::ClientWaitMsg2 { init },
                });
                self.gm_send(from, gmpq::GM_MSG1_RETRY, &retry).await;
            }
            gmpq::GM_MSG1_RETRY => {
                use gm_pq_stack::handshake::cookie::COOKIE_LEN;
                let Some(GmPeer {
                    state: GmState::ServerWaitRetry { e_pk },
                }) = self.peers.get_mut(&from).unwrap().gm.take()
                else {
                    return;
                };
                let verified = (|| {
                    if body.len() < COOKIE_LEN {
                        return None;
                    }
                    let (echo, e_pk2) = body.split_at(COOKIE_LEN);
                    if e_pk2 != e_pk.as_slice() {
                        return None;
                    }
                    self.gm_cookie
                        .as_ref()
                        .unwrap()
                        .verify(from.as_bytes(), &e_pk, echo)
                        .ok()?;
                    Some(e_pk)
                })();
                let Some(e_pk) = verified else {
                    self.emit(NodeEvent::Log("GM-PQ cookie verification failed".into()))
                        .await;
                    return;
                };
                let gm = self.gm_id.as_ref().unwrap();
                let mut resp = gmpq::GmResponder::new(gm.sk.clone(), gm.pk.clone());
                let mut rng = gmpq::new_rng();
                let m2 = resp
                    .read_msg1(&e_pk)
                    .and_then(|_| resp.write_msg2(&mut rng));
                match m2 {
                    Ok(m2) => {
                        self.peers.get_mut(&from).unwrap().gm = Some(GmPeer {
                            state: GmState::ServerWaitMsg3 { resp },
                        });
                        self.gm_send(from, gmpq::GM_MSG2, &m2).await;
                    }
                    Err(e) => {
                        self.emit(NodeEvent::Log(format!("GM-PQ msg1 handling failed: {e}")))
                            .await;
                    }
                }
            }
            gmpq::GM_MSG2 => {
                let Some(GmPeer {
                    state: GmState::ClientWaitMsg2 { mut init },
                }) = self.peers.get_mut(&from).unwrap().gm.take()
                else {
                    return;
                };
                let mut rng = gmpq::new_rng();
                let res = init
                    .read_msg2(body)
                    .and_then(|_| init.write_msg3_with_auth(&mut rng, &gmpq::AllowAllAnchor));
                match res {
                    Ok((m3, session)) => {
                        let peer_gm_pk = init.peer_static().unwrap_or_default().to_vec();
                        // Session ready: immediately send BIND to complete identity binding
                        let bind = gmpq::build_bind(
                            &self.identity,
                            &self.gm_id.as_ref().unwrap().pk,
                            session.session_id(),
                        );
                        let mut sess = session;
                        let pkt = sess.send(&bind);
                        self.peers.get_mut(&from).unwrap().gm = Some(GmPeer {
                            state: GmState::ReadyUnbound {
                                session: sess,
                                peer_gm_pk,
                            },
                        });
                        self.gm_send(from, gmpq::GM_MSG3, &m3).await;
                        // BIND as the first session ciphertext
                        let mut payload = Vec::with_capacity(pkt.len() + 2);
                        payload.extend_from_slice(&[gmpq::GM_TAG, gmpq::GM_DATA]);
                        payload.extend_from_slice(&pkt);
                        let _ = self.relay.send_data(from, payload).await;
                    }
                    Err(e) => {
                        self.emit(NodeEvent::Log(format!("GM-PQ msg2 handling failed: {e}")))
                            .await;
                    }
                }
            }
            gmpq::GM_MSG3 => {
                let Some(GmPeer {
                    state: GmState::ServerWaitMsg3 { mut resp },
                }) = self.peers.get_mut(&from).unwrap().gm.take()
                else {
                    return;
                };
                match resp.read_msg3_with_auth(body, &gmpq::AllowAllAnchor) {
                    Ok((mut session, client_pk)) => {
                        let bind = gmpq::build_bind(
                            &self.identity,
                            &self.gm_id.as_ref().unwrap().pk,
                            session.session_id(),
                        );
                        let pkt = session.send(&bind);
                        self.peers.get_mut(&from).unwrap().gm = Some(GmPeer {
                            state: GmState::ReadyUnbound {
                                session,
                                peer_gm_pk: client_pk,
                            },
                        });
                        let mut payload = Vec::with_capacity(pkt.len() + 2);
                        payload.extend_from_slice(&[gmpq::GM_TAG, gmpq::GM_DATA]);
                        payload.extend_from_slice(&pkt);
                        let _ = self.relay.send_data(from, payload).await;
                    }
                    Err(e) => {
                        self.emit(NodeEvent::Log(format!("GM-PQ msg3 rejected: {e}")))
                            .await;
                    }
                }
            }
            gmpq::GM_DATA => {
                // Take out the session and decrypt; once BIND verifies, transition to Ready and flush pending
                enum Out {
                    Bound,
                    Plain(Vec<u8>),
                    Drop(&'static str),
                    Ignore,
                }
                let out = {
                    let p = self.peers.get_mut(&from).unwrap();
                    match p.gm.as_mut() {
                        Some(GmPeer {
                            state:
                                GmState::ReadyUnbound {
                                    session,
                                    peer_gm_pk,
                                },
                        }) => match session.recv(body) {
                            Ok(pt) if pt.starts_with(gmpq::BIND_PREFIX) => {
                                match gmpq::parse_bind(&pt, &from, peer_gm_pk, session.session_id())
                                {
                                    Ok(_) => Out::Bound,
                                    Err(e) => Out::Drop(e),
                                }
                            }
                            Ok(_) => Out::Drop("data received before BIND"),
                            Err(_) => Out::Drop("GM-PQ decryption failed"),
                        },
                        Some(GmPeer {
                            state: GmState::Ready { session },
                        }) => match session.recv(body) {
                            Ok(pt) => Out::Plain(pt),
                            Err(_) => Out::Drop("GM-PQ decryption failed/replay"),
                        },
                        _ => Out::Ignore,
                    }
                };
                match out {
                    Out::Bound => {
                        // Transition state to Ready
                        let p = self.peers.get_mut(&from).unwrap();
                        if let Some(mut gp) = p.gm.take() {
                            if let GmState::ReadyUnbound { session, .. } = gp.state {
                                gp.state = GmState::Ready { session };
                                p.gm = Some(gp);
                            }
                        }
                        self.emit(NodeEvent::SessionReady {
                            peer: from,
                            suite: "sm2+ml-kem-768+sm4-gcm",
                        })
                        .await;
                        self.flush_pending(from).await;
                    }
                    Out::Plain(pt) => self.on_plain_inner(from, pt).await,
                    Out::Drop(e) => {
                        self.emit(NodeEvent::Log(format!("GM-PQ dropped: {e} (peer={from})")))
                            .await;
                    }
                    Out::Ignore => {}
                }
            }
            _ => {}
        }
    }
}
