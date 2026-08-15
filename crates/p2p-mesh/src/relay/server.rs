//! Relay server: registered sessions, hole-punch brokering (Exchange cross-send), ciphertext forwarding, traffic metering

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::identity::NodeId;
use crate::proto::{read_frame, write_frame, Frame};

/// Per-node traffic counters
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeTraffic {
    /// Node uplink bytes (received by the relay)
    pub up_bytes: u64,
    /// Node downlink bytes (sent by the relay)
    pub down_bytes: u64,
    /// Relayed messages
    pub relayed_msgs: u64,
}

struct Session {
    tx: mpsc::Sender<Frame>,
    cands: crate::proto::Candidates,
}

#[derive(Default)]
struct ServerState {
    sessions: HashMap<NodeId, Session>,
    stats: HashMap<NodeId, NodeTraffic>,
}

pub struct RelayServer {
    listener: TcpListener,
    state: Arc<Mutex<ServerState>>,
}

impl RelayServer {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            state: Arc::new(Mutex::new(ServerState::default())),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Lightweight stats handle (still queryable after serve() takes ownership)
    pub fn handle(&self) -> RelayHandle {
        RelayHandle { state: Arc::clone(&self.state) }
    }

    /// Traffic stats snapshot
    pub fn stats(&self) -> HashMap<NodeId, NodeTraffic> {
        self.state.lock().unwrap().stats.clone()
    }

    /// Number of online nodes
    pub fn online(&self) -> usize {
        self.state.lock().unwrap().sessions.len()
    }

    pub fn stats_text(&self) -> String {
        let st = self.state.lock().unwrap();
        let mut s = format!("online={} nodes={}", st.sessions.len(), st.stats.len());
        for (id, t) in &st.stats {
            s.push_str(&format!(
                "\n  {}: up={}B down={}B msgs={}",
                id, t.up_bytes, t.down_bytes, t.relayed_msgs
            ));
        }
        s
    }

    /// Run the accept loop (does not return unless the listener errors)
    pub async fn serve(self) -> io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            stream.set_nodelay(true).ok();
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, state).await {
                    eprintln!("[relay] {} session ended: {}", peer, e);
                }
            });
        }
    }
}

async fn handle_conn(stream: TcpStream, state: Arc<Mutex<ServerState>>) -> io::Result<()> {
    let peer_addr = stream.peer_addr().ok();
    let (mut rd, mut wr) = stream.into_split();
    // One write channel per connection: other relay handlers push frames back through it
    let (tx, mut rx) = mpsc::channel::<Frame>(256);
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if write_frame(&mut wr, &f).await.is_err() {
                break;
            }
        }
        wr.shutdown().await.ok();
    });

    // The first frame must be Hello (register NodeId + candidate addresses)
    let me = match read_frame(&mut rd).await? {
        Some(Frame::Hello { node_id, cands }) => {
            state
                .lock()
                .unwrap()
                .sessions
                .insert(node_id, Session { tx: tx.clone(), cands });
            state.lock().unwrap().stats.entry(node_id).or_default();
            // STUN-like: echo the observed peer address
            write_frame_chan(
                &tx,
                Frame::HelloAck {
                    observed: peer_addr.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
                },
            )
            .await;
            node_id
        }
        _ => {
            write_frame_chan(&tx, Frame::Error { msg: "first frame must be Hello".into() }).await;
            drop(tx);
            writer.await.ok();
            return Ok(());
        }
    };

    // Main loop
    while let Some(f) = read_frame(&mut rd).await? {
        match f {
            // Re-registration: the node updates its candidate list after learning the observed address
            Frame::Hello { node_id, cands } if node_id == me => {
                if let Some(s) = state.lock().unwrap().sessions.get_mut(&me) {
                    s.cands = cands;
                }
            }
            Frame::PunchRequest { target } => {
                // Broker: cross-send both sides' candidate addresses
                let (my_cands, target_tx, target_cands) = {
                    let st = state.lock().unwrap();
                    let my = st.sessions.get(&me).map(|s| s.cands.clone()).unwrap_or_default();
                    let tgt = st.sessions.get(&target);
                    (
                        my,
                        tgt.map(|s| s.tx.clone()),
                        tgt.map(|s| s.cands.clone()),
                    )
                };
                match (target_tx, target_cands) {
                    (Some(ttx), Some(taddrs)) => {
                        write_frame_chan(&tx, Frame::Exchange { peer: target, cands: taddrs }).await;
                        write_frame_chan(&ttx, Frame::Exchange { peer: me, cands: my_cands }).await;
                    }
                    _ => {
                        write_frame_chan(&tx, Frame::Error { msg: "target is not online".into() }).await;
                    }
                }
            }
            Frame::RelayData { to, payload, .. } => {
                let from = me; // anti-spoofing: `from` is taken from the connection identity
                let n = payload.len() as u64;
                let target_tx = state.lock().unwrap().sessions.get(&to).map(|s| s.tx.clone());
                match target_tx {
                    Some(ttx) => {
                        {
                            let mut st = state.lock().unwrap();
                            let up = st.stats.entry(me).or_default();
                            up.up_bytes += n;
                            up.relayed_msgs += 1;
                            let down = st.stats.entry(to).or_default();
                            down.down_bytes += n;
                        }
                        write_frame_chan(&ttx, Frame::RelayData { to, from, payload }).await;
                    }
                    None => {
                        write_frame_chan(&tx, Frame::Error { msg: "recipient is not online".into() }).await;
                    }
                }
            }
            Frame::StatsQuery => {
                let text = {
                    let st = state.lock().unwrap();
                    let mut s = String::new();
                    for (id, t) in &st.stats {
                        s.push_str(&format!(
                            "{} up={}B down={}B msgs={}\n",
                            id, t.up_bytes, t.down_bytes, t.relayed_msgs
                        ));
                    }
                    s
                };
                write_frame_chan(&tx, Frame::StatsReport { text }).await;
            }
            _ => {}
        }
    }

    // Connection closed: unregister the session
    state.lock().unwrap().sessions.remove(&me);
    drop(tx);
    writer.await.ok();
    Ok(())
}

async fn write_frame_chan(tx: &mpsc::Sender<Frame>, f: Frame) {
    let _ = tx.send(f).await;
}

/// Stats handle (cheap to clone; usable across tasks)
#[derive(Clone)]
pub struct RelayHandle {
    state: Arc<Mutex<ServerState>>,
}

impl RelayHandle {
    pub fn stats_text(&self) -> String {
        let st = self.state.lock().unwrap();
        let mut s = format!("online={} nodes={}", st.sessions.len(), st.stats.len());
        for (id, t) in &st.stats {
            s.push_str(&format!(
                "\n  {}: up={}B down={}B msgs={}",
                id, t.up_bytes, t.down_bytes, t.relayed_msgs
            ));
        }
        s
    }
}
