//! Relay client: the node-side session connecting to the relay

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::identity::NodeId;
use crate::proto::{read_frame, write_frame, Frame};

pub struct RelayClient {
    node_id: NodeId,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    rx: mpsc::Receiver<Frame>,
    reader: tokio::task::JoinHandle<()>,
}

impl RelayClient {
    /// Connect and register (Hello/HelloAck handshake); returns (client, the local address observed by the relay)
    pub async fn connect(
        relay_addr: SocketAddr,
        node_id: NodeId,
        cands: crate::proto::Candidates,
    ) -> io::Result<(Self, SocketAddr)> {
        let stream = TcpStream::connect(relay_addr).await?;
        stream.set_nodelay(true).ok();
        let (mut rd, wr) = stream.into_split();
        let writer = Arc::new(Mutex::new(wr));
        write_frame(&mut *writer.lock().await, &Frame::Hello { node_id, cands }).await?;
        // Synchronously wait for HelloAck (no other frames can arrive on the connection yet)
        let observed = match read_frame(&mut rd).await? {
            Some(Frame::HelloAck { observed }) => observed,
            Some(Frame::Error { msg }) => {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, msg))
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected HelloAck, got {:?}", other),
                ))
            }
        };
        let (tx, rx) = mpsc::channel(256);
        let reader = tokio::spawn(async move {
            let mut rd = rd;
            loop {
                match read_frame(&mut rd).await {
                    Ok(Some(f)) => {
                        if tx.send(f).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });
        Ok((
            Self {
                node_id,
                writer,
                rx,
                reader,
            },
            observed,
        ))
    }

    /// Update candidate addresses (re-register after learning the observed address)
    pub async fn update_addrs(&self, cands: crate::proto::Candidates) -> io::Result<()> {
        write_frame(
            &mut *self.writer.lock().await,
            &Frame::Hello {
                node_id: self.node_id,
                cands,
            },
        )
        .await
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub async fn punch_request(&self, target: NodeId) -> io::Result<()> {
        write_frame(
            &mut *self.writer.lock().await,
            &Frame::PunchRequest { target },
        )
        .await
    }

    /// Send via the relay (the payload MUST be end-to-end ciphertext)
    pub async fn send_data(&self, to: NodeId, payload: Vec<u8>) -> io::Result<()> {
        write_frame(
            &mut *self.writer.lock().await,
            &Frame::RelayData {
                to,
                from: self.node_id,
                payload,
            },
        )
        .await
    }

    pub async fn stats_query(&self) -> io::Result<()> {
        write_frame(&mut *self.writer.lock().await, &Frame::StatsQuery).await
    }

    /// Receive the next frame; returns None when the connection drops
    pub async fn recv(&mut self) -> Option<Frame> {
        self.rx.recv().await
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
