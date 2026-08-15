//! Relay wire protocol: length-framed tagged payloads over TCP (hand-written binary, zero serde dependency)
//!
//! Frame format: `u32be total-length (including tag) | u8 tag | payload`
//! All frames have a plaintext protocol header for the relay; application data (RelayData.payload)
//! is end-to-end ciphertext (session handshake messages are plaintext public keys + signatures —
//! public material, no confidentiality needed).
//!
//! Candidate addresses carry a type tag: CAND_PUNCH (socket for hole-punch probing) / CAND_QUIC (socket for QUIC direct connections).

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::identity::NodeId;

pub const TAG_HELLO: u8 = 1; // register: node_id + candidate addresses (for hole punching)
pub const TAG_HELLO_ACK: u8 = 2; // echo the observed address (STUN-like)
pub const TAG_PUNCH_REQ: u8 = 3; // request relay-brokered hole punching to a target
pub const TAG_EXCHANGE: u8 = 4; // relay -> both sides: peer node_id + candidate addresses
pub const TAG_RELAY_DATA: u8 = 5; // relayed data: to/from + ciphertext payload
pub const TAG_STATS_QUERY: u8 = 6;
pub const TAG_STATS_REPORT: u8 = 7;
pub const TAG_ERROR: u8 = 255;

/// Candidate address type: hole-punch probe socket
pub const CAND_PUNCH: u8 = 0;
/// Candidate address type: QUIC direct-connect socket
pub const CAND_QUIC: u8 = 1;

/// Candidate address list: (address, type)
pub type Candidates = Vec<(SocketAddr, u8)>;

const MAX_FRAME: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Hello { node_id: NodeId, cands: Candidates },
    /// STUN-like: the relay echoes the peer's TCP address as observed (the node infers its public IP)
    HelloAck { observed: SocketAddr },
    PunchRequest { target: NodeId },
    Exchange { peer: NodeId, cands: Candidates },
    RelayData { to: NodeId, from: NodeId, payload: Vec<u8> },
    StatsQuery,
    StatsReport { text: String },
    Error { msg: String },
}

// ---------- encoding helpers ----------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(bad("frame truncated"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn id(&mut self) -> io::Result<NodeId> {
        Ok(NodeId::from_bytes(self.take(32)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| bad("invalid UTF-8"))
    }
    fn addr(&mut self) -> io::Result<SocketAddr> {
        let ver = self.u8()?;
        let port = self.u16()?;
        match ver {
            4 => {
                let o: [u8; 4] = self.take(4)?.try_into().unwrap();
                Ok(SocketAddr::from((o, port)))
            }
            6 => {
                let o: [u8; 16] = self.take(16)?.try_into().unwrap();
                Ok(SocketAddr::from((o, port)))
            }
            _ => Err(bad("unknown address family")),
        }
    }
    fn cands(&mut self) -> io::Result<Candidates> {
        let n = self.u8()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let kind = self.u8()?;
            out.push((self.addr()?, kind));
        }
        Ok(out)
    }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_id(out: &mut Vec<u8>, id: &NodeId) {
    out.extend_from_slice(id.as_bytes());
}
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}
fn put_addr(out: &mut Vec<u8>, a: &SocketAddr) {
    match a {
        SocketAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&a.port().to_be_bytes());
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&a.port().to_be_bytes());
            out.extend_from_slice(&v6.ip().octets());
        }
    }
}
fn put_cands(out: &mut Vec<u8>, cands: &Candidates) {
    out.push(cands.len() as u8);
    for (a, kind) in cands {
        out.push(*kind);
        put_addr(out, a);
    }
}

// ---------- frame encode / decode ----------

pub fn encode(f: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    match f {
        Frame::Hello { node_id, cands } => {
            out.push(TAG_HELLO);
            put_id(&mut out, node_id);
            put_cands(&mut out, cands);
        }
        Frame::HelloAck { observed } => {
            out.push(TAG_HELLO_ACK);
            put_addr(&mut out, observed);
        }
        Frame::PunchRequest { target } => {
            out.push(TAG_PUNCH_REQ);
            put_id(&mut out, target);
        }
        Frame::Exchange { peer, cands } => {
            out.push(TAG_EXCHANGE);
            put_id(&mut out, peer);
            put_cands(&mut out, cands);
        }
        Frame::RelayData { to, from, payload } => {
            out.push(TAG_RELAY_DATA);
            put_id(&mut out, to);
            put_id(&mut out, from);
            put_bytes(&mut out, payload);
        }
        Frame::StatsQuery => out.push(TAG_STATS_QUERY),
        Frame::StatsReport { text } => {
            out.push(TAG_STATS_REPORT);
            put_bytes(&mut out, text.as_bytes());
        }
        Frame::Error { msg } => {
            out.push(TAG_ERROR);
            put_bytes(&mut out, msg.as_bytes());
        }
    }
    out
}

pub fn decode(buf: &[u8]) -> io::Result<Frame> {
    let mut c = Cursor { buf, pos: 0 };
    let tag = c.u8()?;
    let f = match tag {
        TAG_HELLO => Frame::Hello {
            node_id: c.id()?,
            cands: c.cands()?,
        },
        TAG_HELLO_ACK => Frame::HelloAck { observed: c.addr()? },
        TAG_PUNCH_REQ => Frame::PunchRequest { target: c.id()? },
        TAG_EXCHANGE => Frame::Exchange {
            peer: c.id()?,
            cands: c.cands()?,
        },
        TAG_RELAY_DATA => Frame::RelayData {
            to: c.id()?,
            from: c.id()?,
            payload: c.bytes()?,
        },
        TAG_STATS_QUERY => Frame::StatsQuery,
        TAG_STATS_REPORT => Frame::StatsReport { text: c.string()? },
        TAG_ERROR => Frame::Error { msg: c.string()? },
        _ => return Err(bad("unknown frame tag")),
    };
    Ok(f)
}

/// Write one frame: `u32be total-length | content`
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    let body = encode(f);
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// Read one frame (returns Ok(None) when the peer closes)
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME {
        return Err(bad("invalid frame length"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(Some(decode(&body)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn frame_roundtrip() {
        let id = NodeId::from_bytes([3u8; 32]);
        let frames = vec![
            Frame::Hello {
                node_id: id,
                cands: vec![
                    (SocketAddr::from((Ipv4Addr::LOCALHOST, 1234)), CAND_PUNCH),
                    (SocketAddr::from((Ipv6Addr::LOCALHOST, 5678)), CAND_QUIC),
                    (SocketAddr::from((Ipv4Addr::new(192, 168, 1, 2), 9000)), CAND_PUNCH),
                ],
            },
            Frame::HelloAck {
                observed: SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 5555)),
            },
            Frame::PunchRequest { target: id },
            Frame::Exchange {
                peer: id,
                cands: vec![(SocketAddr::from((Ipv4Addr::new(192, 168, 1, 2), 9000)), CAND_QUIC)],
            },
            Frame::RelayData {
                to: id,
                from: id,
                payload: vec![1, 2, 3, 250],
            },
            Frame::StatsQuery,
            Frame::StatsReport { text: "stats".into() },
            Frame::Error { msg: "boom".into() },
        ];
        for f in frames {
            assert_eq!(decode(&encode(&f)).unwrap(), f);
        }
    }

    #[tokio::test]
    async fn frame_io_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let f = Frame::RelayData {
            to: NodeId::from_bytes([1; 32]),
            from: NodeId::from_bytes([2; 32]),
            payload: b"ciphertext".to_vec(),
        };
        write_frame(&mut a, &f).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), Some(f));
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap(), None);
    }
}
