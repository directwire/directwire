//! 控制通道抽象：统一「裸 QUIC 流」与「GM-PQ 加密会话」两种控制面承载。
//!
//! - 不开 feature `gm-pq`：控制消息以裸帧形式跑在首条 bi-stream 上（原有行为）；
//! - 开启后：首条 bi-stream 先完成混合握手，之后控制消息逐条经
//!   `SecureChannel`（SM4-GCM）加密传输，帧格式不变（Message::encode 的字节
//!   作为会话消息载荷）。

use std::io;
use std::sync::Arc;

use quinn::{RecvStream, SendStream};
use tokio::sync::Mutex;

use crate::message::Message;
use crate::net::{self, FrameReader};

/// 控制通道发送半（可克隆，多任务共享）。
#[derive(Clone)]
pub enum ControlSender {
    /// 裸 QUIC 流（默认）。
    Raw(Arc<Mutex<SendStream>>),
    /// GM-PQ 加密会话（feature gm-pq）。
    #[cfg(feature = "gm-pq")]
    Secure(crate::gmpq::GmPqSender),
}

impl ControlSender {
    pub fn raw(send: SendStream) -> Self {
        Self::Raw(Arc::new(Mutex::new(send)))
    }

    /// 发送一条控制消息。
    pub async fn send(&self, msg: &Message) -> io::Result<()> {
        match self {
            ControlSender::Raw(s) => {
                let mut g = s.lock().await;
                net::write_frame(&mut g, msg).await
            }
            #[cfg(feature = "gm-pq")]
            ControlSender::Secure(s) => s.send(msg.encode()),
        }
    }
}

/// 控制通道接收半。
pub enum ControlReceiver {
    /// 裸 QUIC 流（默认）。
    Raw { recv: RecvStream, reader: FrameReader },
    /// GM-PQ 加密会话（feature gm-pq）。
    #[cfg(feature = "gm-pq")]
    Secure(crate::gmpq::GmPqReceiver),
}

impl ControlReceiver {
    pub fn raw(recv: RecvStream) -> Self {
        Self::Raw {
            recv,
            reader: FrameReader::new(),
        }
    }

    /// 接收一条控制消息；对端干净关闭返回 Ok(None)。
    pub async fn recv(&mut self) -> io::Result<Option<Message>> {
        match self {
            ControlReceiver::Raw { recv, reader } => reader.read(recv).await,
            #[cfg(feature = "gm-pq")]
            ControlReceiver::Secure(r) => match r.recv().await {
                Some(bytes) => Message::decode(&bytes).map(Some),
                None => Ok(None),
            },
        }
    }
}
