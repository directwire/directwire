//! 客户端辅助：publisher / subscriber 的会话建立与数据收发。
//!
//! 通道模型（与 relay 对齐）：
//! - 控制面：一条双向流（SETUP 后复用），承载 ANNOUNCE/SUBSCRIBE/UNSUBSCRIBE/GOAWAY；
//! - 数据面：publisher 每个 group 开一条单向流（GROUP_HEADER + OBJECT 序列）；
//!   subscriber 侧派生 accept_uni 任务解复用下行 group 流；
//! - track alias：subscriber 在 SUBSCRIBE 中自带 alias；publisher 在收到 relay
//!   转发的 SUBSCRIBE 后记录 alias，之后的 group 流头用 alias 代替完整 track。

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint, SendStream};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::control::{ControlReceiver, ControlSender};
use crate::message::{Message, PROTO_VERSION, Role, StartMode, TrackRef};
use crate::net::{self, FrameReader};
use crate::track::{Object, Priority, TrackId};

/// 控制事件（目前仅 GOAWAY）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    /// 对端通告即将关闭。
    Goaway { reason: String },
}

/// 控制通道 + 可选的 GM-PQ 握手信息。
struct ControlPlane {
    sender: ControlSender,
    receiver: ControlReceiver,
    #[cfg(feature = "gm-pq")]
    gmpq_info: Option<crate::gmpq::GmPqInfo>,
}

// ---------------------------------------------------------------------------
// 公共：SETUP 握手
// ---------------------------------------------------------------------------

/// 发起连接：开启 GM-PQ 时先在首条 bi-stream 上完成混合握手，再做 SETUP。
async fn handshake(
    endpoint: &Endpoint,
    addr: SocketAddr,
    role: Role,
    #[cfg(feature = "gm-pq")] gmpq: Option<Arc<crate::gmpq::ClientIdentity>>,
) -> io::Result<(Connection, ControlPlane)> {
    let conn = endpoint
        .connect(addr, "localhost")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("connect 失败: {e}")))?
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("QUIC 握手失败: {e}"),
            )
        })?;
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| io::Error::other(format!("打开流失败: {e}")))?;

    #[cfg(feature = "gm-pq")]
    let (sender, receiver, gmpq_info) = match gmpq {
        Some(id) => {
            let (s, r, info) = crate::gmpq::client_handshake(send, recv, &id).await?;
            (
                ControlSender::Secure(s),
                ControlReceiver::Secure(r),
                Some(info),
            )
        }
        None => (ControlSender::raw(send), ControlReceiver::raw(recv), None),
    };
    #[cfg(not(feature = "gm-pq"))]
    let (sender, receiver) = (ControlSender::raw(send), ControlReceiver::raw(recv));

    let mut plane = ControlPlane {
        sender,
        receiver,
        #[cfg(feature = "gm-pq")]
        gmpq_info,
    };
    plane
        .sender
        .send(&Message::Setup {
            version: PROTO_VERSION,
            role,
        })
        .await?;
    match plane.receiver.recv().await? {
        Some(Message::Setup { .. }) => Ok((conn, plane)),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("期望服务端 SETUP，实际: {other:?}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Publisher
// ---------------------------------------------------------------------------

/// GM-PQ 握手信息（非 feature 构建下为单元占位，保证签名一致）。
#[cfg(feature = "gm-pq")]
type MaybeGmPqInfo = Option<crate::gmpq::GmPqInfo>;
#[cfg(not(feature = "gm-pq"))]
type MaybeGmPqInfo = ();

/// 发布端句柄。
pub struct Publisher {
    conn: Connection,
    control: ControlSender,
    /// relay 协商出的 track → alias（收到上游 SUBSCRIBE 后记录）。
    aliases: Arc<Mutex<HashMap<TrackId, u64>>>,
}

impl Publisher {
    /// 连接 relay 并启动控制面任务（处理 ANNOUNCE_OK / 上游 SUBSCRIBE / GOAWAY）。
    pub async fn connect(endpoint: &Endpoint, addr: SocketAddr) -> io::Result<Self> {
        Self::connect_inner(
            endpoint,
            addr,
            #[cfg(feature = "gm-pq")]
            None,
        )
        .await
        .map(|(p, _)| p)
    }

    /// 连接 relay 并启用 GM-PQ 会话层（返回握手信息用于模式/耗时打印）。
    #[cfg(feature = "gm-pq")]
    pub async fn connect_gmpq(
        endpoint: &Endpoint,
        addr: SocketAddr,
        identity: Arc<crate::gmpq::ClientIdentity>,
    ) -> io::Result<(Self, crate::gmpq::GmPqInfo)> {
        let (p, info) = Self::connect_inner(endpoint, addr, Some(identity)).await?;
        Ok((p, info.expect("GM-PQ 路径必有握手信息")))
    }

    async fn connect_inner(
        endpoint: &Endpoint,
        addr: SocketAddr,
        #[cfg(feature = "gm-pq")] gmpq: Option<Arc<crate::gmpq::ClientIdentity>>,
    ) -> io::Result<(Self, MaybeGmPqInfo)> {
        let (conn, plane) = handshake(
            endpoint,
            addr,
            Role::Publisher,
            #[cfg(feature = "gm-pq")]
            gmpq,
        )
        .await?;
        #[cfg(feature = "gm-pq")]
        let info = plane.gmpq_info.clone();
        #[cfg(not(feature = "gm-pq"))]
        let info: MaybeGmPqInfo = ();
        let ControlPlane {
            sender: control,
            receiver,
            ..
        } = plane;
        let aliases: Arc<Mutex<HashMap<TrackId, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let aliases = Arc::clone(&aliases);
            let control = control.clone();
            let mut receiver = receiver;
            tokio::spawn(async move {
                // 控制面读循环。
                while let Ok(Some(msg)) = receiver.recv().await {
                    match msg {
                        Message::AnnounceOk { .. } => {}
                        // relay 转发的订阅：记录 alias 并确认。
                        Message::Subscribe {
                            subscribe_id,
                            track_alias,
                            track,
                            ..
                        } => {
                            aliases.lock().await.insert(track, track_alias);
                            let _ = control.send(&Message::SubscribeOk { subscribe_id }).await;
                        }
                        Message::Goaway { reason } => {
                            eprintln!("[publisher] 收到 GOAWAY: {reason}");
                            return;
                        }
                        _ => {}
                    }
                }
            });
        }
        Ok((
            Self {
                conn,
                control,
                aliases,
            },
            info,
        ))
    }

    /// 声明命名空间。
    pub async fn announce(&self, namespace: &str) -> io::Result<()> {
        self.control
            .send(&Message::Announce {
                namespace: namespace.to_string(),
            })
            .await
    }

    /// 查询某 track 已协商的 alias（测试与内部使用）。
    pub async fn alias_of(&self, track: &TrackId) -> Option<u64> {
        self.aliases.lock().await.get(track).copied()
    }

    /// 开一个 group 数据流：有 alias 用 alias，否则用完整 track 标识。
    pub async fn begin_group(&self, track: &TrackId, group_id: u64) -> io::Result<GroupWriter> {
        let track_ref = match self.alias_of(track).await {
            Some(a) => TrackRef::Alias(a),
            None => TrackRef::Full(track.clone()),
        };
        let mut s = self.conn.open_uni().await.map_err(|e| {
            io::Error::new(io::ErrorKind::BrokenPipe, format!("开 group 流失败: {e}"))
        })?;
        net::write_frame(
            &mut s,
            &Message::GroupHeader {
                track_ref,
                group_id,
            },
        )
        .await?;
        Ok(GroupWriter {
            stream: s,
            group_id,
        })
    }

    /// 优雅收尾：finish 所有流后等待投递（调用方在此之前应完成所有 group）。
    pub async fn close(self) {
        self.conn.close(0u32.into(), b"publisher done");
    }
}

/// 一个 group 的数据流写入器。
pub struct GroupWriter {
    stream: SendStream,
    group_id: u64,
}

impl GroupWriter {
    /// 写入一个 object（group_id 自动取自流头）。
    pub async fn write_object(&mut self, obj: &Object) -> io::Result<()> {
        debug_assert_eq!(obj.group_id, self.group_id, "object 必须属于本 group");
        net::write_frame(
            &mut self.stream,
            &Message::Object {
                object: obj.clone(),
            },
        )
        .await
    }

    /// 结束本 group 的流（对端据此得知 group 完结）。
    pub fn finish(&mut self) {
        let _ = self.stream.finish();
    }
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

/// 订阅结果待决通道（SubscribeOk/SubscribeError → oneshot）。
type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<(), String>>>>>;

/// 订阅端句柄。
pub struct Subscriber {
    control: ControlSender,
    /// subscribe_id → 待决结果（SubscribeOk / SubscribeError）。
    pending: PendingMap,
    /// alias → object 下行通道。
    routes: Arc<Mutex<HashMap<u64, mpsc::Sender<Object>>>>,
    /// 控制事件（GOAWAY 等）。
    events: mpsc::Receiver<ControlEvent>,
}

impl Subscriber {
    /// 连接 relay 并启动控制面 + 数据面任务。
    pub async fn connect(endpoint: &Endpoint, addr: SocketAddr) -> io::Result<Self> {
        Self::connect_inner(
            endpoint,
            addr,
            #[cfg(feature = "gm-pq")]
            None,
        )
        .await
        .map(|(s, _)| s)
    }

    /// 连接 relay 并启用 GM-PQ 会话层（返回握手信息用于模式/耗时打印）。
    #[cfg(feature = "gm-pq")]
    pub async fn connect_gmpq(
        endpoint: &Endpoint,
        addr: SocketAddr,
        identity: Arc<crate::gmpq::ClientIdentity>,
    ) -> io::Result<(Self, crate::gmpq::GmPqInfo)> {
        let (s, info) = Self::connect_inner(endpoint, addr, Some(identity)).await?;
        Ok((s, info.expect("GM-PQ 路径必有握手信息")))
    }

    async fn connect_inner(
        endpoint: &Endpoint,
        addr: SocketAddr,
        #[cfg(feature = "gm-pq")] gmpq: Option<Arc<crate::gmpq::ClientIdentity>>,
    ) -> io::Result<(Self, MaybeGmPqInfo)> {
        let (conn, plane) = handshake(
            endpoint,
            addr,
            Role::Subscriber,
            #[cfg(feature = "gm-pq")]
            gmpq,
        )
        .await?;
        #[cfg(feature = "gm-pq")]
        let info = plane.gmpq_info.clone();
        #[cfg(not(feature = "gm-pq"))]
        let info: MaybeGmPqInfo = ();
        let ControlPlane {
            sender: control,
            mut receiver,
            ..
        } = plane;
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let routes: Arc<Mutex<HashMap<u64, mpsc::Sender<Object>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, event_rx) = mpsc::channel(16);

        // 控制面读循环。
        {
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                while let Ok(Some(msg)) = receiver.recv().await {
                    match msg {
                        Message::SubscribeOk { subscribe_id } => {
                            if let Some(tx) = pending.lock().await.remove(&subscribe_id) {
                                let _ = tx.send(Ok(()));
                            }
                        }
                        Message::SubscribeError {
                            subscribe_id,
                            reason,
                            ..
                        } => {
                            if let Some(tx) = pending.lock().await.remove(&subscribe_id) {
                                let _ = tx.send(Err(reason));
                            }
                        }
                        Message::Goaway { reason } => {
                            let _ = event_tx.send(ControlEvent::Goaway { reason }).await;
                            return;
                        }
                        _ => {}
                    }
                }
            });
        }

        // 数据面：解复用下行 group 流。
        {
            let routes = Arc::clone(&routes);
            tokio::spawn(async move {
                loop {
                    match conn.accept_uni().await {
                        Ok(recv) => {
                            let routes = Arc::clone(&routes);
                            tokio::spawn(async move {
                                let _ = read_group_stream(recv, routes).await;
                            });
                        }
                        Err(_) => return, // 连接关闭
                    }
                }
            });
        }

        Ok((
            Self {
                control,
                pending,
                routes,
                events: event_rx,
            },
            info,
        ))
    }

    /// 发起订阅；Ok(Ok(rx)) 成功，Ok(Err(reason)) 为 SUBSCRIBE_ERROR。
    ///
    /// alias 直接复用 subscribe_id（订阅方选定，符合 MoQ「alias 由请求方选择」语义）。
    pub async fn subscribe(
        &self,
        subscribe_id: u64,
        track: &TrackId,
        start: StartMode,
        priority: Priority,
    ) -> io::Result<Result<mpsc::Receiver<Object>, String>> {
        let (tx, rx) = mpsc::channel(1024);
        let (done_tx, done_rx) = oneshot::channel();
        self.routes.lock().await.insert(subscribe_id, tx);
        self.pending.lock().await.insert(subscribe_id, done_tx);
        self.control
            .send(&Message::Subscribe {
                subscribe_id,
                track_alias: subscribe_id,
                track: track.clone(),
                start,
                priority,
            })
            .await?;
        match done_rx.await {
            Ok(Ok(())) => Ok(Ok(rx)),
            Ok(Err(reason)) => {
                self.routes.lock().await.remove(&subscribe_id);
                Ok(Err(reason))
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "控制面任务已退出",
            )),
        }
    }

    /// 取消订阅（UNSUBSCRIBE）。
    pub async fn unsubscribe(&self, subscribe_id: u64) -> io::Result<()> {
        self.routes.lock().await.remove(&subscribe_id);
        self.control
            .send(&Message::Unsubscribe { subscribe_id })
            .await
    }

    /// 控制事件通道（GOAWAY 等）。
    pub fn events(&mut self) -> &mut mpsc::Receiver<ControlEvent> {
        &mut self.events
    }
}

/// 解复用一条下行 group 流：GROUP_HEADER（alias 路由）+ OBJECT 序列。
async fn read_group_stream(
    mut recv: quinn::RecvStream,
    routes: Arc<Mutex<HashMap<u64, mpsc::Sender<Object>>>>,
) -> io::Result<()> {
    let mut reader = FrameReader::new();
    let (alias, group_id) = match reader.read(&mut recv).await? {
        Some(Message::GroupHeader {
            track_ref: TrackRef::Alias(a),
            group_id,
        }) => (a, group_id),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("group 流首帧必须是 GROUP_HEADER(alias)，实际: {other:?}"),
            ));
        }
    };
    let tx = routes.lock().await.get(&alias).cloned();
    let Some(tx) = tx else {
        return Ok(()); // 未知 alias（可能已退订）：直接丢弃该流
    };
    while let Ok(Some(msg)) = reader.read(&mut recv).await {
        if let Message::Object { mut object } = msg {
            object.group_id = group_id; // 回填流头中的 group_id
            if tx.send(object).await.is_err() {
                return Ok(()); // 消费方退出
            }
        }
    }
    Ok(())
}

/// 当前 UNIX 毫秒时间戳。
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
