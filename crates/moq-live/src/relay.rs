//! 中继服务器（Relay）：接收 publisher 的 object 流，向多个 subscriber 扇出。
//!
//! 通道模型（对齐 MoQ 核心范式）：
//! - 控制面：每连接一条双向流（SETUP/ANNOUNCE/SUBSCRIBE/UNSUBSCRIBE/GOAWAY 等）；
//! - 数据面：stream-per-group——publisher 每个 group 开一条单向流
//!   （GROUP_HEADER + OBJECT 序列），relay 解复用后向每个 subscriber
//!   重新起流转发（每 group 一条新单向流）；
//! - track alias：subscriber 的 SUBSCRIBE 自带 alias（下行数据帧头引用）；
//!   relay 在首个订阅到达时向上游 publisher 转发 SUBSCRIBE 并分配 alias，
//!   publisher 之后的数据帧头用 alias 代替完整 track 字符串；
//! - 丢包决策：下行写入前经过 PriorityDropQueue，拥塞时优先丢低优先级非关键帧；
//!   上游 broadcast Lagged 时跳到下一 group 边界（丢 P 保 I）。

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::{Mutex, Notify};

use crate::control::{ControlReceiver, ControlSender};
use crate::dropq::{PriorityDropQueue, PushOutcome};
use crate::hub::Hub;
use crate::message::{
    ERR_NAMESPACE_NOT_FOUND, Message, PROTO_VERSION, Role, StartMode, TrackRef,
};
use crate::net::{self, FrameReader};
use crate::track::{Object, TrackId};

/// 下行丢弃队列容量（每订阅）：超出即触发优先级丢弃。
const DROP_QUEUE_CAPACITY: usize = 64;

/// 中继服务器句柄。
pub struct Relay {
    endpoint: Endpoint,
    hub: Hub,
    /// 活跃连接注册表（用于 GOAWAY 优雅关闭）。
    conns: Arc<Mutex<HashMap<usize, ConnReg>>>,
    /// track → 发布端注册信息（alias 协商与数据帧头解析）。
    publishers: Arc<Mutex<HashMap<TrackId, PublisherReg>>>,
    /// relay 向上游分配 track alias 的计数器。
    next_alias: Arc<AtomicU64>,
    /// GM-PQ 会话层身份（feature gm-pq；None = 不启用会话层）。
    #[cfg(feature = "gm-pq")]
    gmpq: Option<Arc<crate::gmpq::ServerIdentity>>,
}

#[derive(Clone)]
struct ConnReg {
    control: ControlSender,
    conn: Connection,
}

/// 发布端注册：控制流写半 + 已协商 alias + 该连接上的 alias→track 解析表。
#[derive(Clone)]
struct PublisherReg {
    control: ControlSender,
    /// 已分配给该 track 的上游 alias（None = 尚未协商）。
    alias: Option<u64>,
}

impl Relay {
    pub fn new(endpoint: Endpoint, hub: Hub) -> Self {
        Self {
            endpoint,
            hub,
            conns: Arc::new(Mutex::new(HashMap::new())),
            publishers: Arc::new(Mutex::new(HashMap::new())),
            next_alias: Arc::new(AtomicU64::new(1)),
            #[cfg(feature = "gm-pq")]
            gmpq: None,
        }
    }

    /// 启用 GM-PQ 会话层：首条 bi-stream 先跑混合握手，通过后才放行控制面。
    #[cfg(feature = "gm-pq")]
    pub fn with_gmpq(mut self, identity: Arc<crate::gmpq::ServerIdentity>) -> Self {
        self.gmpq = Some(identity);
        self
    }

    /// 实际监听地址（便于传入 :0 后取回端口）。
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    /// 运行接受循环，直到 endpoint 关闭或出错。
    pub async fn run(&self) -> io::Result<()> {
        loop {
            let Some(incoming) = self.endpoint.accept().await else {
                return Ok(()); // endpoint 已关闭
            };
            let ctx = ConnCtx {
                hub: self.hub.clone(),
                conns: Arc::clone(&self.conns),
                publishers: Arc::clone(&self.publishers),
                next_alias: Arc::clone(&self.next_alias),
                #[cfg(feature = "gm-pq")]
                gmpq: self.gmpq.clone(),
            };
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_connection(conn, ctx).await {
                            eprintln!("[relay] 连接结束: {e}");
                        }
                    }
                    Err(e) => eprintln!("[relay] 握手失败: {e}"),
                }
            });
        }
    }

    /// 优雅关闭：向全部活跃连接发送 GOAWAY，留出投递窗口后关闭 endpoint。
    pub async fn shutdown(&self) {
        let regs: Vec<ConnReg> = self.conns.lock().await.values().cloned().collect();
        for reg in &regs {
            let _ = reg
                .control
                .send(&Message::Goaway {
                    reason: "relay 优雅关闭".to_string(),
                })
                .await;
        }
        // 留出 GOAWAY 投递窗口，再由对端主动关闭 / endpoint 兜底关闭。
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        for reg in &regs {
            reg.conn.close(0u32.into(), b"server shutdown");
        }
        self.endpoint.close(0u32.into(), b"server shutdown");
    }
}

/// 每条连接共享的上下文。
struct ConnCtx {
    hub: Hub,
    conns: Arc<Mutex<HashMap<usize, ConnReg>>>,
    publishers: Arc<Mutex<HashMap<TrackId, PublisherReg>>>,
    next_alias: Arc<AtomicU64>,
    #[cfg(feature = "gm-pq")]
    gmpq: Option<Arc<crate::gmpq::ServerIdentity>>,
}

/// 建立控制通道：启用 GM-PQ 时先跑混合握手（红线 1：client_tag 绑定对端地址）。
async fn open_control(conn: &Connection, ctx: &ConnCtx) -> io::Result<(ControlSender, ControlReceiver)> {
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("接受流失败: {e}")))?;
    #[cfg(feature = "gm-pq")]
    if let Some(id) = &ctx.gmpq {
        let tag = conn.remote_address().to_string().into_bytes();
        let (s, r, info) = crate::gmpq::server_handshake(send, recv, id, tag).await?;
        eprintln!(
            "[relay] GM-PQ 会话建立: {} 耗时 {:?} session={}",
            info.mode_label(),
            info.elapsed,
            hex8(&info.session_id)
        );
        return Ok((ControlSender::Secure(s), ControlReceiver::Secure(r)));
    }
    #[cfg(not(feature = "gm-pq"))]
    let _ = ctx; // 未启用 GM-PQ 时上下文不参与控制通道建立
    Ok((ControlSender::raw(send), ControlReceiver::raw(recv)))
}

#[cfg(feature = "gm-pq")]
fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

/// 处理单条 QUIC 连接：SETUP → 控制流分发 + 数据流解复用。
async fn handle_connection(conn: Connection, ctx: ConnCtx) -> io::Result<()> {
    // 1. 建立控制通道（GM-PQ 开启时此处含混合握手，握手不过则无后续）。
    let (control, mut receiver) = open_control(&conn, &ctx).await?;

    // 2. SETUP 握手。
    let peer_role = match receiver.recv().await? {
        Some(Message::Setup { version, role }) => {
            if version != PROTO_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("协议版本不兼容: 对端 {version:#x}"),
                ));
            }
            role
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("首条消息必须是 SETUP，实际: {other:?}"),
            ))
        }
    };
    control
        .send(&Message::Setup {
            version: PROTO_VERSION,
            role: Role::Both,
        })
        .await?;
    eprintln!("[relay] 新连接 {:?}，角色 {:?}", conn.remote_address(), peer_role);

    // 注册连接（GOAWAY 用）。
    let stable_id = conn.stable_id();
    ctx.conns.lock().await.insert(
        stable_id,
        ConnReg {
            control: control.clone(),
            conn: conn.clone(),
        },
    );

    // 3. 数据面任务：接受 publisher 的 group 单向流并解复用。
    let ingress = {
        let conn = conn.clone();
        let ctx_hub = ctx.hub.clone();
        let ctx_publishers = Arc::clone(&ctx.publishers);
        let control2 = control.clone();
        tokio::spawn(async move {
            loop {
                match conn.accept_uni().await {
                    Ok(recv) => {
                        let hub = ctx_hub.clone();
                        let pubs = Arc::clone(&ctx_publishers);
                        let ctl = control2.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_group_stream(recv, hub, pubs, ctl).await {
                                eprintln!("[relay] group 流处理失败: {e}");
                            }
                        });
                    }
                    Err(_) => return, // 连接关闭
                }
            }
        })
    };

    // 4. 控制面循环。
    let mut forwarders: HashMap<u64, ForwarderHandle> = HashMap::new();
    let result = control_loop(&conn, &ctx, &control, &mut receiver, &mut forwarders).await;

    // 5. 收尾：撤销注册、停掉转发与数据面任务。
    ctx.conns.lock().await.remove(&stable_id);
    for (_, h) in forwarders {
        h.abort();
    }
    ingress.abort();
    result
}

/// 控制面消息分发循环。返回时连接生命周期结束。
async fn control_loop(
    conn: &Connection,
    ctx: &ConnCtx,
    control: &ControlSender,
    receiver: &mut ControlReceiver,
    forwarders: &mut HashMap<u64, ForwarderHandle>,
) -> io::Result<()> {
    loop {
        let msg = match receiver.recv().await {
            Ok(Some(m)) => m,
            Ok(None) => {
                // 对端关闭发送半流：订阅转发仍应继续，直到对端断开连接。
                eprintln!("[relay] 对端关闭控制发送半流，保留下行转发");
                loop {
                    if forwarders.is_empty() {
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    forwarders.retain(|_, h| !h.is_finished());
                }
            }
            Err(e) => {
                eprintln!("[relay] 读消息失败: {e}");
                return Ok(());
            }
        };
        match msg {
            Message::Announce { namespace } => {
                ctx.hub.announce_namespace(&namespace);
                control.send(&Message::AnnounceOk { namespace }).await?;
            }
            Message::Subscribe {
                subscribe_id,
                track_alias,
                track,
                start,
                priority,
            } => {
                if !ctx.hub.namespace_announced(&track.namespace) {
                    control
                        .send(&Message::SubscribeError {
                            subscribe_id,
                            code: ERR_NAMESPACE_NOT_FOUND,
                            reason: format!("命名空间未发布: {}", track.namespace),
                        })
                        .await?;
                    continue;
                }
                control.send(&Message::SubscribeOk { subscribe_id }).await?;
                // 首个订阅触发向上游 publisher 的 alias 协商。
                maybe_bind_upstream_alias(ctx, &track).await;
                let sub = ctx.hub.subscribe(&track, start);
                eprintln!(
                    "[relay] SUBSCRIBE {track} alias={track_alias} replay={} 个 object",
                    sub.replay.len()
                );
                let handle = spawn_forwarder(
                    conn.clone(),
                    track,
                    track_alias,
                    priority,
                    sub.replay,
                    sub.live,
                );
                forwarders.insert(subscribe_id, handle);
            }
            Message::Unsubscribe { subscribe_id } => {
                if let Some(h) = forwarders.remove(&subscribe_id) {
                    h.abort();
                    eprintln!("[relay] UNSUBSCRIBE id={subscribe_id}，转发已停止");
                }
            }
            Message::Goaway { reason } => {
                eprintln!("[relay] 对端 GOAWAY: {reason}");
                return Ok(());
            }
            // 上游 publisher 对 relay 转发的 SUBSCRIBE 的确认：忽略即可。
            Message::SubscribeOk { .. } => {}
            other => {
                eprintln!("[relay] 忽略意外消息: {other:?}");
            }
        }
    }
}

/// 首个订阅到达时，向上游 publisher 转发 SUBSCRIBE 以协商 track alias。
async fn maybe_bind_upstream_alias(ctx: &ConnCtx, track: &TrackId) {
    let mut pubs = ctx.publishers.lock().await;
    let Some(reg) = pubs.get_mut(track) else {
        return; // publisher 尚未推流（首个 group 流到达时才注册），等下次订阅再协商
    };
    if reg.alias.is_some() {
        return; // 已协商
    }
    let alias = ctx.next_alias.fetch_add(1, Ordering::Relaxed);
    let msg = Message::Subscribe {
        subscribe_id: alias, // relay 内部订阅 id 复用 alias，足够区分
        track_alias: alias,
        track: track.clone(),
        start: StartMode::NextObject,
        priority: 0,
    };
    if reg.control.send(&msg).await.is_ok() {
        reg.alias = Some(alias);
        eprintln!("[relay] 上游 alias 协商: {track} -> alias={alias}");
    }
}

/// 处理一条 group 数据流（publisher → relay）：首帧 GROUP_HEADER，其后 OBJECT 序列。
async fn handle_group_stream(
    mut recv: RecvStream,
    hub: Hub,
    publishers: Arc<Mutex<HashMap<TrackId, PublisherReg>>>,
    control: ControlSender,
) -> io::Result<()> {
    let mut reader = FrameReader::new();
    // 首帧必须是 GROUP_HEADER。
    let (track, group_id) = match reader.read(&mut recv).await? {
        Some(Message::GroupHeader {
            track_ref,
            group_id,
        }) => {
            let track = resolve_track_ref(track_ref, &publishers, control).await?;
            (track, group_id)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("group 流首帧必须是 GROUP_HEADER，实际: {other:?}"),
            ))
        }
    };
    // 该 group 的 OBJECT 序列：回填 group_id 后入 hub。
    while let Some(msg) = reader.read(&mut recv).await? {
        match msg {
            Message::Object { mut object } => {
                object.group_id = group_id;
                hub.publish(&track, object);
            }
            other => eprintln!("[relay] group 流内忽略意外消息: {other:?}"),
        }
    }
    Ok(())
}

/// 解析数据帧头中的 track 引用。
///
/// - Full：自描述；同时按「单 publisher 单 track」假设惰性注册发布端；
/// - Alias：查 relay 向上游分配 alias 时记录的 publishers 表。
async fn resolve_track_ref(
    track_ref: TrackRef,
    publishers: &Arc<Mutex<HashMap<TrackId, PublisherReg>>>,
    control: ControlSender,
) -> io::Result<TrackId> {
    match track_ref {
        TrackRef::Full(track) => {
            let mut pubs = publishers.lock().await;
            pubs.entry(track.clone()).or_insert(PublisherReg {
                control,
                alias: None,
            });
            Ok(track)
        }
        TrackRef::Alias(a) => {
            let pubs = publishers.lock().await;
            pubs.iter()
                .find(|(_, reg)| reg.alias == Some(a))
                .map(|(t, _)| t.clone())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("未知 track alias: {a}")))
        }
    }
}

/// 订阅转发任务句柄（reader + writer 两个任务；abort 必须成对执行）。
struct ForwarderHandle {
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl ForwarderHandle {
    fn abort(&self) {
        self.reader.abort();
        self.writer.abort();
    }
    /// writer 结束（连接断开/对端取消）即视为转发结束。
    fn is_finished(&self) -> bool {
        self.writer.is_finished()
    }
}

/// 派生订阅转发：先回放快照（一条流），再实时转发（每 group 一条流）。
///
/// 结构：broadcast reader → PriorityDropQueue（拥塞丢帧）→ stream writer。
fn spawn_forwarder(
    conn: Connection,
    _track: TrackId,
    alias: u64,
    _priority: crate::track::Priority,
    replay: Vec<Arc<Object>>,
    mut live: tokio::sync::broadcast::Receiver<Arc<Object>>,
) -> ForwarderHandle {
    use tokio::sync::broadcast::error::RecvError;

    // reader → writer 的共享队列（带关闭标志）。
    struct Shared {
        queue: PriorityDropQueue,
        closed: bool,
    }
    let shared = Arc::new(Mutex::new(Shared {
        queue: PriorityDropQueue::new(DROP_QUEUE_CAPACITY),
        closed: false,
    }));
    let notify = Arc::new(Notify::new());

    // reader：从 broadcast 读实时 object，Lagged 时跳到下一 group 边界。
    let reader_task = {
        let shared = Arc::clone(&shared);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            let mut skip_to_group_head = false;
            loop {
                match live.recv().await {
                    Ok(obj) => {
                        if skip_to_group_head && !obj.is_group_head() {
                            continue; // 丢 P 帧直至遇到 I 帧
                        }
                        skip_to_group_head = false;
                        let mut g = shared.lock().await;
                        if let PushOutcome::Evicted(old) = g.queue.push(obj) {
                            eprintln!(
                                "[relay] 下行拥塞：驱逐低优先级 object g{} o{}",
                                old.group_id, old.object_id
                            );
                        }
                        drop(g);
                        notify.notify_one();
                    }
                    Err(RecvError::Lagged(n)) => {
                        eprintln!("[relay] 慢订阅者落后 {n} 个 object，跳到下一 group 边界");
                        skip_to_group_head = true;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
            shared.lock().await.closed = true;
            notify.notify_one();
        })
    };

    // writer：回放 + 按 group 起流写出。
    let writer_task = {
        let shared = Arc::clone(&shared);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            // 1. 追赶快照（LatestGroup 模式下为单个 group）。
            if let Some(first) = replay.first() {
                let group_id = first.group_id;
                match open_group_stream(&conn, alias, group_id).await {
                    Ok(mut s) => {
                        for obj in &replay {
                            if write_object(&mut s, obj).await.is_err() {
                                return;
                            }
                        }
                        let _ = s.finish();
                    }
                    Err(_) => return,
                }
            }
            // 2. 实时流：group 变化时结束旧流、开新流。
            let mut current: Option<(u64, SendStream)> = None;
            loop {
                let obj = {
                    let mut g = shared.lock().await;
                    match g.queue.pop() {
                        Some(o) => Some(o),
                        None if g.closed => None,
                        None => {
                            drop(g);
                            notify.notified().await;
                            continue;
                        }
                    }
                };
                let Some(obj) = obj else { break };
                // group 切换 → 换新流。
                if current.as_ref().is_none_or(|(g, _)| *g != obj.group_id) {
                    if let Some((_, mut old)) = current.take() {
                        let _ = old.finish();
                    }
                    match open_group_stream(&conn, alias, obj.group_id).await {
                        Ok(s) => current = Some((obj.group_id, s)),
                        Err(_) => return, // 连接已断
                    }
                }
                let (_, s) = current.as_mut().expect("刚打开必然存在");
                if write_object(s, &obj).await.is_err() {
                    return;
                }
            }
            if let Some((_, mut s)) = current.take() {
                let _ = s.finish();
            }
        })
    };

    ForwarderHandle {
        reader: reader_task,
        writer: writer_task,
    }
}

/// 向订阅端开一条 group 数据流并写首帧。
async fn open_group_stream(
    conn: &Connection,
    alias: u64,
    group_id: u64,
) -> io::Result<SendStream> {
    let mut s = conn
        .open_uni()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("开 group 流失败: {e}")))?;
    net::write_frame(
        &mut s,
        &Message::GroupHeader {
            track_ref: TrackRef::Alias(alias),
            group_id,
        },
    )
    .await?;
    Ok(s)
}

/// 向 group 数据流写入一个 object。
async fn write_object(s: &mut SendStream, obj: &Object) -> io::Result<()> {
    net::write_frame(s, &Message::Object {
        object: obj.clone(),
    })
    .await
}
