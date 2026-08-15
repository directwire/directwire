//! GM-PQ 会话层（feature `gm-pq`）：QUIC TLS 之上的国密合规 + 后量子安全会话。
//!
//! 架构：QUIC 连接建立后，**第一条 bi-stream 先跑 gm-pq-stack 的 SM2+ML-KEM-768
//! 混合握手**；握手通过后，SETUP/ANNOUNCE/SUBSCRIBE 等全部控制消息走
//! `SecureChannel`（SM4-GCM + 序号 + 重放窗口）。数据面 group 流仍由 QUIC TLS
//! 保护（媒体面国密化见 README 技术债）。
//!
//! 阻塞/异步桥接：gm-pq API 是阻塞 `Read + Write`，本模块用「内存管道 +
//! 独立工作线程」桥接——
//! - `BlockingEnd`：交给 gm-pq 阻塞代码的 Read+Write 端点（Condvar 等待）；
//! - shuttle 任务：quinn 流 ⇄ 管道之间的双向字节搬运；
//! - 握手完成后同一工作线程转入消息循环（outbox 明文出站 / inbox 明文入站）。
//!
//! 红线遵守（见 gm-pq-stack docs/INTEGRATION.md）：
//! 1. `client_tag` = QUIC 对端地址字节（绑定传输层来源身份）；
//! 2. 0-RTT early_data 仅放幂等内容（本模块固定为 `b"moq-live-resume"` 探针）；
//! 3. `TicketCache` 在 [`ServerIdentity`] 内进程级共享（Mutex 跨连接复用）。

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use gm_pq_stack::api::{
    ClientOutcome, SecureChannel, ServerConfig, ServerOutcome, client_connect_full,
    client_connect_resume, server_accept,
};
use gm_pq_stack::handshake::cookie::CookieIssuer;
use gm_pq_stack::handshake::psk::{TicketCache, TicketIssuer};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::trust::PinFileAnchor;
use quinn::{RecvStream, SendStream};

/// 静态私钥类型（不暴露字节接口）。
pub type StaticSecretKey = <DefaultHybrid as Kem>::SecretKey;

/// 生成一对混合静态密钥（SM2 + ML-KEM-768）。
pub fn generate_keypair() -> io::Result<(StaticSecretKey, Vec<u8>)> {
    let mut rng = gm_pq_stack::rng::SysRng::new();
    DefaultHybrid::keypair(&mut rng)
        .map_err(|e| io::Error::other(format!("GM-PQ 密钥生成失败: {e}")))
}

/// 握手算法模式名（如 "SM2+ML-KEM-768"）。
pub fn algorithm_name() -> &'static str {
    DefaultHybrid::NAME
}

/// 0-RTT early_data 内容（幂等探针，仅用于演示恢复路径）。
const EARLY_DATA_PROBE: &[u8] = b"moq-live-resume";

// ---------------------------------------------------------------------------
// 身份
// ---------------------------------------------------------------------------

/// 服务端（relay）身份与进程级握手组件。
pub struct ServerIdentity {
    sk: StaticSecretKey,
    pk: Vec<u8>,
    cookie: CookieIssuer,
    tickets: TicketIssuer,
    /// 红线 3：票据重放缓存跨连接共享。
    cache: Mutex<TicketCache>,
    anchor: PinFileAnchor,
    ticket_ttl_secs: u64,
}

impl ServerIdentity {
    /// cookie TTL 30s，票据 TTL 由参数指定。
    pub fn new(sk: StaticSecretKey, pk: Vec<u8>, anchor: PinFileAnchor, ticket_ttl_secs: u64) -> Self {
        Self {
            sk,
            pk,
            cookie: CookieIssuer::new(30),
            tickets: TicketIssuer::new(),
            cache: Mutex::new(TicketCache::new()),
            anchor,
            ticket_ttl_secs,
        }
    }
}

/// 客户端身份与恢复票据保存槽。
pub struct ClientIdentity {
    sk: StaticSecretKey,
    pk: Vec<u8>,
    anchor: PinFileAnchor,
    /// 上次连接保存的 (ticket, psk)，用于 0-RTT 恢复。
    ticket: Mutex<Option<(Vec<u8>, [u8; 32])>>,
}

impl ClientIdentity {
    pub fn new(sk: StaticSecretKey, pk: Vec<u8>, anchor: PinFileAnchor) -> Self {
        Self {
            sk,
            pk,
            anchor,
            ticket: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// 阻塞 ⇄ 异步桥
// ---------------------------------------------------------------------------

/// 桥接共享状态：quinn→worker 字节（inbound）、应用→worker 明文（outbox）、
/// worker→quinn 线上字节（wire）。Condvar 唤醒阻塞 worker；Notify 唤醒异步出向。
#[derive(Default)]
struct BridgeShared {
    inbound: VecDeque<u8>,
    outbox: VecDeque<Vec<u8>>,
    wire: VecDeque<u8>,
    closed: bool,
}

struct Bridge {
    m: Mutex<BridgeShared>,
    cv: Condvar,
    /// 唤醒 shuttle 出向（可跨线程调用）。
    wire_notify: tokio::sync::Notify,
}

type Shared = Arc<Bridge>;

fn shared_push_inbound(shared: &Shared, bytes: &[u8]) {
    shared.m.lock().expect("桥锁中毒").inbound.extend(bytes);
    shared.cv.notify_one();
}

fn shared_push_wire(shared: &Shared, bytes: &[u8]) {
    shared.m.lock().expect("桥锁中毒").wire.extend(bytes);
    shared.wire_notify.notify_one();
}

fn shared_push_outbox(shared: &Shared, msg: Vec<u8>) -> io::Result<()> {
    let mut g = shared.m.lock().expect("桥锁中毒");
    if g.closed {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "GM-PQ 会话已关闭"));
    }
    g.outbox.push_back(msg);
    shared.cv.notify_one();
    Ok(())
}

/// 关闭桥（幂等）：同时唤醒阻塞 worker（Condvar）与异步出向（Notify），
/// 保证握手失败/连接断开等任意路径都能收敛。
fn shared_close(shared: &Shared) {
    shared.m.lock().expect("桥锁中毒").closed = true;
    shared.cv.notify_all();
    shared.wire_notify.notify_one();
}

/// 交给 gm-pq 阻塞代码的 Read+Write 端点（只持共享桥）。
struct BlockingEnd {
    shared: Shared,
}

impl Read for BlockingEnd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut g = self.shared.m.lock().expect("桥锁中毒");
        loop {
            if !g.inbound.is_empty() {
                let n = buf.len().min(g.inbound.len());
                for b in &mut buf[..n] {
                    *b = g.inbound.pop_front().expect("已判非空");
                }
                return Ok(n);
            }
            if g.closed {
                return Ok(0); // EOF
            }
            g = self.shared.cv.wait(g).expect("桥锁中毒");
        }
    }
}

impl Write for BlockingEnd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // 非阻塞：推入共享 wire 队列，由异步 shuttle 写入 quinn。
        // 关键设计：异步侧零 spawn_blocking——runtime 退出时无需等待阻塞池，
        // 避免「测试通过但进程挂死」的关闭死锁。
        shared_push_wire(&self.shared, buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// shuttle：quinn bi-stream ⇄ 桥（握手与会话阶段的线上字节搬运）。
///
/// 关闭传播链：入向结束 / worker 退出 / 写失败任一路径 → shared_close →
/// 阻塞 worker 经 Condvar 得 EOF、异步出向经 Notify 得 closed，全链收敛。
async fn shuttle(mut qsend: SendStream, mut qrecv: RecvStream, shared: Shared) {
    // 入向：quinn → shared.inbound（同步推，无需阻塞）。
    let inbound_task = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match qrecv.read(&mut buf).await {
                    Ok(Some(n)) => shared_push_inbound(&shared, &buf[..n]),
                    Ok(None) => break,   // 对端 finish
                    Err(_) => break,     // 连接错误
                }
            }
            shared_close(&shared); // 入向结束 → 唤醒 worker 与出向退出
        })
    };
    // 出向：shared.wire 队列（Notify 唤醒，纯异步）→ quinn。
    let outbound_task = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            loop {
                let (bytes, closed) = {
                    let mut g = shared.m.lock().expect("桥锁中毒");
                    (g.wire.drain(..).collect::<Vec<u8>>(), g.closed)
                };
                if !bytes.is_empty() {
                    if qsend.write_all(&bytes).await.is_err() {
                        break;
                    }
                    continue;
                }
                if closed {
                    break;
                }
                shared.wire_notify.notified().await;
            }
            let _ = qsend.finish();
            shared_close(&shared); // 出向结束 → 同样传播关闭
        })
    };
    let _ = tokio::join!(inbound_task, outbound_task);
    shared_close(&shared); // 幂等兜底
}

// ---------------------------------------------------------------------------
// 会话（异步句柄）
// ---------------------------------------------------------------------------

/// 握手元信息。
#[derive(Debug, Clone)]
pub struct GmPqInfo {
    /// 会话标识（双方一致）。
    pub session_id: [u8; 32],
    /// 已认证的对端静态公钥。
    pub peer_static_key: Vec<u8>,
    /// 是否为 0-RTT 恢复会话。
    pub resumed: bool,
    /// 0-RTT early_data 是否被接受（客户端视角；服务端为收到的 early_data）。
    pub early_data: Option<Vec<u8>>,
    /// 握手耗时。
    pub elapsed: Duration,
}

impl GmPqInfo {
    /// 模式描述（打印用）：算法 + 完整/恢复。
    pub fn mode_label(&self) -> String {
        format!(
            "{}/{}",
            algorithm_name(),
            if self.resumed { "0-RTT恢复" } else { "完整握手" }
        )
    }
}

/// 会话发送半（可克隆，多任务共享）。
#[derive(Clone)]
pub struct GmPqSender {
    shared: Shared,
}

impl GmPqSender {
    /// 发送一条明文消息（由工作线程加密上线）。
    pub fn send(&self, plaintext: Vec<u8>) -> io::Result<()> {
        shared_push_outbox(&self.shared, plaintext)
    }
}

/// 会话接收半。
pub struct GmPqReceiver {
    inbox: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
}

impl GmPqReceiver {
    /// 接收一条明文消息；会话结束返回 None。
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.recv().await
    }
}

// ---------------------------------------------------------------------------
// 对外握手入口
// ---------------------------------------------------------------------------

/// 服务端：在 (send, recv) 上完成混合握手，返回加密会话收发半 + 握手信息。
pub async fn server_handshake(
    qsend: SendStream,
    qrecv: RecvStream,
    id: &Arc<ServerIdentity>,
    client_tag: Vec<u8>,
) -> io::Result<(GmPqSender, GmPqReceiver, GmPqInfo)> {
    let (shared, end) = make_bridge();
    tokio::spawn(shuttle(qsend, qrecv, Arc::clone(&shared)));

    let id2 = Arc::clone(id);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (inbox_tx, inbox_rx) = tokio::sync::mpsc::unbounded_channel();
    let shared2 = Arc::clone(&shared);
    std::thread::spawn(move || {
        let started = Instant::now();
        let mut cache = id2.cache.lock().expect("票据缓存锁中毒");
        let mut cfg = ServerConfig {
            cookie: &id2.cookie,
            tickets: &id2.tickets,
            cache: &mut cache,
            anchor: &id2.anchor,
            client_tag: &client_tag,
            ticket_ttl_secs: id2.ticket_ttl_secs,
        };
        let result = server_accept(
            end,
            clone_secret(&id2.sk),
            id2.pk.clone(),
            &mut cfg,
        );
        drop(cache); // 握手完成后释放票据缓存锁（红线 3：跨连接共享但不长占）
        match result {
            Ok(ServerOutcome {
                channel,
                early_data,
                resumed,
            }) => {
                let info = GmPqInfo {
                    session_id: *channel.session_id(),
                    peer_static_key: channel.peer_static_key().to_vec(),
                    resumed,
                    early_data,
                    elapsed: started.elapsed(),
                };
                let _ = tx.send(Ok(info));
                message_loop(channel, shared2, inbox_tx);
            }
            Err(e) => {
                let _ = tx.send(Err(format!("{e}")));
                shared_close(&shared2);
            }
        }
    });
    let info = rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "GM-PQ 工作线程退出"))?
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("GM-PQ 握手失败: {e}")))?;
    Ok((
        GmPqSender { shared },
        GmPqReceiver { inbox: inbox_rx },
        info,
    ))
}

/// 客户端：在 (send, recv) 上完成混合握手（有保存票据则走 0-RTT 恢复）。
pub async fn client_handshake(
    qsend: SendStream,
    qrecv: RecvStream,
    id: &Arc<ClientIdentity>,
) -> io::Result<(GmPqSender, GmPqReceiver, GmPqInfo)> {
    let (shared, end) = make_bridge();
    tokio::spawn(shuttle(qsend, qrecv, Arc::clone(&shared)));

    let id2 = Arc::clone(id);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (inbox_tx, inbox_rx) = tokio::sync::mpsc::unbounded_channel();
    let shared2 = Arc::clone(&shared);
    std::thread::spawn(move || {
        let started = Instant::now();
        let ticket = id2.ticket.lock().expect("票据槽锁中毒").clone();
        let result = match ticket {
            Some((t, psk)) => client_connect_resume(
                end,
                clone_secret(&id2.sk),
                id2.pk.clone(),
                &id2.anchor,
                &t,
                &psk,
                Some(EARLY_DATA_PROBE), // 红线 2：幂等探针
            ),
            None => client_connect_full(
                end,
                clone_secret(&id2.sk),
                id2.pk.clone(),
                &id2.anchor,
            ),
        };
        match result {
            Ok(ClientOutcome {
                channel,
                resumption,
                resumed,
                early_data_accepted,
            }) => {
                // 保存新票据供下次 0-RTT。
                if let Some(t) = resumption {
                    *id2.ticket.lock().expect("票据槽锁中毒") = Some(t);
                }
                let info = GmPqInfo {
                    session_id: *channel.session_id(),
                    peer_static_key: channel.peer_static_key().to_vec(),
                    resumed,
                    early_data: if resumed {
                        Some(format!("early_data_accepted={early_data_accepted}").into_bytes())
                    } else {
                        None
                    },
                    elapsed: started.elapsed(),
                };
                let _ = tx.send(Ok(info));
                message_loop(channel, shared2, inbox_tx);
            }
            Err(e) => {
                let _ = tx.send(Err(format!("{e}")));
                shared_close(&shared2);
            }
        }
    });
    let info = rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "GM-PQ 工作线程退出"))?
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("GM-PQ 握手失败: {e}")))?;
    Ok((
        GmPqSender { shared },
        GmPqReceiver { inbox: inbox_rx },
        info,
    ))
}

/// 构造桥：共享状态 + 交给 gm-pq 阻塞代码的端点。
fn make_bridge() -> (Shared, BlockingEnd) {
    let shared: Shared = Arc::new(Bridge {
        m: Mutex::new(BridgeShared::default()),
        cv: Condvar::new(),
        wire_notify: tokio::sync::Notify::new(),
    });
    let end = BlockingEnd {
        shared: Arc::clone(&shared),
    };
    (shared, end)
}

/// 握手后的消息循环（服务端与客户端共用）。
fn message_loop(
    mut ch: SecureChannel<BlockingEnd>,
    shared: Shared,
    inbox_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    let m = &shared.m;
    let c = &shared.cv;
    loop {
        // 1. 优先排空 outbox。
        loop {
            let msg = m.lock().expect("桥锁中毒").outbox.pop_front();
            match msg {
                Some(plaintext) => {
                    if ch.send_msg(&plaintext).is_err() {
                        shared_close(&shared);
                        return;
                    }
                }
                None => break,
            }
        }
        // 2. 等待：inbound 有数据 / outbox 有新消息 / 关闭。
        {
            let mut g = m.lock().expect("桥锁中毒");
            while g.inbound.is_empty() && g.outbox.is_empty() && !g.closed {
                g = c.wait(g).expect("桥锁中毒");
            }
            if g.closed {
                return;
            }
            if !g.outbox.is_empty() {
                continue;
            }
            drop(g);
        }
        // 3. 收一条消息。
        match ch.recv_msg() {
            Ok(plaintext) => {
                if inbox_tx.send(plaintext).is_err() {
                    shared_close(&shared);
                    return;
                }
            }
            Err(_) => {
                shared_close(&shared);
                return;
            }
        }
    }
}

/// 克隆静态私钥：gm-pq 的 SecretKey 未暴露 clone 字节接口，
/// 通过 public_of + 重新生成不可行——改为要求 Kem::SecretKey: Clone（hybrid 组合器已实现）。
fn clone_secret(sk: &StaticSecretKey) -> StaticSecretKey {
    sk.clone()
}
