//! Homa-lite 传输层：消息导向、无连接、接收端驱动调度。
//!
//! 架构（多 IO 线程）：
//! - [`SenderCore`] / [`ReceiverCore`] 是不碰 socket 的纯状态机（输出 [`Action`]）；
//! - **接收线程**（`io_loop`）只做：recv → 驱动状态机 → 把待发包压入跨线程 `TxQueues`；
//! - **发送线程**（`send_thread`）只做：从 `TxQueues` 批量弹包 → 锁外 `UDP send_to`。
//!
//! 收发分离后 socket syscall 不再占用状态锁：长消息的高分片洪泛不会卡死
//! 短消息的接收与调度活性（benchmark 中短 RPC P99 不再被长 RPC 拖垮），
//! 且发送侧可以一次批量发出整窗分片（真 pacing 的发送端，配合接收端 GRANT 大窗口）。

#[cfg(windows)]
pub mod gro;
pub mod gso;
pub mod packet;
pub mod priority;
pub mod receiver;
pub mod sender;
pub mod txqueue;

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use packet::{Packet, PacketType};
use receiver::ReceiverCore;
use sender::SenderCore;
use txqueue::{FLUSH_BUDGET, TxQueues};

/// 状态机产出的动作
#[derive(Debug)]
pub enum Action {
    /// 向 dest 发一个 UDP 数据报
    Send { dest: SocketAddr, bytes: Vec<u8> },
    /// 一条消息重组完成，交付给上层
    Deliver {
        src: SocketAddr,
        msg_id: u64,
        data: Vec<u8>,
    },
}

/// 传输层参数（对标 Homa 默认值的可调版本）
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// UDP 数据报负载分片大小（字节）
    pub packet_size: usize,
    /// 未调度窗口：每条消息首 RTT 无需授权直接发送的字节数（Homa 默认 ~10KB）
    pub unscheduled_bytes: usize,
    /// 每次 GRANT 的授予增量（约一个 BDP；越大，长消息的授权往返越少）
    pub grant_increment: usize,
    /// 接收端判定授予窗口内缺包的超时
    pub resend_timeout: Duration,
    /// 接收端判定 GRANT 丢失（授权后无进展）的超时
    pub grant_timeout: Duration,
    /// 发送端停滞探测间隔
    pub poke_timeout: Duration,
    /// 「确认前重发」窗口的保守 RTT 估计（短消息无 RTT 样本时使用）。
    /// 带 retransmit 标志的消息（RPC 请求）整条发完后，若在此窗口内未收到确认
    /// （响应 = 隐式 ACK，上层 confirm 摘除），重发首分片。保守取值（默认 500ms）
    /// 保证无丢包时响应先到、确认先于窗口触发——零额外重发。
    pub retransmit_timeout: Duration,
    /// 消息发完后保留状态响应迟到 RESEND 的驻留时间
    pub linger: Duration,
    /// send_to 的整体超时（超过则放弃，由上层 RPC 重试）
    pub send_timeout: Duration,
    /// 接收端允许的最大并发在收消息数，超出回 BUSY
    pub max_incoming: usize,
    /// overcommit：同时授权的消息条数（Homa 默认 8，loopback 骨架默认 2）
    pub overcommit: usize,
    /// 防饿死：等待授权超过该时长强制入授权集合
    pub starve_threshold: Duration,
    /// UDP 收发缓冲区大小（loopback 突发吞包主因是默认缓冲太小）
    pub socket_buf: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            packet_size: 1200,
            unscheduled_bytes: 10_240,
            grant_increment: 262_144, // 256KB：比默认 64KB 大 4×，长消息授权往返减到 ~1/4
            resend_timeout: Duration::from_millis(20),
            grant_timeout: Duration::from_millis(40),
            poke_timeout: Duration::from_millis(50),
            retransmit_timeout: Duration::from_millis(500),
            linger: Duration::from_secs(5),
            send_timeout: Duration::from_secs(30),
            max_incoming: 1024,
            overcommit: 2,
            starve_threshold: Duration::from_millis(200),
            socket_buf: 16 << 20,
        }
    }
}

/// 共享状态（IO 线程与 API 调用线程并发访问）
struct State {
    sender: SenderCore,
    receiver: ReceiverCore,
    /// 已重组完成、等待上层 recv 取走的消息
    completed: VecDeque<(SocketAddr, Vec<u8>)>,
}

struct Inner {
    socket: UdpSocket,
    /// Windows 下启用 GRO 的接收句柄（一次 recvmsg 拿合并缓冲，按 stride 拆包）。
    /// None = GRO 初始化失败，回退逐包 recv_from。
    #[cfg(windows)]
    gro: Option<gro::Gro>,
    state: Mutex<State>,
    /// 跨线程发送队列：状态锁内只入队，发送线程锁外批量 syscall
    tx: TxQueues,
    /// 有消息交付 / 发送完成时通知等待者
    cv: Condvar,
    msg_counter: AtomicU64,
    shutdown: AtomicBool,
    send_timeout: Duration,
    /// 未调度窗口：整体落在窗口内的消息走调用线程直发（短消息免 send_loop 线程切换）
    unscheduled_bytes: usize,
    /// 分片负载容量（GSO 聚合的满包/步进基准）。仅 Windows 的 GSO 路径读取
    /// （`send_segment` / send_loop 的聚合器都是 `#[cfg(windows)]`）；Linux 走
    /// 逐包回退、从不读它，故随 send_segment 一并 gate 到 Windows，否则
    /// `-D warnings`（CI RUSTFLAGS）在 Linux 上报 dead_code 硬错误。
    #[cfg(windows)]
    packet_size: usize,
    /// 调试计数（HOMA_TRACE=1 时 probe 打印）：send_loop syscall 数 / GSO 段数 / io_loop 包数
    send_syscalls: AtomicU64,
    gso_segments: AtomicU64,
    recv_packets: AtomicU64,
    /// io_loop 锁内批处理累计耗时（决定接收端单点吞吐上限）。等锁 vs 持锁分离：
    /// io_lock_ns=纯持锁(锁到手到释放)，io_lock_wait_ns=等锁（含 syscall 往返）。
    io_lock_ns: AtomicU64,
    io_lock_wait_ns: AtomicU64,
    io_batches: AtomicU64,
    /// 调试追踪（HOMA_TRACE=1 启用）：(时间戳, 事件, msg_id)
    trace_on: bool,
    trace: Mutex<Vec<(Instant, String, u64)>>,
}

impl Inner {
    fn trace(&self, ev: &str, id: u64) {
        if self.trace_on {
            self.trace
                .lock()
                .unwrap()
                .push((Instant::now(), ev.to_string(), id));
        }
    }
}

/// 消息导向传输句柄。克隆廉价（内部 Arc），可多线程并发 send/recv。
pub struct Transport {
    inner: Arc<Inner>,
    io_thread: Option<JoinHandle<()>>,
    /// 多个发送线程从同一跨线程队列并行弹批 → 锁外批量 syscall。
    /// UDP loopback 每包 ~5µs 是瓶颈，2 线程实测吞吐 1.5×（更多线程亚线性）
    send_threads: Vec<JoinHandle<()>>,
}

impl Transport {
    /// 绑定本地地址并启动 IO 线程（接收）与发送线程
    pub fn bind(addr: &str, cfg: TransportConfig) -> io::Result<Self> {
        // 用 socket2 放大 UDP 收发缓冲：默认缓冲在授权窗口突发下会整片丢包
        let s2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        s2.set_recv_buffer_size(cfg.socket_buf)?;
        s2.set_send_buffer_size(cfg.socket_buf)?;
        s2.bind(
            &addr
                .parse::<SocketAddr>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                .into(),
        )?;
        let socket: UdpSocket = s2.into();
        // IO 线程需要周期性 tick（RESEND / 重发 GRANT / 发送端探针），给读设短超时
        socket.set_read_timeout(Some(Duration::from_millis(5)))?;
        // Windows：启用 UDP GRO（一次 recvmsg 拿合并缓冲）。失败不致命（回退逐包 recv）
        #[cfg(windows)]
        let gro = match gro::Gro::new(&socket) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("[homa-rpc] GRO 不可用（回退逐包接收）: {e}");
                None
            }
        };
        let send_timeout = cfg.send_timeout;
        let unscheduled_bytes = cfg.unscheduled_bytes;
        #[cfg(windows)]
        let packet_size = cfg.packet_size;
        let inner = Arc::new(Inner {
            socket,
            #[cfg(windows)]
            gro,
            state: Mutex::new(State {
                sender: SenderCore::new(cfg.clone()),
                receiver: ReceiverCore::new(cfg),
                completed: VecDeque::new(),
            }),
            tx: TxQueues::new(),
            cv: Condvar::new(),
            msg_counter: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
            send_timeout,
            unscheduled_bytes,
            #[cfg(windows)]
            packet_size,
            send_syscalls: AtomicU64::new(0),
            gso_segments: AtomicU64::new(0),
            recv_packets: AtomicU64::new(0),
            io_lock_ns: AtomicU64::new(0),
            io_lock_wait_ns: AtomicU64::new(0),
            io_batches: AtomicU64::new(0),
            trace_on: std::env::var("HOMA_TRACE").is_ok_and(|v| v == "1"),
            trace: Mutex::new(Vec::new()),
        });

        let recv_inner = Arc::clone(&inner);
        let io_thread = std::thread::Builder::new()
            .name("homa-io-recv".into())
            .spawn(move || io_loop(recv_inner))?;

        const SEND_THREADS: usize = 2;
        let mut send_threads = Vec::new();
        for i in 0..SEND_THREADS {
            let send_inner = Arc::clone(&inner);
            let t = std::thread::Builder::new()
                .name(format!("homa-io-send-{i}").into())
                .spawn(move || send_loop(send_inner))?;
            send_threads.push(t);
        }

        Ok(Self {
            inner,
            io_thread: Some(io_thread),
            send_threads,
        })
    }

    /// 本地绑定地址
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }

    /// 调试：导出追踪事件（HOMA_TRACE=1 时记录）
    pub fn take_trace(&self) -> Vec<(Instant, String, u64)> {
        let mut t = self.inner.trace.lock().unwrap();
        std::mem::take(&mut *t)
    }

    /// 调试：导出 syscall/GSO/收包计数
    pub fn debug_stats(&self) -> String {
        let batches = self.inner.io_batches.load(Ordering::Relaxed);
        let pkts = self.inner.recv_packets.load(Ordering::Relaxed);
        let lock_ns = self.inner.io_lock_ns.load(Ordering::Relaxed);
        let wait_ns = self.inner.io_lock_wait_ns.load(Ordering::Relaxed);
        let retx = self.inner.state.lock().unwrap().sender.retransmit_count();
        format!(
            "send_syscalls={} gso_segments={} recv_packets={} retransmit_pokes={} io_lock_batches={} io_lock_avg_batch={:.1}µs(持锁) io_lock_wait_batch={:.1}µs(等锁) io_lock_per_pkt={:.2}µs",
            self.inner.send_syscalls.load(Ordering::Relaxed),
            self.inner.gso_segments.load(Ordering::Relaxed),
            pkts,
            retx,
            batches,
            if batches > 0 {
                lock_ns as f64 / batches as f64 / 1e3
            } else {
                0.0
            },
            if batches > 0 {
                wait_ns as f64 / batches as f64 / 1e3
            } else {
                0.0
            },
            if pkts > 0 {
                (lock_ns + wait_ns) as f64 / pkts as f64 / 1e3
            } else {
                0.0
            },
        )
    }

    /// 调试：导出内部状态机快照（在发消息、在收消息、待交付数）
    pub fn debug_state(&self) -> String {
        let st = self.inner.state.lock().unwrap();
        format!(
            "发送中: {}\n在收: {}\n待交付: {}",
            st.sender.debug_dump(),
            st.receiver.debug_dump(),
            st.completed.len()
        )
    }

    /// 发送一条完整消息（消息导向语义：对端要么收全要么不收）。
    /// 阻塞直到全部字节发出（含等待 GRANT），超时返回 TimedOut。
    pub fn send_to(&self, dest: SocketAddr, data: &[u8]) -> io::Result<u64> {
        self.send_vec(dest, data.to_vec())
    }

    /// 与 send_to 等语义，但**移动**数据而非拷贝：调用方已拥有 Vec 时免去一次全量复制
    ///（长消息 1MiB 负载的 memcpy 是 RPC 路径上可省的大头）。
    /// 普通发送：**不**进入「确认前重发」窗口（服务端响应等由对端重发请求触发
    /// 幂等回放的路径走这里——自身重发会造成双倍响应流量）。
    pub fn send_vec(&self, dest: SocketAddr, data: Vec<u8>) -> io::Result<u64> {
        self.send_impl(dest, data, false)
    }

    /// 带「确认前重发」窗口的发送（RPC 请求路径）：消息发完后若未收到确认
    /// （上层收到响应后调 [`Transport::confirm`]），发送端在保守 RTT 估计
    /// （`TransportConfig::retransmit_timeout`，默认 500ms）后重发首分片——
    /// 修复短消息单包丢失时接收端无法发 RESEND（它从没见过这条消息）的死区。
    /// 无丢包时响应先到、confirm 摘除消息，窗口从不触发（零额外重发）。
    pub fn send_pokeable(&self, dest: SocketAddr, data: Vec<u8>) -> io::Result<u64> {
        self.send_impl(dest, data, true)
    }

    fn send_impl(&self, dest: SocketAddr, data: Vec<u8>, retransmit: bool) -> io::Result<u64> {
        let data_len = data.len();
        let msg_id = self.inner.msg_counter.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let deadline = now + self.inner.send_timeout;

        // 重发窗口只对「整体落在未调度窗口内」的短消息生效——那是接收端无法
        // RESEND（从没见过）的唯一死区。长消息在发送中途被接收端从任意分片获知，
        // 由停滞探针 + RESEND 恢复；对长消息开窗口只会因「入队完成→响应到达」的
        // 时间差在无丢包时触发空重发（双倍流量）。
        let retransmit = retransmit && data_len <= self.inner.unscheduled_bytes;

        let actions = {
            let mut st = self.inner.state.lock().unwrap();
            if retransmit {
                st.sender.start_retransmit(dest, msg_id, data, now)
            } else {
                st.sender.start(dest, msg_id, data, now)
            }
        };

        // 短消息（整体落在未调度窗口内）：调用线程直发全部，免去 send_loop 线程切换的
        // 数百 µs 延迟（loopback 实测短 RPC P50 快 ~5×）。直发在锁外（start 已释放状态锁）。
        // 长消息不能直发——8 个 worker 各自阻塞在长消息直发 + 等 GRANT，并发度塌陷；
        // 必须入队由 send_loop 批量发，worker 快速返回保持并发。
        if data_len <= self.inner.unscheduled_bytes {
            for a in &actions {
                if let Action::Send { dest, bytes } = a {
                    self.inner.socket.send_to(bytes, *dest)?;
                }
            }
            self.inner.trace("send_queued", msg_id);
            return Ok(msg_id);
        }
        self.dispatch(actions);
        self.inner.trace("send_queued", msg_id);

        // 等待全部分片**已压入发送队列**（is_done = done_at 置位）。
        // 队列弹空由 send_loop 负责；Transport 释放时 send_loop 在退出前冲刷干净，
        // 因此 send_to 无需等全局队列空——多并发 worker 各等各的消息，不被他人积压拖住
        //（旧实现等「全局 tx 空」，一条慢消息会让所有已完成的消息也阻塞到它发完）。
        let mut st = self.inner.state.lock().unwrap();
        loop {
            if st.sender.is_done(dest, msg_id) {
                // 不立即销毁：留 linger 期响应对端迟到的 RESEND，由 sender.tick 自动回收
                return Ok(msg_id);
            }
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                st.sender.finish(dest, msg_id);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "homa send_to timeout",
                ));
            }
            let (guard, _) = self.inner.cv.wait_timeout(st, remain).unwrap();
            st = guard;
        }
    }

    /// 确认一条消息已被对端完整接收（RPC 收到响应 = 请求的隐式 ACK）：
    /// 停止其「确认前重发」窗口；已发完则立即回收（对端收全即不会再发 RESEND，
    /// 无需留 linger）。消息不存在时无操作。
    pub fn confirm(&self, dest: SocketAddr, msg_id: u64) {
        let mut st = self.inner.state.lock().unwrap();
        st.sender.confirm(dest, msg_id);
    }

    /// 放弃一条消息（超时重试等场景）：从发送状态移除，停止一切重发/重传。
    pub fn finish(&self, dest: SocketAddr, msg_id: u64) {
        let mut st = self.inner.state.lock().unwrap();
        st.sender.finish(dest, msg_id);
    }

    /// 调试：「确认前重发」窗口触发次数（net_probe 用它验证「无丢包零额外重发」）
    pub fn retransmit_pokes(&self) -> u64 {
        self.inner.state.lock().unwrap().sender.retransmit_count()
    }

    /// 接收一条完整消息。timeout 内无消息返回 WouldBlock。
    pub fn recv(&self, timeout: Duration) -> io::Result<(SocketAddr, Vec<u8>)> {
        let deadline = Instant::now() + timeout;
        let mut st = self.inner.state.lock().unwrap();
        loop {
            if let Some((src, data)) = st.completed.pop_front() {
                return Ok((src, data));
            }
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "homa recv timeout",
                ));
            }
            let (guard, _) = self.inner.cv.wait_timeout(st, remain).unwrap();
            st = guard;
        }
    }

    /// 把状态机产出的发包动作压入跨线程发送队列（长消息路径）
    fn dispatch(&self, actions: Vec<Action>) {
        let mut st = self.inner.state.lock().unwrap();
        drain(&self.inner, &mut st, actions);
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        // 发送线程空队列等待时也要能退出：置位 + 唤醒，wait_batch 返回空批
        self.inner.tx.shutdown();
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(t) = self.io_thread.take() {
            let _ = t.join();
        }
        for t in self.send_threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// 处理状态机产出：Deliver 进完成队列并唤醒 recv；
/// Send 压入跨线程发送队列（不发 socket，由发送线程锁外批量 syscall）。
/// 因此状态锁内只有纯内存操作，绝不阻塞在 I/O 上。
fn drain(inner: &Inner, st: &mut State, actions: Vec<Action>) {
    let mut delivered = false;
    for a in actions {
        match a {
            Action::Deliver { src, data, msg_id } => {
                st.completed.push_back((src, data));
                delivered = true;
                inner.trace("deliver", msg_id);
            }
            Action::Send { dest, bytes } => {
                inner.tx.push(dest, bytes);
            }
        }
    }
    if delivered {
        inner.cv.notify_all();
    }
}

/// 发送线程：从跨线程队列批量弹包 → 锁外 send。
/// 一次批量可发出整窗分片（真 pacing 的发送端，减少逐包唤醒开销）。
///
/// Windows 下启用 GSO 聚合：同消息连续满包拼段，一次 syscall 提交 ≤64KB
/// （1MiB 消息 874 分片 → ~17 段），内核切成对端透明的小数据报；
/// 其他平台逐包 send_to（UDP_SEGMENT 路径待补）。
///
/// 关闭后仍继续冲刷队列直到弹空（send_to 只等「入队完成」就返回，
/// 剩下的积压分片靠这里的 flush 保证最终发出，对端不至于收不全）。
fn send_loop(inner: Arc<Inner>) {
    #[cfg(windows)]
    let mut agg = gso::GsoAggregator::new(inner.packet_size);
    loop {
        let batch = inner.tx.wait_batch(FLUSH_BUDGET);
        if batch.is_empty() {
            // wait_batch 仅「空队列且 shutdown」时返回空批 → 退出；
            // 其余空批（防御）回到队列检查
            if inner.shutdown.load(Ordering::Relaxed) {
                break;
            }
            continue;
        }
        for (dest, bytes) in batch {
            // Windows：尽量并入 GSO 段；不能聚合的先冲段再单发
            #[cfg(windows)]
            {
                if agg.try_push(dest, &bytes) {
                    continue;
                }
                if let Some((d, seg, n)) = agg.finish() {
                    gso::send_segment(&inner, d, &seg, n);
                    inner.send_syscalls.fetch_add(1, Ordering::Relaxed);
                    inner.gso_segments.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            // UDP 发送失败（如 ICMP 不可达）不致命，忽略继续
            let _ = inner.socket.send_to(&bytes, dest);
            inner.send_syscalls.fetch_add(1, Ordering::Relaxed);
        }
        // 冲掉本批残余段（跨批聚合窗口保持，段不满也发，避免消息尾包滞留）
        #[cfg(windows)]
        if let Some((d, seg, n)) = agg.finish() {
            gso::send_segment(&inner, d, &seg, n);
            inner.send_syscalls.fetch_add(1, Ordering::Relaxed);
            inner.gso_segments.fetch_add(n as u64, Ordering::Relaxed);
        }
        // 本批发出后队列可能已空：唤醒 send_to 等待者复检 is_done
        inner.cv.notify_all();
    }
}

/// 在**单次状态锁**内处理一批数据报（GRO 合并缓冲拆出的多个 Homa 包）。
/// 一次锁 = 一个 GSO 段：1MiB 消息 874 包 → ~17 次锁往返，接收端锁竞争不再是瓶颈。
/// 拆包按 stride 步进（合并段内每数据报等长）；最后不足 stride 的余数是尾包，单独处理。
/// 零拷贝：chunk 直接借用接收缓冲的切片，不做 to_vec。
fn process_batch(inner: &Inner, src: SocketAddr, data: &[u8], stride: usize) {
    let now = Instant::now();
    let lock_t0 = Instant::now();
    let mut st = inner.state.lock().unwrap();
    let lock_held_t0 = Instant::now();
    let mut actions = Vec::new();
    let stride = if stride == 0 { data.len() } else { stride };
    let mut off = 0usize;
    while off < data.len() {
        let step = stride.min(data.len() - off);
        let chunk = &data[off..off + step];
        off += stride;
        let Ok((pkt, payload)) = Packet::decode(chunk) else {
            continue;
        };
        match pkt.typ {
            PacketType::Data => st
                .receiver
                .handle_data(src, &pkt, payload, now, &mut actions),
            PacketType::Grant => {
                st.sender.handle_grant(src, &pkt, now, &mut actions);
                inner.trace("grant", pkt.msg_id);
                if st.sender.is_done(src, pkt.msg_id) {
                    inner.cv.notify_all(); // 唤醒 send_to 等待者
                }
            }
            PacketType::Resend => st.sender.handle_resend(src, &pkt, now, &mut actions),
            PacketType::Busy => st.sender.handle_busy(src, &pkt, now),
        }
        inner.recv_packets.fetch_add(1, Ordering::Relaxed);
    }
    drain(inner, &mut st, actions);
    inner.io_lock_wait_ns.fetch_add(
        lock_held_t0.duration_since(lock_t0).as_nanos() as u64,
        Ordering::Relaxed,
    );
    inner
        .io_lock_ns
        .fetch_add(lock_held_t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    inner.io_batches.fetch_add(1, Ordering::Relaxed);
}

/// 接收线程主循环：收包 → 驱动状态机 → 压入发送队列。
/// Windows 走 GRO 合并缓冲（一次 recvmsg 拿一个 GSO 段的多包，单次锁批处理）；
/// GRO 不可用或非 Windows 回退逐包接收。
/// tick 按时间触发（每 5ms）：高负载期收包队列不空、读永不超时，
/// 若只在读超时 tick 会导致 RESEND/重授权被饿死，造成系统性停滞。
fn io_loop(inner: Arc<Inner>) {
    #[cfg(windows)]
    let mut data_buf = vec![0u8; gro::RECV_BUF_SIZE];
    #[cfg(windows)]
    let mut ctrl_buf = [0u8; 128];
    #[cfg(not(windows))]
    let mut buf = vec![0u8; 1 << 16];
    let tick_interval = Duration::from_millis(5);
    let mut last_tick = Instant::now();
    while !inner.shutdown.load(Ordering::Relaxed) {
        #[cfg(windows)]
        {
            if let Some(g) = inner.gro.as_ref() {
                match g.recv(&inner.socket, &mut data_buf, &mut ctrl_buf) {
                    Ok((n, stride, src)) if n > 0 => {
                        process_batch(&inner, src, &data_buf[..n], stride);
                    }
                    Ok(_) => {} // 0 长度数据报，忽略
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut => {}
                    Err(_) => {
                        if inner.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            } else {
                // GRO 初始化失败：回退逐包接收
                match inner.socket.recv_from(&mut data_buf) {
                    Ok((n, src)) => {
                        process_batch(&inner, src, &data_buf[..n], n);
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut => {}
                    Err(_) => {
                        if inner.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            match inner.socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    process_batch(&inner, src, &buf[..n], n);
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {
                    if inner.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
        // 按时间驱动 tick（无论本次是否收到包）
        let now = Instant::now();
        if now.duration_since(last_tick) >= tick_interval {
            last_tick = now;
            let mut st = inner.state.lock().unwrap();
            let mut actions = Vec::new();
            st.sender.tick(now, &mut actions);
            st.receiver.tick(now, &mut actions);
            drain(&inner, &mut st, actions);
        }
    }
}
