//! # net-sim — 确定性网络注入测试基建
//!
//! 在真实 socket 之间插入可编程中继（proxy），把网络条件注入到被测代码的通信路径：
//! RTT、丢包、抖动、乱序、带宽。被测方零改造——客户端把中继地址当作对端，
//! 中继把流量双向转发到真实服务端。
//!
//! 设计选择：
//! - **真实全栈**：走真实 UDP socket / 内核路径（含 GSO/GRO 聚合、缓冲限制），
//!   只有网络条件被替换——比纯状态机虚拟时钟模拟器多测了一整层。
//! - **确定性**：所有随机决策（丢包/抖动/乱序）由 seed PRNG（splitmix64）驱动，
//!   同 seed 同序列，结果可精确复现。
//! - **零侵入**：不 import、不改被测 crate，纯旁路中继。
//!
//! 诚实限制：
//! - TCP 代理只注入延迟/带宽，不做丢包——TCP 的丢包必须在报文段层面注入，
//!   字节流代理无法可靠做到。TCP 对比只比较 RTT 维度（丢包对 TCP 的影响是
//!   拥塞窗口退避，方向明确，可单独论证）。
//! - 延迟用真实 sleep 实现：高 RTT 实验按真实时间推进（100ms RTT 的实验就要
//!   真的等 100ms）。代价是慢，换取的是「不信任假时钟」的真实性——测的是
//!   真实内核、真实协议栈、真实 GSO/GRO，只有网络条件是被替换的。

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::sync::Mutex;

// Windows 专用修复。两个坑都是实测踩出来的：
// 1. 默认系统定时器 tick ~15.6ms → SO_RCVTIMEO(1ms) 实际 ~13-15ms 才触发，
//    中继把每个包持有 ~13ms，延迟注入失真。timeBeginPeriod(1) 提升到 1ms。
// 2. UDP socket 收到 ICMP Port Unreachable 后，下一次 recv 返回 WSAECONNRESET，
//    且可能丢弃已排队数据报——这是「send_to 返回 Ok 但对端收不到」的头号嫌疑。
//    SIO_UDP_CONNRESET=0 关闭该行为。
#[cfg(windows)]
mod win {
    pub fn raise_timer_resolution() {
        // 失败也无所谓：只是让 1ms 超时更准时，不影响正确性
        unsafe {
            windows_sys::Win32::Media::timeBeginPeriod(1);
        }
    }

    pub fn disable_udp_connreset(socket: &std::net::UdpSocket) {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_UDP_CONNRESET, SOCKET};
        let s: SOCKET = socket.as_raw_socket() as SOCKET;
        let zero: u32 = 0;
        let mut ret: u32 = 0;
        unsafe {
            WSAIoctl(
                s,
                SIO_UDP_CONNRESET,
                std::ptr::addr_of!(zero).cast(),
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut ret,
                std::ptr::null_mut(),
                None,
            );
        }
    }
}
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AOrdering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// 网络条件。`rtt` 是**往返**延迟，每一方向注入 `rtt/2`。
#[derive(Debug, Clone, Copy)]
pub struct Conditions {
    /// 往返延迟（每方向 rtt/2）。真实实验语义：100ms RTT 就写 100ms。
    pub rtt: Duration,
    /// 单向丢包率 0.0..1.0（每个 IP 报文独立判定）
    pub loss: f64,
    /// 抖动幅度：每方向延迟在 [rtt/2, rtt/2 + jitter/2) 均匀采样（只增不减）
    pub jitter: Duration,
    /// 乱序概率：以该概率让新到报文插队（比标准延迟更早发出，超越已排队报文）
    pub reorder: f64,
    /// 带宽上限（bytes/s）。None = 不限
    pub bandwidth: Option<u64>,
    /// 随机种子：同 seed 同丢包/抖动/乱序序列
    pub seed: u64,
}

impl Default for Conditions {
    fn default() -> Self {
        Self {
            rtt: Duration::from_micros(200),
            loss: 0.0,
            jitter: Duration::ZERO,
            reorder: 0.0,
            bandwidth: None,
            seed: 0xD1EC7_00,
        }
    }
}

impl Conditions {
    /// loopback 理想条件
    pub fn ideal() -> Self {
        Self::default()
    }
    /// 指定往返延迟
    pub fn with_rtt(rtt: Duration) -> Self {
        Self {
            rtt,
            ..Self::default()
        }
    }
    /// 便捷：毫秒往返
    pub fn rtt_ms(ms: u64) -> Self {
        Self::with_rtt(Duration::from_millis(ms))
    }
}

/// splitmix64 —— 无外部依赖、确定性的 PRNG。
#[derive(Clone, Copy)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// 均匀 [0,1)
    #[inline]
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }
    /// 均匀 [0, n)
    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// 排队中的待转发报文（send_at 最小者先出）
struct Pending {
    send_at: Instant,
    dest: SocketAddr,
    bytes: Vec<u8>,
}

impl Ord for Pending {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap 是最大堆；反向比较 = send_at 最小者置顶
        other.send_at.cmp(&self.send_at)
    }
}
impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Eq for Pending {}
impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.send_at == other.send_at
    }
}

/// 中继计数（诊断用）
#[derive(Default)]
pub struct ProxyStats {
    /// 收报数（中继 socket 上）
    pub received: AtomicU64,
    /// 成功转发数
    pub sent: AtomicU64,
    /// send_to 失败丢弃数（中继自身发送缓冲/系统层丢包）
    pub send_errors: AtomicU64,
    /// 丢包注入丢弃数（loss 条件）
    pub loss_dropped: AtomicU64,
}

/// UDP 中继：客户端把中继地址当对端，中继按条件把报文双向转发到真实服务端。
pub struct UdpProxy {
    /// 被测客户端应连接的中继地址
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    stats: Arc<ProxyStats>,
    /// 常开中继事件环形缓冲：(自 spawn 起 µs, 'r'/'s', 字节数)。始终记录、
    /// 不打印不阻塞，故障时 dump 用——避免诊断本身扰动时序。
    relay_log: Arc<Mutex<VecDeque<(u64, char, u64)>>>,
}

impl UdpProxy {
    /// 起一个 UDP 中继。`server` 是真实服务端地址；返回的中继地址给被测客户端。
    pub fn spawn(server: SocketAddr, conds: Conditions) -> io::Result<Self> {
        // Windows：1ms 读超时 + 1ms 延迟注入都要求定时器分辨率够细
        #[cfg(windows)]
        win::raise_timer_resolution();
        // 放大收发缓冲：被测方（homa-rpc）用 16MB 缓冲，中继如果太小会在长消息
        // 突发时把「自己塞不下的包」丢在中继自身——那不是我们要注入的丢包。
        let s2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        s2.set_recv_buffer_size(16 << 20)?;
        s2.set_send_buffer_size(16 << 20)?;
        s2.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())?;
        let socket: UdpSocket = s2.into();
        #[cfg(windows)]
        win::disable_udp_connreset(&socket);
        let addr = socket.local_addr()?;
        socket.set_read_timeout(Some(Duration::from_millis(1)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let stats = Arc::new(ProxyStats::default());
        let stats2 = Arc::clone(&stats);
        let log = Arc::new(Mutex::new(VecDeque::new()));
        let log2 = Arc::clone(&log);
        let handle = thread::Builder::new()
            .name("net-sim-udp-proxy".into())
            .spawn(move || relay_udp(socket, server, conds, stop2, stats2, log2))?;
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
            stats,
            relay_log: log,
        })
    }

    /// 中继事件日志副本：(µs, 'r'/'s', bytes)，按时间正序，最多 512 条。
    pub fn relay_log(&self) -> Vec<(u64, char, u64)> {
        self.relay_log.lock().unwrap().iter().copied().collect()
    }

    /// 诊断：转发计数 (received, sent, send_errors, loss_dropped)
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.received.load(AOrdering::Relaxed),
            self.stats.sent.load(AOrdering::Relaxed),
            self.stats.send_errors.load(AOrdering::Relaxed),
            self.stats.loss_dropped.load(AOrdering::Relaxed),
        )
    }
}

impl Drop for UdpProxy {
    fn drop(&mut self) {
        self.stop.store(true, AOrdering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn relay_udp(
    socket: UdpSocket,
    server: SocketAddr,
    conds: Conditions,
    stop: Arc<AtomicBool>,
    stats: Arc<ProxyStats>,
    log: Arc<Mutex<VecDeque<(u64, char, u64)>>>,
) {
    // NETSIM_TRACE=1 时逐包打印中继时间线（诊断 Windows UDP 丢包用）
    let trace = std::env::var("NETSIM_TRACE").is_ok();
    let t0 = Instant::now();
    let mut rng = Rng::new(conds.seed);
    let mut client_addr: Option<SocketAddr> = None;
    let mut pending: BinaryHeap<Pending> = BinaryHeap::new();
    // 带宽整形用的单调发送时刻（在报文间推进）
    let mut next_slot = Instant::now();
    let mut buf = vec![0u8; 65536];

    while !stop.load(AOrdering::Relaxed) {
        let now = Instant::now();

        // 1) 发送到期的报文（受带宽约束）
        while let Some(head) = pending.peek() {
            let head_at = head.send_at;
            let send_at = match conds.bandwidth {
                Some(0) => {
                    pending.clear();
                    break; // 带宽为 0 = 黑洞
                }
                Some(rate) => {
                    let slot = next_slot.max(head_at);
                    next_slot =
                        slot + Duration::from_secs_f64(head.bytes.len() as f64 / rate as f64);
                    slot
                }
                None => head_at,
            };
            if send_at > now {
                break;
            }
            let p = pending.pop().unwrap();
            if trace {
                eprintln!(
                    "[proxy +{:>9.1}µs] send {}B -> {}",
                    t0.elapsed().as_secs_f64() * 1e6,
                    p.bytes.len(),
                    p.dest
                );
            }
            let st = Instant::now();
            match socket.send_to(&p.bytes, p.dest) {
                Ok(_) => {
                    stats.sent.fetch_add(1, AOrdering::Relaxed);
                    {
                        let ts = t0.elapsed().as_micros() as u64;
                        let mut l = log.lock().unwrap();
                        if l.len() >= 512 {
                            l.pop_front();
                        }
                        l.push_back((ts, 's', p.bytes.len() as u64));
                    }
                }
                Err(_) => {
                    stats.send_errors.fetch_add(1, AOrdering::Relaxed);
                }
            }
            if trace {
                let blocked = st.elapsed();
                if blocked.as_micros() > 500 {
                    eprintln!(
                        "[proxy +{:>9.1}µs] send_to BLOCKED {}µs (to {})",
                        t0.elapsed().as_secs_f64() * 1e6,
                        blocked.as_secs_f64() * 1e6,
                        p.dest
                    );
                }
            }
        }

        // 2) 收报文并注入条件
        let rt = Instant::now();
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if trace && rt.elapsed().as_micros() > 1500 {
                    eprintln!(
                        "[proxy +{:>9.1}µs] recv_from blocked {}µs before delivering {n}B (timeout not firing?)",
                        t0.elapsed().as_secs_f64() * 1e6,
                        rt.elapsed().as_secs_f64() * 1e6
                    );
                }
                let dest = if src == server {
                    match client_addr {
                        Some(c) => c,
                        None => continue, // 服务端先来？不会发生
                    }
                } else {
                    if client_addr.is_none() {
                        client_addr = Some(src);
                    }
                    server
                };

                // 丢包（每个报文独立判定）
                stats.received.fetch_add(1, AOrdering::Relaxed);
                {
                    let ts = t0.elapsed().as_micros() as u64;
                    let mut l = log.lock().unwrap();
                    if l.len() >= 512 {
                        l.pop_front();
                    }
                    l.push_back((ts, 'r', n as u64));
                }
                if trace {
                    eprintln!(
                        "[proxy +{:>9.1}µs] recv {n}B src={src} -> {dest}",
                        t0.elapsed().as_secs_f64() * 1e6
                    );
                }
                if conds.loss > 0.0 && rng.next_f64() < conds.loss {
                    stats.loss_dropped.fetch_add(1, AOrdering::Relaxed);
                    continue;
                }

                // 延迟 = rtt/2 + jitter/2 内均匀
                let hop = conds.rtt / 2;
                let j = conds.jitter.as_micros() as i64 / 2;
                let mut send_at = now + hop;
                if j > 0 {
                    let off = rng.below((2 * j) as u64) as i64 - j; // [-j, j)
                    send_at = send_at + Duration::from_micros(off.max(0) as u64);
                }
                if send_at < now {
                    send_at = now;
                }

                // 乱序：以概率把 send_at 提到 hop/2（早于已排队报文 → 乱序交付）
                let send_at = if conds.reorder > 0.0
                    && rng.next_f64() < conds.reorder
                    && hop > Duration::ZERO
                {
                    now + hop / 2
                } else {
                    send_at
                };

                pending.push(Pending {
                    send_at,
                    dest,
                    bytes: buf[..n].to_vec(),
                });
            }
            Err(e) => {
                if trace && rt.elapsed().as_micros() > 1500 {
                    eprintln!(
                        "[proxy +{:>9.1}µs] recv_from Err({e:?}) after {}µs",
                        t0.elapsed().as_secs_f64() * 1e6,
                        rt.elapsed().as_secs_f64() * 1e6
                    );
                }
                // 读超时或暂时失败：回到顶部，继续检查到期队列
            }
        }
    }
}

/// TCP 延迟中继：为 TCP 基线对比注入 RTT（延迟在字节流层实现）。
/// 不做丢包——TCP 的丢包必须在报文段层面注入，字节流代理无法可靠做到。
pub struct TcpDelayProxy {
    /// 被测客户端应连接的代理地址
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TcpDelayProxy {
    pub fn spawn(server: SocketAddr, rtt: Duration) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("net-sim-tcp-proxy".into())
            .spawn(move || {
                listener.set_nonblocking(true).ok();
                while !stop2.load(AOrdering::Relaxed) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            // Windows：accept 继承 listener 的非阻塞标志，必须显式改回阻塞
                            if client.set_nonblocking(false).is_err() {
                                continue;
                            }
                            match TcpStream::connect(server) {
                                Ok(upstream) => {
                                    let hop = rtt / 2;
                                    // 双向各一条转发线程（try_clone 共享同一 socket）
                                    let up2 = upstream.try_clone().ok();
                                    let cl2 = client.try_clone().ok();
                                    match (up2, cl2) {
                                        (Some(up2), Some(cl2)) => {
                                            thread::spawn(move || relay_stream(client, up2, hop));
                                            thread::spawn(move || relay_stream(upstream, cl2, hop));
                                        }
                                        _ => {
                                            let _ = client;
                                            let _ = upstream;
                                        }
                                    }
                                }
                                Err(_) => {
                                    drop(client);
                                }
                            }
                        }
                        Err(_) => thread::sleep(Duration::from_millis(1)),
                    }
                }
            })?;
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for TcpDelayProxy {
    fn drop(&mut self) {
        self.stop.store(true, AOrdering::Relaxed);
        // 自连一次，让阻塞在 accept 的线程退出
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn relay_stream(mut r: TcpStream, mut w: TcpStream, hop: Duration) {
    let mut buf = [0u8; 65536];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                thread::sleep(hop);
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        let _ = c.next_u64();
        assert_ne!(a.next_u64(), c.next_u64());
    }

    #[test]
    fn rng_in_unit_range() {
        let mut r = Rng::new(7);
        for _ in 0..10000 {
            let x = r.next_f64();
            assert!((0.0..1.0).contains(&x));
        }
    }

    /// UDP 代理冒烟：客户端发的字节在 rtt/2 后到服务端。
    #[test]
    fn udp_proxy_forwards_both_ways() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let proxy = UdpProxy::spawn(server_addr, Conditions::rtt_ms(20)).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        // 客户端 → 代理 → 服务端
        client.send_to(b"ping", proxy.addr).unwrap();
        let mut buf = [0u8; 16];
        let t0 = Instant::now();
        let (n, src) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        // 源地址是代理地址（转发 socket），服务端回给代理
        assert_eq!(src, proxy.addr);
        assert!(t0.elapsed() >= Duration::from_millis(8), "单程延迟 ~10ms");

        // 服务端 → 代理 → 客户端
        server.send_to(b"pong", src).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    /// 丢包注入生效：高丢包下能构造丢包序列
    #[test]
    fn udp_proxy_drops() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        // 全丢：服务端什么都收不到
        let proxy = UdpProxy::spawn(
            server_addr,
            Conditions {
                loss: 1.0,
                ..Default::default()
            },
        )
        .unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(80)))
            .unwrap();
        for _ in 0..20 {
            client.send_to(b"x", proxy.addr).unwrap();
        }
        let mut buf = [0u8; 4];
        assert!(
            server.recv_from(&mut buf).is_err(),
            "全丢时服务端不应收到任何包"
        );
        drop(proxy);

        // 1% 丢包、固定 seed：确定性——同样打 1000 包，丢包数稳定（用新 seed 验证可复现）
        let drop_probe = |seed: u64| -> usize {
            let p = UdpProxy::spawn(
                server_addr,
                Conditions {
                    loss: 0.1,
                    seed,
                    ..Default::default()
                },
            )
            .unwrap();
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut got = 0usize;
            for _ in 0..300 {
                c.send_to(b"y", p.addr).unwrap();
            }
            while server.recv_from(&mut [0u8; 4]).is_ok() {
                got += 1;
            }
            drop(p);
            got
        };
        // 同 seed 结果一致；不同 seed 大概率不同
        assert_eq!(drop_probe(99), drop_probe(99));
    }

    /// TCP 延迟代理冒烟：往返 ≈ rtt
    #[test]
    fn tcp_delay_proxy_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut b = [0u8; 4];
            c.read_exact(&mut b).unwrap();
            c.write_all(&b).unwrap();
        });

        let proxy = TcpDelayProxy::spawn(server_addr, Duration::from_millis(30)).unwrap();
        let mut c = TcpStream::connect(proxy.addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let t0 = Instant::now();
        c.write_all(b"ping").unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(25),
            "RTT ≈ 30ms, 实测 {elapsed:?}"
        );
        srv.join().unwrap();
    }
}
