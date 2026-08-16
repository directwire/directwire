//! 网络条件探针：真实 RPC 栈走 net-sim 注入的网络条件。
//!
//! 回答白皮书级问题（真实实验的 80% 替代）：
//!   1. SRPT 在 100ms RTT 下还赢 TCP 吗？
//!   2. 100ms RTT + 1% 丢包下呢？——实测发现：短消息单包丢失无法自愈
//!      （sender tick 跳过 done 消息，receiver 对未知消息不发 RESEND），
//!      只能靠 RPC 层 attempt_timeout 兜底 → P99 从 ~100ms 暴涨到 ~5s。
//!      详见 transport/sender.rs 的 tick 逻辑与 net_probe 实测输出。
//!   3. 1MiB 长消息在丢包下的 RESEND 修复代价（~874 包丢 ~9 包）。
//!
//! 模拟器 Windows 修复（见 net-sim lib.rs win 模块）：timeBeginPeriod(1) 提升
//! 定时器分辨率（否则 1ms 读超时实际 ~13ms 才触发），SIO_UDP_CONNRESET=0 关掉
//! UDP 的 WSAECONNRESET（否则内核 loopback 会丢 ~4% 数据报、把排队报文连带吃掉）。
//!
//! 方法：homa-rpc 与 tcp-baseline 都通过 net-sim 中继（真实 socket + 注入条件），
//! 不改任何被测代码。诚实限制：TCP 只注入延迟（丢包无法在字节流代理上可靠注入，
//! 见 net-sim 文档；TCP 的丢包代价是拥塞窗口退避，方向已知，这里不伪造对比）。
//!
//! 运行：
//!   cargo run --release -p homa-rpc --example net_probe

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use homa_rpc::rpc::tcp_baseline::{self, TcpEchoServer};
use homa_rpc::rpc::{RpcClient, RpcServer};
use homa_rpc::transport::TransportConfig;
use net_sim::{Conditions, TcpDelayProxy, UdpProxy};

const WORKERS: usize = 8;
const SHORT_BYTES: usize = 100;
const LONG_BYTES: usize = 1 << 20;

#[derive(Default)]
struct Stats {
    short: Vec<Duration>,
    long: Vec<Duration>,
    /// 尝试上限用尽/超时的调用数（丢包 profile 下短消息单包丢失无法自愈，
    /// 只有 RPC 层 attempt_timeout 兜底——这部分延迟如实计入上面的 vec）
    failed: u64,
    /// homa 客户端「确认前重发」窗口触发次数（理想 profile 应为 0 = 无丢包零额外重发）
    retransmits: u64,
}

impl Stats {
    /// 输入需已排序
    fn pct(sorted: &[Duration], p: f64) -> Duration {
        if sorted.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn report(&self, tag: &str) {
        let mut sh = self.short.clone();
        let mut lo = self.long.clone();
        sh.sort();
        lo.sort();
        let us = |d: Duration| format!("{:.0}", d.as_secs_f64() * 1e6);
        println!(
            "  [{tag}] 短 n={} P50={}µs P90={}µs P99={}µs | 长 n={} P50={}µs | 失败 {} | 重发 {}",
            sh.len(),
            us(Self::pct(&sh, 0.50)),
            us(Self::pct(&sh, 0.90)),
            us(Self::pct(&sh, 0.99)),
            lo.len(),
            us(Self::pct(&lo, 0.50)),
            self.failed,
            self.retransmits,
        );
    }
}

/// 按已知 RTT 配置「确认前重发」窗口：取 2×RTT、下限 150ms（宁高勿低）。
/// 150ms 下限是 loopback 实测标定：确认全程（请求→响应→confirm）P50≈5.5ms、
/// P99≈13.6ms，50ms 下限会出现 ~9 次「响应按时到但窗口已过」的估计错误重发，
/// 150ms 后 ideal 实测 0 次——即无丢包零额外重发。
/// 窗口必须 > 请求发出→confirm 的全程延迟（RTT + 服务端处理 + 响应 + 分发），
/// 而不是只 > RTT——否则无丢包时响应未到窗口已过，造成双倍流量常态化。
/// 丢包时恢复 = 窗口 + RTT。真实部署无 RTT 样本时用默认 500ms 保守值。
fn homa_config(rtt: Duration) -> TransportConfig {
    let oc = std::env::var("HOMA_OVERCOMMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let ginc = std::env::var("HOMA_GRANT_INC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1 << 20);
    // 调试/实验用显式覆盖
    let retransmit_timeout = std::env::var("HOMA_RETX_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| (rtt * 2).max(Duration::from_millis(150)));
    TransportConfig {
        overcommit: oc,
        grant_increment: ginc,
        retransmit_timeout,
        ..Default::default()
    }
}

/// 一轮混合负载（~91% 短 + ~9% 长），通过中继注入条件。
/// 中继必须存活到本轮结束（Target 持有它），否则转发线程退出即断网。
enum Target {
    Homa(Arc<RpcClient>, SocketAddr, RpcServer, UdpProxy),
    Tcp(SocketAddr, TcpEchoServer, TcpDelayProxy),
}

fn run_mixed(homa: bool, conds: Conditions, total_ops: u64, attempt_timeout: Duration) -> Stats {
    let stats = Arc::new(Mutex::new(Stats::default()));
    let counter = Arc::new(AtomicU64::new(0));
    let short_payload = Arc::new(vec![0xabu8; SHORT_BYTES]);
    let long_payload = Arc::new(vec![0xcdu8; LONG_BYTES]);

    let target = if homa {
        let server =
            RpcServer::spawn_with_config("127.0.0.1:0", homa_config(conds.rtt), |req| req.to_vec())
                .unwrap();
        // 客户端连中继地址；中继把流量转发到真实服务端
        let proxy = UdpProxy::spawn(server.addr(), conds).unwrap();
        let mut client = RpcClient::new_with_config("127.0.0.1:0", homa_config(conds.rtt)).unwrap();
        // attempt_timeout 是响应丢失的兜底（发送端重发请求 → 服务端幂等回放）：
        // 必须 > 重发窗口 + RTT（避免与发送端自愈竞态），且 + RTT 后 < 验收线
        client.attempt_timeout = attempt_timeout;
        client.max_attempts = 3;
        for _ in 0..50 {
            // 预热容忍丢包 profile 下的偶发 5s 重试，不崩
            let _ = client.call(proxy.addr, &short_payload);
        }
        Target::Homa(Arc::new(client), proxy.addr, server, proxy)
    } else {
        let server = TcpEchoServer::spawn("127.0.0.1:0").unwrap();
        let proxy = TcpDelayProxy::spawn(server.addr, conds.rtt).unwrap();
        for _ in 0..50 {
            tcp_baseline::call(proxy.addr, &short_payload).unwrap();
        }
        Target::Tcp(proxy.addr, server, proxy)
    };
    let target = Arc::new(target);

    let t0 = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let counter = Arc::clone(&counter);
        let stats = Arc::clone(&stats);
        let target = Arc::clone(&target);
        let sp = Arc::clone(&short_payload);
        let lp = Arc::clone(&long_payload);
        handles.push(std::thread::spawn(move || {
            loop {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                if n >= total_ops {
                    break;
                }
                let is_long = n % 11 == 10;
                let payload = if is_long { &lp } else { &sp };
                let start = Instant::now();
                let res = match &*target {
                    Target::Homa(client, addr, _s, _p) => client.call(*addr, payload).map(|_| ()),
                    Target::Tcp(addr, _s, _p) => tcp_baseline::call(*addr, payload).map(|_| ()),
                };
                let el = start.elapsed();
                let mut s = stats.lock().unwrap();
                if res.is_err() {
                    // 计时如实计入（含 attempt_timeout 的重试成本），失败单列
                    s.failed += 1;
                }
                if is_long {
                    s.long.push(el);
                } else {
                    s.short.push(el);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    println!(
        "  [{}] {total_ops} ops 完成，墙钟 {:.2?}",
        if homa { "homa" } else { "tcp " },
        t0.elapsed()
    );
    let mut stats = Arc::try_unwrap(stats).ok().unwrap().into_inner().unwrap();
    // 汇报「确认前重发」触发数：无丢包 profile（ideal / 100ms RTT）应为 0
    if let Target::Homa(client, _, _, _) = &*target {
        stats.retransmits = client.retransmit_pokes();
    }
    stats
}

fn main() {
    println!("=== net-sim 网络条件探针：homa-rpc (Homa-lite over UDP) vs TCP ===");

    // NETSIM_PROFILE=n 只跑第 n 个 profile（省时间）
    let only: Option<usize> = std::env::var("NETSIM_PROFILE")
        .ok()
        .and_then(|s| s.parse().ok());

    // (name, conditions, ops, RPC attempt_timeout)
    // attempt_timeout 选择：> retransmit_timeout(2×RTT, 下限150ms) + RTT（避开与
    // 发送端自愈竞态，让 transport 重发窗口做主要恢复），且 + RTT 后 < 500ms
    // 验收线（1% 丢包 profile 的响应丢失恢复 = attempt + RTT）。
    let profiles: Vec<(&str, Conditions, u64, Duration)> = vec![
        (
            "ideal loopback（proxy 校验）",
            Conditions::ideal(),
            550,
            Duration::from_millis(500),
        ),
        (
            "100ms RTT",
            Conditions::rtt_ms(100),
            300,
            Duration::from_millis(350),
        ),
        (
            "100ms RTT + 1% 丢包",
            Conditions {
                loss: 0.01,
                seed: 0xBADC0FFE,
                ..Conditions::rtt_ms(100)
            },
            300,
            Duration::from_millis(350),
        ),
        (
            "10ms RTT + 5% 丢包（MoQ 类）",
            Conditions {
                loss: 0.05,
                seed: 0xDEADBEEF,
                ..Conditions::rtt_ms(10)
            },
            300,
            // 200ms > 重发窗口(150) + RTT(10)：让 transport 窗口做主要恢复(~160ms)，
            // RPC 重试作兜底(210ms)，避免两路在同一时刻竞态双发
            Duration::from_millis(200),
        ),
    ];

    for (idx, (name, conds, ops, attempt_timeout)) in profiles.into_iter().enumerate() {
        if let Some(o) = only {
            if idx != o {
                continue;
            }
        }
        println!("\n=== {name} ===");
        let homa = run_mixed(true, conds, ops, attempt_timeout);
        let tcp = run_mixed(false, conds, ops, attempt_timeout);
        homa.report("homa");
        tcp.report("tcp ");
        let mut hs = homa.short.clone();
        let mut ts = tcp.short.clone();
        hs.sort();
        ts.sort();
        let p = |v: &[Duration], q: f64| Stats::pct(v, q).as_secs_f64();
        if !hs.is_empty() && !ts.is_empty() {
            println!(
                "  短 RPC 加速比 (tcp/homa): P50 {:.2}×  P90 {:.2}×  P99 {:.2}×",
                p(&ts, 0.50) / p(&hs, 0.50),
                p(&ts, 0.90) / p(&hs, 0.90),
                p(&ts, 0.99) / p(&hs, 0.99),
            );
        }
    }
}
