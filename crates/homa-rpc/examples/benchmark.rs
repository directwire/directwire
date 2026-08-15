//! Benchmark：同一 loopback 上并发混合负载（90% 100B 短 RPC + 10% 1MB 长 RPC），
//! 对比 homa-rpc（Homa-lite over UDP）与简单 TCP 实现的 P50/P99 延迟。
//!
//! 运行：
//!   cargo run --release --example benchmark        # 建议 release，debug 太慢
//!
//! 说明：loopback 没有真实网络拥塞与网卡优先级队列，本 benchmark 主要展示
//! 「混合负载下短 RPC 不被长 RPC 阻塞」的架构特性（SRPT 授权调度 vs TCP 字节流排队），
//! 不声称复现 Homa 论文在数据中心交换网络下的 19-72× 数字。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use homa_rpc::rpc::tcp_baseline::{self, TcpEchoServer};
use homa_rpc::rpc::{RpcClient, RpcServer};

/// 工作线程数
const WORKERS: usize = 8;
/// 总调用次数（90% 短 / 10% 长）
const TOTAL_OPS: u64 = 550;
/// 短 RPC 负载
const SHORT_BYTES: usize = 100;
/// 长 RPC 负载
const LONG_BYTES: usize = 1 << 20; // 1MiB

struct Stats {
    short: Vec<Duration>,
    long: Vec<Duration>,
}

impl Stats {
    fn percentile(sorted: &[Duration], p: f64) -> Duration {
        if sorted.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn report(&self, name: &str) {
        let mut short = self.short.clone();
        let mut long = self.long.clone();
        short.sort();
        long.sort();
        let us = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1e6);
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} | {} | {} |",
            short.len(),
            us(Self::percentile(&short, 0.50)),
            us(Self::percentile(&short, 0.90)),
            us(Self::percentile(&short, 0.99)),
            long.len(),
            us(Self::percentile(&long, 0.50)),
            us(Self::percentile(&long, 0.90)),
            us(Self::percentile(&long, 0.99)),
        );
    }
}

/// 运行一轮混合负载。homa=true 走本实现，false 走 TCP 对照。
fn run_mixed(homa: bool) -> Stats {
    let stats = Stats { short: Vec::new(), long: Vec::new() };
    let stats = Arc::new(Mutex::new(stats));
    let counter = Arc::new(AtomicU64::new(0));

    // 负载固定内容即可，不需要随机性
    let short_payload = Arc::new(vec![0xabu8; SHORT_BYTES]);
    let long_payload = Arc::new(vec![0xcdu8; LONG_BYTES]);

    // 注意：server 必须随 Target 存活到本轮结束，否则 drop 即关闭服务线程
    enum Target {
        Homa(Arc<RpcClient>, std::net::SocketAddr, RpcServer),
        Tcp(std::net::SocketAddr, TcpEchoServer),
    }
    let target = if homa {
        let server = RpcServer::spawn("127.0.0.1:0", |req| req.to_vec()).unwrap();
        let mut client = RpcClient::new("127.0.0.1:0").unwrap();
        client.attempt_timeout = Duration::from_secs(5);
        client.max_attempts = 3;
        // 预热
        for _ in 0..50 {
            client.call(server.addr(), &short_payload).unwrap();
        }
        Target::Homa(Arc::new(client), server.addr(), server)
    } else {
        let server = TcpEchoServer::spawn("127.0.0.1:0").unwrap();
        for _ in 0..50 {
            tcp_baseline::call(server.addr, &short_payload).unwrap();
        }
        Target::Tcp(server.addr, server)
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
        handles.push(std::thread::spawn(move || loop {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            if n >= TOTAL_OPS {
                break;
            }
            // 每 11 次有 1 次长 RPC → 550 次中含 50 次长 RPC
            let is_long = n % 11 == 10;
            let payload = if is_long { &lp } else { &sp };
            let start = Instant::now();
            match &*target {
                Target::Homa(client, addr, _server) => {
                    client.call(*addr, payload).unwrap();
                }
                Target::Tcp(addr, _server) => {
                    tcp_baseline::call(*addr, payload).unwrap();
                }
            }
            let el = start.elapsed();
            let mut s = stats.lock().unwrap();
            if is_long {
                s.long.push(el);
            } else {
                s.short.push(el);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total = t0.elapsed();
    println!(
        "  [{}] {} 次调用完成，总耗时 {:.2?}",
        if homa { "homa-rpc" } else { "tcp-base" },
        TOTAL_OPS,
        total
    );
    // 解包共享统计（此注释说明：所有工作线程已 join，Arc 必然独占）
    let s = Arc::try_unwrap(stats).ok().expect("workers joined").into_inner().unwrap();
    s
}

fn main() {
    println!("=== homa-rpc vs TCP loopback 混合负载 benchmark ===");
    println!("负载: {TOTAL_OPS} 次调用, ~91% {SHORT_BYTES}B 短 RPC + ~9% {}MiB 长 RPC, {WORKERS} 并发线程\n", LONG_BYTES >> 20);

    println!("-- homa-rpc (Homa-lite over UDP, GRANT/SRPT 调度) --");
    let homa = run_mixed(true);
    println!("\n-- tcp-baseline (长度前缀帧, 短连接) --");
    let tcp = run_mixed(false);

    println!("\n延迟单位 µs");
    println!("| 实现 | 短样本 | 短P50 | 短P90 | 短P99 | 长样本 | 长P50 | 长P90 | 长P99 |");
    println!("|---|---|---|---|---|---|---|---|---|");
    homa.report("homa-rpc");
    tcp.report("tcp-baseline");

    // 短 RPC P99 加速比
    let mut hs = homa.short.clone();
    let mut ts = tcp.short.clone();
    hs.sort();
    ts.sort();
    let p99 = |v: &[Duration]| Stats::percentile(v, 0.99).as_secs_f64();
    if !hs.is_empty() && !ts.is_empty() {
        println!("\n短 RPC P99 加速比: {:.1}×", p99(&ts) / p99(&hs));
    }
}
