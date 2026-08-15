//! benchmark：模拟 1000 万包流经 XDP 数据面，统计吞吐与决策延迟分布。
//!
//! 运行：cargo run --release --example benchmark
//!
//! 说明：
//! - 报文由内置 xorshift 生成器合成（零依赖），80% 命中既有连接、
//!   20% 新连接，掺杂少量超速攻击源以覆盖 DROP 快速路径；
//! - 吞吐 = 总包数 / 墙钟时间（单线程，即单核软件路径能力）；
//! - 延迟每 256 包采样一次（Instant::now 本身有开销，全量采样会污染结果），
//!   输出 P50 / P90 / P99 / P999 决策延迟。

use std::time::Instant;
use xdp_edge::packet::{FiveTuple, Packet, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN};
use xdp_edge::simulator::{SimConfig, XdpSimulator};

const TOTAL_PACKETS: u64 = 10_000_000;
const SAMPLE_EVERY: u64 = 256;

/// xorshift64* 伪随机（benchmark 用，避免外部依赖）
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

fn main() {
    let backends: Vec<u32> = (0..16).map(|i| 0x0a00_0001 + i).collect(); // 16 个后端
    let cfg = SimConfig {
        rate_per_sec: 20_000.0, // 单源 20k pps 上限，正常源远低于此
        rate_burst: 1_000.0,
        conntrack_capacity: 1 << 20,
        ..Default::default()
    };
    let mut sim = XdpSimulator::new(&cfg, &backends, 65537);

    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut lat_samples: Vec<u128> = Vec::with_capacity((TOTAL_PACKETS / SAMPLE_EVERY) as usize);
    let mut now_ns: u64 = 1_000_000_000; // 虚拟时钟：平均 1µs 一包 = 1Mpps 到达率

    println!("== xdp-edge 数据面模拟 benchmark ==");
    println!("目标包数: {} | 后端: {} | LUT: 65537", TOTAL_PACKETS, backends.len());

    let start = Instant::now();
    for i in 0..TOTAL_PACKETS {
        let r = rng.next();
        // 80% 复用既有流（模拟连接命中），20% 新流
        let flow_id = if r % 100 < 80 { r % 50_000 } else { 50_000 + (i % 200_000) };
        // 20% 攻击流量：前 4 个源发 SYN（走 SYN flood 检测），
        // 后 4 个源发 ACK 洪水（走令牌桶限速 DROP）
        let (src_ip, flags) = if i % 10 < 2 {
            let atk = 0x0bad_0000 + (i % 8) as u32;
            if i % 8 < 4 { (atk, TCP_SYN) } else { (atk, TCP_ACK) }
        } else {
            (0xc000_0000 + (flow_id % 40_000) as u32, TCP_ACK)
        };
        let pkt = Packet::new(
            FiveTuple {
                src_ip,
                dst_ip: 0xcb00_7101,
                src_port: (1024 + flow_id % 60_000) as u16,
                dst_port: 443,
                protocol: if r % 10 == 0 { PROTO_UDP } else { PROTO_TCP },
            },
            flags,
            64 + (r % 1400) as u32,
        );
        now_ns += 500 + (rng.next() % 1000); // 间隔 0.5~1.5µs

        if i % SAMPLE_EVERY == 0 {
            let t0 = Instant::now();
            let _ = sim.process(&pkt, now_ns);
            lat_samples.push(t0.elapsed().as_nanos());
        } else {
            let _ = sim.process(&pkt, now_ns);
        }
    }
    let wall = start.elapsed();

    let pps = TOTAL_PACKETS as f64 / wall.as_secs_f64();
    let s = &sim.stats;
    println!("\n-- 吞吐 --");
    println!("总耗时: {:.2}s | 吞吐: {:.2} M pps（单线程软件路径）", wall.as_secs_f64(), pps / 1e6);
    println!("\n-- 决策分布 --");
    println!(
        "转发: {} (命中 {} / 新建 {}) | 限速丢弃: {} | SYN丢弃: {}",
        s.forwarded, s.conn_hits, s.conn_misses, s.dropped_rate, s.dropped_synflood
    );
    println!("连接表: {} 条 | LRU 淘汰: {}", sim.conntrack_len(), sim.conntrack_evictions());

    lat_samples.sort_unstable();
    let pct = |p: f64| lat_samples[(p * (lat_samples.len() - 1) as f64) as usize];
    println!("\n-- 决策延迟（{} 次采样） --", lat_samples.len());
    println!("P50: {}ns | P90: {}ns | P99: {}ns | P99.9: {}ns",
        pct(0.50), pct(0.90), pct(0.99), pct(0.999));

    // 验收参照：Katran 单核 5.2 Mpps（内核 XDP）。纯用户态 Rust 单线程
    // 达到 1M+ pps 即证明每包逻辑成本在微秒级以内，架构可行。
    if pps < 1e6 {
        eprintln!("\n警告：吞吐低于 1 Mpps，请使用 --release 运行");
        std::process::exit(1);
    }
}
