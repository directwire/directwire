//! 令牌桶限速精度测试（虚拟时钟驱动，确定性）。
//!
//! 精度验收：以固定速率持续打流，窗口内实际放行数与理论值
//! rate * t + burst 的偏差应在 2% 以内。

use xdp_edge::packet::{Action, FiveTuple, PROTO_TCP, Packet, TCP_ACK};
use xdp_edge::simulator::{SimConfig, XdpSimulator};
use xdp_edge::token_bucket::{RateLimiter, TokenBucket};

#[test]
fn sustained_rate_accuracy() {
    // 速率 1000 pps，突发 10
    let mut b = TokenBucket::new(1000.0, 10.0);
    let mut allowed = 0u64;
    let total = 100_000u64;
    // 每 100µs 来一个包 = 到达率 10000 pps（10 倍超速）
    let step_ns = 100_000u64;
    for i in 0..total {
        if b.allow(i * step_ns) {
            allowed += 1;
        }
    }
    // 理论：1000 pps * 10s + 10 burst ≈ 10010
    let expected = 1000.0 * (total as f64 * step_ns as f64 / 1e9) + 10.0;
    let err = (allowed as f64 - expected).abs() / expected;
    assert!(
        err < 0.02,
        "限速精度误差 {:.2}% 超 2%（放行 {} / 理论 {:.0}）",
        err * 100.0,
        allowed,
        expected
    );
}

#[test]
fn per_source_isolation() {
    // 不同源 IP 独立计数：攻击源打满不影响正常源
    let mut rl = RateLimiter::new(100.0, 5.0, 1024);
    let attacker = 0x0bad_0001u32;
    let normal = 0x0a00_0001u32;

    // 攻击源瞬间灌 1000 包
    let mut attacker_ok = 0;
    for _ in 0..1000 {
        if rl.allow(attacker, 0) {
            attacker_ok += 1;
        }
    }
    assert!(attacker_ok <= 5, "攻击源突发未被限住: {}", attacker_ok);

    // 正常源在同一时刻应正常放行（用满自己的突发）
    let mut normal_ok = 0;
    for _ in 0..5 {
        if rl.allow(normal, 0) {
            normal_ok += 1;
        }
    }
    assert_eq!(normal_ok, 5, "正常源被误伤");
}

#[test]
fn simulator_drop_path_under_flood() {
    // 端到端：模拟器内攻击源超速打流应主要走 XDP_DROP
    let cfg = SimConfig {
        rate_per_sec: 1_000.0,
        rate_burst: 50.0,
        ..Default::default()
    };
    let backends = [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003];
    let mut sim = XdpSimulator::new(&cfg, &backends, 4099);

    let mut forwarded = 0u64;
    let mut dropped = 0u64;
    for i in 0..10_000u64 {
        let pkt = Packet::new(
            FiveTuple {
                src_ip: 0x0bad_0001,
                dst_ip: 0xcb00_7101,
                src_port: (1024 + i % 60_000) as u16,
                dst_port: 443,
                protocol: PROTO_TCP,
            },
            TCP_ACK, // 已建连流量，避免触发 SYN 检测
            64,
        );
        match sim.process(&pkt, i * 10_000) {
            // 到达率 100k pps，限速 1k pps
            Action::Forward(_) => forwarded += 1,
            Action::Drop => dropped += 1,
            Action::Pass => {}
        }
    }
    let drop_ratio = dropped as f64 / (dropped + forwarded) as f64;
    assert!(
        drop_ratio > 0.95,
        "洪水下丢包率 {:.2}% 过低",
        drop_ratio * 100.0
    );
}
