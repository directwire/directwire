//! 连接跟踪过期与 LRU 淘汰测试（端到端走模拟器管线）。

use xdp_edge::conntrack::{ConnEntry, ConnTrack};
use xdp_edge::packet::{Action, FiveTuple, Packet, PROTO_TCP, TCP_ACK};
use xdp_edge::simulator::{SimConfig, XdpSimulator};

fn tuple(port: u16) -> FiveTuple {
    FiveTuple {
        src_ip: 0x0a00_0001,
        dst_ip: 0xcb00_7101,
        src_port: port,
        dst_port: 443,
        protocol: PROTO_TCP,
    }
}

#[test]
fn expired_connection_rebuilds_decision() {
    let cfg = SimConfig {
        conntrack_timeout_ns: 1_000_000_000, // 1s
        rate_per_sec: 1e9,                   // 不限速，隔离变量
        rate_burst: 1e6,
        ..Default::default()
    };
    let backends = [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003, 0x0a00_0004];
    let mut sim = XdpSimulator::new(&cfg, &backends, 4099);

    let pkt = Packet::new(tuple(12345), TCP_ACK, 64);
    let t0 = 1_000_000_000u64;

    // 首包：miss -> 新建连接
    let a1 = sim.process(&pkt, t0);
    assert!(matches!(a1, Action::Forward(_)));
    assert_eq!(sim.stats.conn_misses, 1);
    assert_eq!(sim.stats.conn_hits, 0);

    // 500ms 后：命中，决策不变
    let a2 = sim.process(&pkt, t0 + 500_000_000);
    assert_eq!(a1, a2, "连接亲和性破坏：同流被换后端");
    assert_eq!(sim.stats.conn_hits, 1);

    // 超过 1s 未活跃：过期，重新走 Maglev（miss+1）
    let _ = sim.process(&pkt, t0 + 2_000_000_001);
    assert_eq!(sim.stats.conn_misses, 2, "过期连接未重建");
}

#[test]
fn lru_eviction_under_capacity_pressure() {
    // 容量 1024，灌入 5000 条不同连接，必须发生淘汰且表不越界
    let mut ct = ConnTrack::new(1024, u64::MAX);
    for i in 0..5000u32 {
        ct.insert(
            FiveTuple {
                src_ip: 0x0a00_0001 + i,
                dst_ip: 0xcb00_7101,
                src_port: 1024,
                dst_port: 443,
                protocol: PROTO_TCP,
            },
            ConnEntry { backend_ip: 0x0a00_0001, last_seen_ns: i as u64 },
        );
    }
    assert_eq!(ct.len(), 1024, "LRU 表超出容量");
    assert!(ct.evictions >= 5000 - 1024, "淘汰计数不足: {}", ct.evictions);
}

#[test]
fn connection_affinity_consistent_backend() {
    // 同一条流在连接生命周期内永远转发到同一后端（IPIP 目的地稳定）
    let cfg = SimConfig { rate_per_sec: 1e9, rate_burst: 1e6, ..Default::default() };
    let backends = [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003];
    let mut sim = XdpSimulator::new(&cfg, &backends, 4099);

    let pkt = Packet::new(tuple(54321), TCP_ACK, 64);
    let first = sim.process(&pkt, 0);
    for i in 1..1000u64 {
        assert_eq!(sim.process(&pkt, i * 1_000_000), first, "连接中途换后端");
    }
    assert_eq!(sim.stats.conn_hits, 999);
}
