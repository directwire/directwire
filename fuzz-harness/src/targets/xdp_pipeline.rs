//! xdp-edge 目标：XDP 数据面模拟器的包管线。
//!
//! 入口面：18 字节模拟报文字节 → `FiveTuple`/`Packet` → `XdpSimulator::process`
//! （令牌桶限速 → SYN flood 检测 → 连接跟踪 → Maglev 选后端）。
//! 真实解析器是 `bpf/xdp_edge.c`（C 代码，不在 cargo-fuzz 范围）——这里对等
//! fuzz 用户态模拟器的整条流水线状态机，把限速/SYN/连接跟踪/Maglev 的边界
//! 全跑起来。
//!
//! 防 abort：输入按 18 字节定长切块（≤455 块），每块映射为一个 Packet；模拟器
//! 配置压小（连接跟踪/限速表容量 256）——内存与迭代内分配全部有界。时钟按
//! 输入字节派生地推进，覆盖 SYN 窗口过期与连接跟踪超时逐出。

use xdp_edge::packet::{FiveTuple, PROTO_TCP, Packet, TCP_ACK, TCP_SYN};
use xdp_edge::simulator::{SimConfig, XdpSimulator};

/// 模拟报文字节宽度：五元组(13) + tcp_flags(1) + len(4)
const PKT_LEN: usize = 18;

/// 手编一个 18 字节模拟报文（语料种子用）
fn pkt_bytes(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    flags: u8,
    len: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(PKT_LEN);
    v.extend_from_slice(&src_ip.to_le_bytes());
    v.extend_from_slice(&dst_ip.to_le_bytes());
    v.extend_from_slice(&src_port.to_le_bytes());
    v.extend_from_slice(&dst_port.to_le_bytes());
    v.push(proto);
    v.push(flags);
    v.extend_from_slice(&len.to_le_bytes());
    v
}

pub fn corpus() -> Vec<Vec<u8>> {
    vec![
        pkt_bytes(0x0a00_0001, 0x0a00_0002, 1234, 443, PROTO_TCP, TCP_SYN, 60),
        pkt_bytes(
            0x0a00_0001,
            0x0a00_0002,
            1234,
            443,
            PROTO_TCP,
            TCP_ACK,
            1500,
        ),
        pkt_bytes(
            0xc000_0201,
            0xc000_0202,
            80,
            54321,
            PROTO_TCP,
            TCP_SYN | TCP_ACK,
            40,
        ),
        pkt_bytes(0x0a00_0001, 0x0a00_0002, 9999, 53, 17, 0, 512),
    ]
}

pub fn fuzz(data: &[u8]) {
    let cfg = SimConfig {
        rate_max_entries: 256,
        conntrack_capacity: 256,
        syn_threshold: 8,
        ..Default::default()
    };
    // Maglev 表大小必须是质数（maglev.rs 构造函数 assert）——127 是质数
    let mut sim = XdpSimulator::new(&cfg, &[0x0a00_0001, 0x0a00_0002, 0x0a00_0003], 127);
    let mut now: u64 = 1_000_000;

    for chunk in data.chunks_exact(PKT_LEN) {
        let tuple = FiveTuple {
            src_ip: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
            dst_ip: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
            src_port: u16::from_le_bytes(chunk[8..10].try_into().unwrap()),
            dst_port: u16::from_le_bytes(chunk[10..12].try_into().unwrap()),
            protocol: chunk[12],
        };
        let pkt = Packet::new(
            tuple,
            chunk[13],
            u32::from_le_bytes(chunk[14..18].try_into().unwrap()),
        );
        let _ = sim.process(&pkt, now);
        // 按输入字节推进时钟：覆盖 SYN 窗口过期与连接跟踪超时逐出
        now = now.wrapping_add(1_000 + u64::from(chunk[0]) * 1_000_000);
    }

    // 不变量：连接跟踪满时 LRU 逐出，容量恒定（防「无限增长」内存炸弹）
    assert!(
        sim.conntrack_len() <= cfg.conntrack_capacity,
        "连接跟踪超过容量：LRU 逐出失效"
    );
}
