//! 端到端：控制面 agent + 数据面模拟器协同测试。
//!
//! 场景：4 后端上线 → 打流建立连接 → backend 故障被健康检查摘除 →
//! agent 热发布新 LUT → 模拟器 apply_lut → 验证流量迁移有界、
//! 故障后端不再收到新连接；同时验证周期清扫回收过期连接。

use xdp_edge::control::{AgentConfig, ControlAgent};
use xdp_edge::packet::{Action, FiveTuple, Packet, PROTO_TCP, TCP_ACK};
use xdp_edge::simulator::{SimConfig, XdpSimulator};

const S: u64 = 1_000_000_000;

fn flow_pkt(i: u32) -> Packet {
    Packet::new(
        FiveTuple {
            src_ip: 0xc000_0001 + i,
            dst_ip: 0xcb00_7101,
            src_port: 1024 + (i % 10_000) as u16,
            dst_port: 443,
            protocol: PROTO_TCP,
        },
        TCP_ACK,
        128,
    )
}

#[test]
fn control_plane_failover_end_to_end() {
    let backends = [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003, 0x0a00_0004];
    let sim_cfg = SimConfig { rate_per_sec: 1e9, rate_burst: 1e6, conntrack_timeout_ns: 60 * S, ..Default::default() };
    let agent_cfg = AgentConfig { lut_size: 4099, ..Default::default() };

    let mut sim = XdpSimulator::new(&sim_cfg, &backends, 4099);
    let mut agent = ControlAgent::new(&agent_cfg, &backends);

    // 探活上线全部后端
    for &b in &backends {
        for i in 0..2u64 {
            agent.report_probe(b, true, i * S);
        }
    }
    assert_eq!(agent.alive_backends(), backends);

    // 打流 2000 条新连接（t=5s）
    let n_flows = 2000u32;
    let mut before = Vec::with_capacity(n_flows as usize);
    for i in 0..n_flows {
        let pkt = flow_pkt(i);
        match sim.process(&pkt, 5 * S) {
            Action::Forward(be) => before.push((pkt.tuple, be)),
            _ => panic!("正常流量被误丢"),
        }
    }

    // backend[2] 连续 3 次探测失败 -> 下线，agent 热发布新 LUT
    let failed = backends[2];
    let mut new_version = None;
    for i in 0..3u64 {
        if let Some(v) = agent.report_probe(failed, false, 10 * S + i * S) {
            new_version = Some(v);
        }
    }
    assert!(new_version.is_some());

    // 数据面应用新 LUT（对应内核控制面写 maglev_lut map）
    let snap = agent.lut.snapshot();
    assert_eq!(snap.version, new_version.unwrap());
    sim.apply_lut(snap.backends.to_vec(), snap.table.to_vec());
    drop(snap);

    // 新连接不再进入故障后端
    for i in n_flows..n_flows + 2000 {
        if let Action::Forward(be) = sim.process(&flow_pkt(i), 15 * S) {
            assert_ne!(be, failed, "故障后端仍收到新连接");
        }
    }

    // 旧连接迁移有界：conntrack 里的存量连接仍保持亲和（这是 conntrack 的职责），
    // 过期重建后的新决策才走新 LUT。验证「过期后重建不再选故障后端」：
    let mut rebuilt_to_failed = 0u32;
    for (tuple, _) in &before {
        let pkt = Packet::new(*tuple, TCP_ACK, 128);
        // 推进到超过 conntrack TTL（60s）之后
        if let Action::Forward(be) = sim.process(&pkt, 80 * S) {
            if be == failed {
                rebuilt_to_failed += 1;
            }
        }
    }
    assert_eq!(rebuilt_to_failed, 0, "过期重建的连接仍被分到故障后端");
}

#[test]
fn periodic_sweep_bounds_conntrack() {
    let backends = [0x0a00_0001u32, 0x0a00_0002];
    let sim_cfg = SimConfig {
        rate_per_sec: 1e9,
        rate_burst: 1e6,
        conntrack_timeout_ns: 10 * S, // TTL 10s
        ..Default::default()
    };
    let agent_cfg = AgentConfig { lut_size: 4099, sweep_interval_ns: 5 * S, ..Default::default() };
    let mut sim = XdpSimulator::new(&sim_cfg, &backends, 4099);
    let mut agent = ControlAgent::new(&agent_cfg, &backends);

    // 每 4s 一波短连接（每波 500 条），控制面每 5s 清扫
    for wave in 0..10u64 {
        let t = wave * 4 * S;
        for i in 0..500u32 {
            let _ = sim.process(&flow_pkt((wave as u32) * 500 + i), t);
        }
        // 控制面 tick：清扫 + 探活调度
        let due = agent.tick(sim.conntrack_mut(), t);
        for b in due {
            agent.report_probe(b, true, t);
        }
        // TTL=10s、波间隔 4s、清扫周期 5s：稳态约 2.5~4 波存活（≤2000 条），
        // 留余量到 2500；若无清扫，10 波将累积到 5000 条
        assert!(
            sim.conntrack_len() <= 2500,
            "清扫未生效，连接表膨胀到 {}",
            sim.conntrack_len()
        );
    }
    assert!(agent.sweeper.total_swept > 0, "清扫器从未清扫");
}
