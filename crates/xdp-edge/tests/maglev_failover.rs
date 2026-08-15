//! Maglev 后端故障时的流量迁移测试。
//!
//! 理论：N 个后端摘除 1 个后，原本落在存活后端上的连接应保持不动，
//! 只有故障后端的 ~1/N 份额被重新分配 —— 总扰动量约 1/N。
//! 这是 Maglev 相对取模哈希（扰动 ~100%）的核心卖点。

use xdp_edge::maglev::{Maglev, flow_hash};
use xdp_edge::packet::{FiveTuple, PROTO_TCP};

const LUT_SIZE: usize = 65537; // 与 Katran 默认一致的大质数
const N_BACKENDS: u32 = 8;
const N_FLOWS: u32 = 100_000;

fn backends(n: u32) -> Vec<u32> {
    (0..n).map(|i| 0x0a00_0001 + i).collect() // 10.0.0.1 ~ 10.0.0.n
}

fn flow(i: u32) -> FiveTuple {
    FiveTuple {
        src_ip: 0xc000_0001 + i % 50_000,
        dst_ip: 0xcb00_7101,
        src_port: (1024 + i % 60_000) as u16,
        dst_port: 443,
        protocol: PROTO_TCP,
    }
}

#[test]
fn backend_failure_disruption_within_theory() {
    let all = backends(N_BACKENDS);

    let mut mg = Maglev::new(LUT_SIZE);
    mg.rebuild(&all);

    // 记录故障前的选路结果
    let before: Vec<u32> = (0..N_FLOWS)
        .map(|i| mg.lookup(flow_hash(&flow(i))))
        .collect();

    // 摘除 backend[3]，模拟健康检查下线
    let failed = all[3];
    let survivors: Vec<u32> = all.iter().copied().filter(|&b| b != failed).collect();
    mg.rebuild(&survivors);

    let mut moved_on_survivor = 0u32; // 本不该迁移却迁移的流
    let mut on_failed = 0u32; // 原本在故障后端上、必须迁移的流
    for (i, &b0) in before.iter().enumerate() {
        let b1 = mg.lookup(flow_hash(&flow(i as u32)));
        if b0 == failed {
            on_failed += 1;
            assert_ne!(b1, failed, "故障后端仍被选中");
        } else if b1 != b0 {
            moved_on_survivor += 1;
        }
    }

    // 存活后端的连接亲和性：误迁移率必须 < 1%（理想 Maglev 接近 0）
    let survivor_flows = N_FLOWS - on_failed;
    let false_move_rate = moved_on_survivor as f64 / survivor_flows as f64;
    assert!(
        false_move_rate < 0.01,
        "存活后端连接误迁移率 {:.3}% 超过 1%",
        false_move_rate * 100.0
    );

    // 总扰动（必须迁移的部分）应接近理论值 1/N
    let disruption = on_failed as f64 / N_FLOWS as f64;
    let theory = 1.0 / N_BACKENDS as f64;
    assert!(
        (disruption - theory).abs() < theory * 0.3,
        "故障流量占比 {:.3} 偏离理论值 {:.3} 过多",
        disruption,
        theory
    );
}

#[test]
fn scale_out_disruption_bounded() {
    // 扩容 8 -> 9：新增后端应只吸引约 1/9 的流量
    let before8 = backends(8);
    let after9 = backends(9);

    let mut mg = Maglev::new(LUT_SIZE);
    mg.rebuild(&before8);
    let before: Vec<u32> = (0..N_FLOWS)
        .map(|i| mg.lookup(flow_hash(&flow(i))))
        .collect();
    mg.rebuild(&after9);

    let moved = (0..N_FLOWS as usize)
        .filter(|&i| mg.lookup(flow_hash(&flow(i as u32))) != before[i])
        .count() as f64
        / N_FLOWS as f64;
    let theory = 1.0 / 9.0;
    assert!(
        moved < theory * 1.5,
        "扩容迁移率 {:.3} 超过理论值 1/9 的 1.5 倍",
        moved
    );
}

#[test]
fn load_balance_uniformity() {
    let all = backends(N_BACKENDS);
    let mut mg = Maglev::new(LUT_SIZE);
    mg.rebuild(&all);
    // LUT 槽位均衡度：每后端份额应在 1/N 的 ±10% 内
    let expected = LUT_SIZE as f64 / N_BACKENDS as f64;
    for c in mg.slot_counts() {
        let dev = (c as f64 - expected).abs() / expected;
        assert!(dev < 0.10, "后端槽位份额偏差 {:.2}% 超 10%", dev * 100.0);
    }
}
