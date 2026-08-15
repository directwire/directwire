//! Prometheus 文本格式指标导出。
//!
//! 产品语义：一体机控制面暴露 /metrics HTTP 端点，内容为本模块
//! 生成的 exposition 格式文本。指标来自数据面 stats map
//! （本骨架来自 XdpSimulator 的 SimStats）与控制面观测值。
//!
//! 指标清单：
//! - xdp_edge_packets_total{action}      counter  按动作分类的包计数
//! - xdp_edge_conntrack_lookups_total    counter  连接跟踪命中/未命中
//! - xdp_edge_conntrack_hit_ratio        gauge    命中率（0~1）
//! - xdp_edge_conntrack_entries          gauge    当前连接数
//! - xdp_edge_conntrack_evictions_total  counter  LRU 淘汰总数
//! - xdp_edge_pps                        gauge    窗口期吞吐（由调用方给窗口秒数）
//! - xdp_edge_backends_alive             gauge    存活后端数
//! - xdp_edge_lut_version                gauge    当前 LUT 版本号

use crate::simulator::SimStats;
use std::fmt::Write as _;

/// /metrics 端点内容生成
///
/// - `stats`：数据面累计决策计数
/// - `conntrack_entries` / `evictions`：连接表观测
/// - `window_secs`：pps 统计窗口（由调用方用「本次计数增量 / 窗口」语义传入）
/// - `window_packets`：窗口内包数（用于算 pps）
/// - `backends_alive` / `lut_version`：控制面状态
pub fn render_metrics(
    stats: &SimStats,
    conntrack_entries: usize,
    evictions: u64,
    window_packets: u64,
    window_secs: f64,
    backends_alive: usize,
    lut_version: u64,
) -> String {
    let mut out = String::with_capacity(1024);
    let pps = if window_secs > 0.0 {
        window_packets as f64 / window_secs
    } else {
        0.0
    };
    let lookups = stats.conn_hits + stats.conn_misses;
    let hit_ratio = if lookups > 0 {
        stats.conn_hits as f64 / lookups as f64
    } else {
        0.0
    };

    // counter：按动作的包计数
    let _ = writeln!(
        out,
        "# HELP xdp_edge_packets_total Packets processed by XDP pipeline, by action."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_packets_total counter");
    let _ = writeln!(
        out,
        "xdp_edge_packets_total{{action=\"forward\"}} {}",
        stats.forwarded
    );
    let _ = writeln!(
        out,
        "xdp_edge_packets_total{{action=\"drop_ratelimit\"}} {}",
        stats.dropped_rate
    );
    let _ = writeln!(
        out,
        "xdp_edge_packets_total{{action=\"drop_synflood\"}} {}",
        stats.dropped_synflood
    );
    let _ = writeln!(
        out,
        "xdp_edge_packets_total{{action=\"pass\"}} {}",
        stats.passed
    );

    // counter：连接跟踪查找
    let _ = writeln!(
        out,
        "# HELP xdp_edge_conntrack_lookups_total Conntrack lookups, by result."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_conntrack_lookups_total counter");
    let _ = writeln!(
        out,
        "xdp_edge_conntrack_lookups_total{{result=\"hit\"}} {}",
        stats.conn_hits
    );
    let _ = writeln!(
        out,
        "xdp_edge_conntrack_lookups_total{{result=\"miss\"}} {}",
        stats.conn_misses
    );

    // gauge：命中率 / 规模 / 吞吐 / 控制面状态
    let _ = writeln!(
        out,
        "# HELP xdp_edge_conntrack_hit_ratio Conntrack hit ratio (0-1)."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_conntrack_hit_ratio gauge");
    let _ = writeln!(out, "xdp_edge_conntrack_hit_ratio {:.6}", hit_ratio);

    let _ = writeln!(
        out,
        "# HELP xdp_edge_conntrack_entries Current conntrack entries."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_conntrack_entries gauge");
    let _ = writeln!(out, "xdp_edge_conntrack_entries {}", conntrack_entries);

    let _ = writeln!(
        out,
        "# HELP xdp_edge_conntrack_evictions_total LRU evictions from conntrack."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_conntrack_evictions_total counter");
    let _ = writeln!(out, "xdp_edge_conntrack_evictions_total {}", evictions);

    let _ = writeln!(
        out,
        "# HELP xdp_edge_pps Packet throughput in the sampling window."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_pps gauge");
    let _ = writeln!(out, "xdp_edge_pps {:.1}", pps);

    let _ = writeln!(
        out,
        "# HELP xdp_edge_backends_alive Backends currently in the Maglev set."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_backends_alive gauge");
    let _ = writeln!(out, "xdp_edge_backends_alive {}", backends_alive);

    let _ = writeln!(
        out,
        "# HELP xdp_edge_lut_version Active Maglev LUT version."
    );
    let _ = writeln!(out, "# TYPE xdp_edge_lut_version gauge");
    let _ = writeln!(out, "xdp_edge_lut_version {}", lut_version);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        let stats = SimStats {
            passed: 3,
            dropped_rate: 100,
            dropped_synflood: 50,
            forwarded: 900,
            conn_hits: 800,
            conn_misses: 100,
        };
        render_metrics(&stats, 12345, 7, 5_300_000, 1.0, 15, 42)
    }

    #[test]
    fn contains_all_metrics_with_help_type() {
        let text = sample();
        for name in [
            "xdp_edge_packets_total",
            "xdp_edge_conntrack_lookups_total",
            "xdp_edge_conntrack_hit_ratio",
            "xdp_edge_conntrack_entries",
            "xdp_edge_conntrack_evictions_total",
            "xdp_edge_pps",
            "xdp_edge_backends_alive",
            "xdp_edge_lut_version",
        ] {
            assert!(
                text.contains(&format!("# HELP {}", name)),
                "缺少 HELP: {}",
                name
            );
            assert!(
                text.contains(&format!("# TYPE {}", name)),
                "缺少 TYPE: {}",
                name
            );
        }
    }

    #[test]
    fn sample_lines_are_parseable() {
        let text = sample();
        let mut samples = 0;
        for line in text.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            samples += 1;
            // exposition 格式：metric_name{labels} value
            let (name_part, value_part) = line.rsplit_once(' ').expect("样本行缺值");
            assert!(
                name_part.starts_with("xdp_edge_"),
                "非法指标名: {}",
                name_part
            );
            value_part.parse::<f64>().expect("值非数值");
            if name_part.contains('{') {
                assert!(name_part.ends_with('}'), "标签未闭合: {}", name_part);
            }
        }
        assert!(samples >= 12, "样本行过少: {}", samples);
    }

    #[test]
    fn derived_values_correct() {
        let text = sample();
        // 命中率 800/900 ≈ 0.888889
        assert!(text.contains("xdp_edge_conntrack_hit_ratio 0.888889"));
        // pps = 5_300_000 / 1.0
        assert!(text.contains("xdp_edge_pps 5300000.0"));
        assert!(text.contains("xdp_edge_lut_version 42"));
        assert!(text.contains("xdp_edge_backends_alive 15"));
    }
}
