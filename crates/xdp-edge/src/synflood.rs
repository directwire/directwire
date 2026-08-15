//! SYN flood 检测：per-源 IP 的滑动窗口 SYN/ACK 比率。
//!
//! 原理：正常 TCP 建连中，一个源发出的 SYN 很快会有后续 ACK（三次握手完成）。
//! SYN flood 攻击源只发 SYN 不回 ACK（伪造源甚至根本不存在），
//! 因此窗口内 SYN 计数远超 ACK 计数即为可疑。
//!
//! 与 bpf 侧 syn_track map 对应：每个源维护 (syn_cnt, ack_cnt, window_start)，
//! 窗口滑过即清零重计。判定阈值：窗口内 SYN >= syn_threshold 且
//! SYN > ACK * ack_ratio。

use std::collections::HashMap;

/// 单源滑动窗口计数
#[derive(Debug, Clone, Copy, Default)]
struct Window {
    syn: u32,
    ack: u32,
    start_ns: u64,
    init: bool,
}

/// SYN flood 检测器
pub struct SynFloodGuard {
    windows: HashMap<u32, Window>,
    /// 窗口长度（纳秒）
    window_ns: u64,
    /// 窗口内触发判定的最小 SYN 数（过滤低频噪声）
    syn_threshold: u32,
    /// SYN/ACK 比率阈值
    ack_ratio: u32,
    /// 被判定为攻击的源计数（观测指标）
    pub flagged_sources: u64,
}

impl SynFloodGuard {
    pub fn new(window_ns: u64, syn_threshold: u32, ack_ratio: u32) -> Self {
        Self {
            windows: HashMap::new(),
            window_ns,
            syn_threshold,
            ack_ratio,
            flagged_sources: 0,
        }
    }

    /// 上报一个 TCP 报文，返回该源当前是否判定为攻击源
    pub fn observe(&mut self, src_ip: u32, is_syn: bool, is_ack: bool, now_ns: u64) -> bool {
        let w = self.windows.entry(src_ip).or_default();
        // 窗口滑动：超时则清零重计
        if !w.init || now_ns.saturating_sub(w.start_ns) >= self.window_ns {
            // 老窗口已判定过攻击的不重复计数
            *w = Window { syn: 0, ack: 0, start_ns: now_ns, init: true };
        }
        if is_syn {
            w.syn += 1;
        } else if is_ack {
            w.ack += 1;
        }
        let flagged = w.syn >= self.syn_threshold && w.syn > w.ack.saturating_mul(self.ack_ratio);
        if flagged && w.syn == self.syn_threshold {
            self.flagged_sources += 1;
        }
        flagged
    }

    pub fn tracked_sources(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_syn_flood_source() {
        let mut g = SynFloodGuard::new(1_000_000_000, 100, 4);
        let attacker = 0x0bad_0001u32;
        let mut flagged = false;
        for i in 0..150u64 {
            flagged = g.observe(attacker, true, false, i * 1_000_000);
        }
        assert!(flagged);
        assert_eq!(g.flagged_sources, 1);
    }

    #[test]
    fn normal_handshake_not_flagged() {
        let mut g = SynFloodGuard::new(1_000_000_000, 100, 4);
        let client = 0x0a00_0001u32;
        for i in 0..50u64 {
            // 正常模式：SYN 后紧跟 ACK
            assert!(!g.observe(client, true, false, i * 2_000_000));
            assert!(!g.observe(client, false, true, i * 2_000_000 + 500_000));
        }
        assert_eq!(g.flagged_sources, 0);
    }
}
