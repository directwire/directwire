//! 后端健康检查（虚拟时钟探活模拟）。
//!
//! 产品语义：控制面对每个后端周期发起探活（TCP connect / HTTP GET），
//! 连续 `fall` 次失败判定下线、连续 `rise` 次成功恢复上线（防抖）。
//! 本骨架用虚拟时钟驱动：agent 询问「到期应探测的后端」，
//! 调用方回填探测结果（真实实现里是非阻塞 IO + 超时），
//! 状态机与抖动抑制逻辑与生产完全一致。

use std::collections::HashMap;

/// 后端健康状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// 初始/未知：尚未积累足够样本，不参与选路
    Unknown,
    Up,
    Down,
}

#[derive(Debug, Clone, Copy)]
struct BackendHealth {
    state: Health,
    /// 上一次探测结果（用于判定「连续」）
    last_ok: Option<bool>,
    /// 同方向结果的连续次数
    streak: u32,
    /// 上次探测时刻（u64::MAX = 从未探测，立即到期）
    last_probe_ns: u64,
}

/// 健康检查器
pub struct HealthChecker {
    backends: HashMap<u32, BackendHealth>,
    /// 探活间隔
    interval_ns: u64,
    /// 连续失败多少次判定下线
    fall: u32,
    /// 连续成功多少次判定上线
    rise: u32,
}

impl HealthChecker {
    pub fn new(interval_ns: u64, fall: u32, rise: u32) -> Self {
        assert!(fall >= 1 && rise >= 1);
        Self { backends: HashMap::new(), interval_ns, fall, rise }
    }

    /// 注册后端（初始 Unknown，立即可探测）
    pub fn register(&mut self, backend: u32) {
        self.backends.insert(
            backend,
            BackendHealth { state: Health::Unknown, last_ok: None, streak: 0, last_probe_ns: u64::MAX },
        );
    }

    pub fn unregister(&mut self, backend: u32) {
        self.backends.remove(&backend);
    }

    /// 到期应发起探测的后端列表（agent 每个 tick 调用），排序保证确定性
    pub fn probes_due(&self, now_ns: u64) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .backends
            .iter()
            .filter(|(_, h)| {
                h.last_probe_ns == u64::MAX // 从未探测：立即到期
                    || now_ns.saturating_sub(h.last_probe_ns) >= self.interval_ns
            })
            .map(|(&ip, _)| ip)
            .collect();
        v.sort_unstable();
        v
    }

    /// 回填一次探测结果，返回该后端状态是否发生翻转
    pub fn report(&mut self, backend: u32, ok: bool, now_ns: u64) -> bool {
        let Some(h) = self.backends.get_mut(&backend) else { return false };
        h.last_probe_ns = now_ns;
        h.streak = if h.last_ok == Some(ok) { h.streak + 1 } else { 1 };
        h.last_ok = Some(ok);

        let old = h.state;
        let new = if ok && h.streak >= self.rise {
            Health::Up // Unknown/Down 积累足够连续成功 -> Up
        } else if !ok && h.streak >= self.fall {
            Health::Down // 任意状态积累足够连续失败 -> Down
        } else {
            h.state
        };
        if new != old {
            h.state = new;
            h.streak = 0; // 翻转后重新积累，防止抖动期反复横跳
            true
        } else {
            false
        }
    }

    /// 当前存活（参与 Maglev 选路）的后端集合，排序保证确定性
    pub fn alive_backends(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .backends
            .iter()
            .filter(|(_, h)| matches!(h.state, Health::Up))
            .map(|(&ip, _)| ip)
            .collect();
        v.sort_unstable();
        v
    }

    pub fn state(&self, backend: u32) -> Option<Health> {
        self.backends.get(&backend).map(|h| h.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000; // 1s

    #[test]
    fn unknown_to_up_after_rise() {
        let mut hc = HealthChecker::new(S, 3, 2);
        hc.register(10);
        assert_eq!(hc.state(10), Some(Health::Unknown));
        assert_eq!(hc.probes_due(0), vec![10]);
        assert!(!hc.report(10, true, 0)); // 第 1 次成功，未到 rise=2
        assert!(hc.report(10, true, S)); // 连续第 2 次成功 -> Up
        assert_eq!(hc.alive_backends(), vec![10]);
    }

    #[test]
    fn up_to_down_after_fall_and_flap_suppressed() {
        let mut hc = HealthChecker::new(S, 3, 2);
        hc.register(20);
        hc.report(20, true, 0);
        hc.report(20, true, S);
        assert_eq!(hc.state(20), Some(Health::Up));

        // 抖动：失败、失败、成功 —— 不应下线（连续被打断）
        assert!(!hc.report(20, false, 2 * S));
        assert!(!hc.report(20, false, 3 * S));
        assert!(!hc.report(20, true, 4 * S)); // 打断失败 streak
        assert!(!hc.report(20, false, 5 * S));
        assert!(!hc.report(20, false, 6 * S)); // 仅连续 2 次失败
        assert_eq!(hc.state(20), Some(Health::Up));

        // 5S/6S/7S 连续 3 次失败 -> Down
        assert!(hc.report(20, false, 7 * S));
        assert_eq!(hc.state(20), Some(Health::Down));
        assert!(hc.alive_backends().is_empty());
    }

    #[test]
    fn probe_scheduling_by_interval() {
        let mut hc = HealthChecker::new(S, 3, 2);
        hc.register(30);
        hc.register(31);
        assert_eq!(hc.probes_due(0), vec![30, 31]);
        hc.report(30, true, 0); // 只探测了 30
        // 0.5s 后：30 未到 1s 间隔；31 从未探测过，仍然到期
        assert_eq!(hc.probes_due(S / 2), vec![31]);
        // 1s 后：31 到期（从未探测），30 也到期（距上次 1s）
        assert_eq!(hc.probes_due(S), vec![30, 31]);
    }
}
