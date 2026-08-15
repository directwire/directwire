//! 控制面 agent：把健康检查、LUT 热下发、conntrack 清扫编排成主循环。
//!
//! 对应一体机上的常驻进程（真实实现：Rust + aya/libbpf 操作 BPF map）：
//!
//! ```text
//!   loop {
//!       due = health.probes_due(now)          // 到期后端
//!       for b in due { ok = probe(b);         // 真实实现: 非阻塞 TCP/HTTP 探活
//!                      health.report(b, ok) }
//!       if alive_set_changed {                // 有后端上线/下线
//!           lut.publish(alive_backends)       // 双缓冲构建 + 原子切换
//!       }
//!       sweeper.tick(conntrack, now)          // 周期 TTL 清扫
//!       sleep(tick_interval)
//!   }
//! ```
//!
//! 本骨架中探活动作由调用方注入（虚拟时钟模拟），编排与状态流转逻辑与生产一致。

use super::health::HealthChecker;
use super::lut_publish::LutPublisher;
use super::sweeper::ConntrackSweeper;
use crate::conntrack::ConnTrack;

/// 控制面配置
pub struct AgentConfig {
    /// 探活间隔
    pub probe_interval_ns: u64,
    /// 连续失败下线阈值
    pub fall: u32,
    /// 连续成功上线阈值
    pub rise: u32,
    /// conntrack 清扫周期
    pub sweep_interval_ns: u64,
    /// Maglev LUT 大小
    pub lut_size: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            probe_interval_ns: 1_000_000_000,      // 1s 探活
            fall: 3,                                // 3s 内摘除故障后端（Q2 出口标准）
            rise: 2,
            sweep_interval_ns: 30_000_000_000,      // 30s 清扫
            lut_size: 65537,
        }
    }
}

/// 控制面 agent
pub struct ControlAgent {
    pub health: HealthChecker,
    pub lut: LutPublisher,
    pub sweeper: ConntrackSweeper,
    /// 上次发布使用的存活集合（变更检测）
    last_published: Vec<u32>,
    /// LUT 发布次数（观测指标）
    pub publish_count: u64,
}

impl ControlAgent {
    /// 以初始后端集合启动（注册健康检查 + 发布首版 LUT）
    pub fn new(cfg: &AgentConfig, backends: &[u32]) -> Self {
        let mut health = HealthChecker::new(cfg.probe_interval_ns, cfg.fall, cfg.rise);
        for &b in backends {
            health.register(b);
        }
        let lut = LutPublisher::new(cfg.lut_size, backends);
        Self {
            health,
            lut,
            sweeper: ConntrackSweeper::new(cfg.sweep_interval_ns),
            last_published: backends.to_vec(),
            publish_count: 1,
        }
    }

    /// 单个 tick：返回需要发起探活的后端列表。
    /// 调用方对每个到期后端执行探测后调用 `report_probe()`。
    pub fn tick(&mut self, conntrack: &mut ConnTrack, now_ns: u64) -> Vec<u32> {
        self.sweeper.tick(conntrack, now_ns);
        self.health.probes_due(now_ns)
    }

    /// 回填探测结果；若导致存活集合变化则热发布新 LUT，返回新版本号
    pub fn report_probe(&mut self, backend: u32, ok: bool, now_ns: u64) -> Option<u64> {
        let flipped = self.health.report(backend, ok, now_ns);
        if !flipped {
            return None;
        }
        let alive = self.health.alive_backends();
        if alive.is_empty() || alive == self.last_published {
            return None;
        }
        let ver = self.lut.publish(&alive);
        self.last_published = alive;
        self.publish_count += 1;
        Some(ver)
    }

    /// 当前存活后端（供观测/告警）
    pub fn alive_backends(&self) -> Vec<u32> {
        self.health.alive_backends()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    /// 把一个后端打到 Up（rise 次连续成功）
    fn bring_up(agent: &mut ControlAgent, b: u32, t0: u64) {
        for i in 0..agent.health_rise() {
            agent.report_probe(b, true, t0 + i * S);
        }
    }

    impl ControlAgent {
        fn health_rise(&self) -> u64 {
            // 测试辅助：探活上升阈值
            2
        }
    }

    #[test]
    fn failure_triggers_lut_republish() {
        let cfg = AgentConfig { lut_size: 4099, ..Default::default() };
        let backends = [10u32, 20, 30, 40];
        let mut agent = ControlAgent::new(&cfg, &backends);
        let mut ct = ConnTrack::new(1024, 120 * S);

        // 启动：全部探活上线
        for &b in &backends {
            bring_up(&mut agent, b, 0);
        }
        assert_eq!(agent.alive_backends(), backends);
        let v0 = agent.lut.version();

        // backend 20 连续 3 次失败 -> 下线 -> LUT 重发布
        let mut republished = None;
        for i in 0..3u64 {
            let r = agent.report_probe(20, false, 10 * S + i * S);
            if r.is_some() {
                republished = r;
            }
        }
        assert!(republished.is_some(), "后端下线未触发 LUT 重发布");
        assert!(agent.lut.version() > v0);
        assert_eq!(agent.alive_backends(), vec![10, 30, 40]);
        assert_eq!(agent.lut.snapshot().backends, &[10, 30, 40]);

        // backend 20 恢复：连续 2 次成功 -> 重新上线 -> 再次发布
        let mut back = None;
        for i in 0..2u64 {
            let r = agent.report_probe(20, true, 20 * S + i * S);
            if r.is_some() {
                back = r;
            }
        }
        assert!(back.is_some(), "后端恢复未触发 LUT 重发布");
        assert_eq!(agent.alive_backends(), backends);

        // tick 不产生 panic，清扫正常调度
        let due = agent.tick(&mut ct, 30 * S);
        assert_eq!(due.len(), 4);
    }

    #[test]
    fn flap_does_not_republish() {
        let cfg = AgentConfig { lut_size: 4099, ..Default::default() };
        let mut agent = ControlAgent::new(&cfg, &[10, 20]);
        let mut ct = ConnTrack::new(64, S);
        bring_up(&mut agent, 10, 0);
        bring_up(&mut agent, 20, 0);
        let publishes = agent.publish_count;

        // 抖动：成功-失败交替，不会达到连续阈值
        for i in 0..10u64 {
            let _ = agent.tick(&mut ct, 10 * S + i * S);
            assert!(agent.report_probe(20, i % 2 == 0, 10 * S + i * S).is_none());
        }
        assert_eq!(agent.publish_count, publishes, "抖动不应触发重发布");
    }
}
