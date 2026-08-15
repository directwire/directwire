//! XDP 数据面模拟器：按 bpf/xdp_edge.c 的处理顺序逐包执行判决。
//!
//! 管线（与内核 XDP 程序一一对应）：
//!   1. per-源令牌桶限速          -> 超限 XDP_DROP
//!   2. SYN flood 检测            -> 攻击源 XDP_DROP
//!   3. 连接跟踪查找（LRU+过期）  -> 命中：复用既有后端决策
//!   4. 未命中：Maglev 选后端     -> 写入连接跟踪
//!   5. IPIP 封装后 XDP_TX 转发   -> Action::Forward(backend_ip)
//!
//! 本模块只产出判决与统计，不触碰真实 socket —— 与 XDP 程序
//! 在网卡驱动层运行、无需系统调用的语义保持一致。

use crate::conntrack::{ConnEntry, ConnTrack};
use crate::maglev::{Maglev, flow_hash};
use crate::packet::{Action, Packet};
use crate::synflood::SynFloodGuard;
use crate::token_bucket::RateLimiter;

/// 模拟器配置
pub struct SimConfig {
    /// 每源限速（包/秒）
    pub rate_per_sec: f64,
    /// 限速突发容量
    pub rate_burst: f64,
    /// 限速 map 容量
    pub rate_max_entries: usize,
    /// 连接跟踪容量
    pub conntrack_capacity: usize,
    /// 连接超时（纳秒）
    pub conntrack_timeout_ns: u64,
    /// SYN 检测窗口（纳秒）
    pub syn_window_ns: u64,
    /// SYN 判定阈值
    pub syn_threshold: u32,
    /// SYN/ACK 比率阈值
    pub syn_ack_ratio: u32,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            rate_per_sec: 100_000.0,
            rate_burst: 1_000.0,
            rate_max_entries: 1 << 20,
            conntrack_capacity: 1 << 16,
            conntrack_timeout_ns: 120 * 1_000_000_000, // 120s，对齐内核 TCP 跟踪默认
            syn_window_ns: 1_000_000_000,
            syn_threshold: 1_000,
            syn_ack_ratio: 4,
        }
    }
}

/// 决策统计（对应 bpf 侧 stats per-CPU array）
#[derive(Debug, Default, Clone, Copy)]
pub struct SimStats {
    pub passed: u64,
    pub dropped_rate: u64,
    pub dropped_synflood: u64,
    pub forwarded: u64,
    pub conn_hits: u64,
    pub conn_misses: u64,
}

impl SimStats {
    pub fn total(&self) -> u64 {
        self.passed + self.dropped_rate + self.dropped_synflood + self.forwarded
    }
}

/// XDP 数据面模拟器
pub struct XdpSimulator {
    limiter: RateLimiter,
    syn_guard: SynFloodGuard,
    conntrack: ConnTrack,
    maglev: Maglev,
    pub stats: SimStats,
}

impl XdpSimulator {
    pub fn new(cfg: &SimConfig, backends: &[u32], maglev_size: usize) -> Self {
        let mut maglev = Maglev::new(maglev_size);
        maglev.rebuild(backends);
        Self {
            limiter: RateLimiter::new(cfg.rate_per_sec, cfg.rate_burst, cfg.rate_max_entries),
            syn_guard: SynFloodGuard::new(cfg.syn_window_ns, cfg.syn_threshold, cfg.syn_ack_ratio),
            conntrack: ConnTrack::new(cfg.conntrack_capacity, cfg.conntrack_timeout_ns),
            maglev,
            stats: SimStats::default(),
        }
    }

    /// 后端集合变更（扩缩容 / 健康检查摘除故障后端）
    pub fn set_backends(&mut self, backends: &[u32]) {
        self.maglev.rebuild(backends);
    }

    /// 处理单个报文，now_ns 为单调时钟（测试可注入虚拟时钟）。
    pub fn process(&mut self, pkt: &Packet, now_ns: u64) -> Action {
        let src = pkt.tuple.src_ip;

        // 1. 令牌桶限速
        if !self.limiter.allow(src, now_ns) {
            self.stats.dropped_rate += 1;
            return Action::Drop;
        }

        // 2. SYN flood 检测（仅 TCP）
        if pkt.tuple.protocol == crate::packet::PROTO_TCP
            && self
                .syn_guard
                .observe(src, pkt.is_syn(), pkt.is_ack(), now_ns)
        {
            self.stats.dropped_synflood += 1;
            return Action::Drop;
        }

        // 3. 连接跟踪
        if let Some(entry) = self.conntrack.lookup(&pkt.tuple, now_ns) {
            self.stats.conn_hits += 1;
            self.stats.forwarded += 1;
            return Action::Forward(entry.backend_ip);
        }
        self.stats.conn_misses += 1;

        // 4. Maglev 选后端（IPIP 封装的内层目的地）
        let backend = self.maglev.lookup(flow_hash(&pkt.tuple));
        self.conntrack.insert(
            pkt.tuple,
            ConnEntry {
                backend_ip: backend,
                last_seen_ns: now_ns,
            },
        );

        // 5. IPIP 封装 + XDP_TX
        self.stats.forwarded += 1;
        Action::Forward(backend)
    }

    /// 连接跟踪当前规模（观测用）
    pub fn conntrack_len(&self) -> usize {
        self.conntrack.len()
    }

    pub fn conntrack_evictions(&self) -> u64 {
        self.conntrack.evictions
    }

    /// 暴露连接表给控制面（周期 TTL 清扫用）
    pub fn conntrack_mut(&mut self) -> &mut ConnTrack {
        &mut self.conntrack
    }

    /// 应用控制面热发布的 LUT（数据面不重算，仅切换表内容）。
    /// 内核侧对应 bpf 控制面写入 maglev_lut map 后翻转激活版本。
    pub fn apply_lut(&mut self, backends: Vec<u32>, table: Vec<u32>) {
        self.maglev.load_table(backends, table);
    }
}
