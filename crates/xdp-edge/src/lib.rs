//! xdp-edge：eBPF/XDP 边缘网关数据面 —— 用户态模拟器形态。
//!
//! 本 crate 逐包复刻 `bpf/xdp_edge.c` 的 XDP 程序语义：
//! Maglev 一致性哈希选后端、per-源令牌桶限速、SYN flood 检测、
//! LRU 连接跟踪与 IPIP 转发决策。用于在无 eBPF 工具链的
//! Windows 开发机上验证数据面架构与单核软件路径性能。

pub mod conntrack;
pub mod control;
pub mod maglev;
pub mod metrics;
pub mod packet;
pub mod simulator;
pub mod synflood;
pub mod token_bucket;

pub use packet::{Action, FiveTuple, Packet};
pub use simulator::{SimConfig, SimStats, XdpSimulator};
