//! 控制面模块：健康检查、Maglev LUT 热发布、conntrack TTL 清扫、agent 编排。
//!
//! 对应一体机常驻控制面进程的职责划分（见 `agent` 模块注释的主循环）。

pub mod agent;
pub mod health;
pub mod lut_publish;
pub mod sweeper;

pub use agent::{AgentConfig, ControlAgent};
pub use health::{Health, HealthChecker};
pub use lut_publish::{LutPublisher, LutSnapshot};
pub use sweeper::ConntrackSweeper;
