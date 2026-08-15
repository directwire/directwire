//! # homa-rpc — Homa 消息导向传输的用户态移植 + 极简 RPC
//!
//! - [`transport`]：消息导向、无连接、接收端 GRANT 调度（SRPT）、
//!   首 RTT 未调度窗口直发、8 级优先级、RESEND 重传。
//! - [`rpc`]：请求/响应抽象，at-least-once + 服务端幂等去重。

pub mod rpc;
pub mod transport;

pub use rpc::{RpcClient, RpcServer};
pub use transport::{Transport, TransportConfig};
