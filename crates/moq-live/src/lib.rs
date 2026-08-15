//! moq-live：MoQ（Media over QUIC）国产化低延迟直播传输 —— 可运行的架构验证骨架。
//!
//! 模块划分：
//! - [`varint`]：QUIC varint 编解码（RFC 9000 §16）；
//! - [`message`]：SETUP / ANNOUNCE / SUBSCRIBE / OBJECT 消息帧；
//! - [`track`]：namespace / track / group / object 寻址抽象与优先级；
//! - [`cache`]：按 group 的滑动窗口缓存（追赶语义）；
//! - [`hub`]：发布订阅扇出枢纽（relay 核心状态）；
//! - [`net`]：QUIC endpoint 与流式帧 IO；
//! - [`relay`]：中继服务器；
//! - [`client`]：publisher / subscriber 客户端辅助。

pub mod cache;
pub mod client;
pub mod control;
pub mod dropq;
pub mod hub;
pub mod message;
pub mod net;
pub mod relay;
pub mod track;
pub mod varint;

/// 国密+后量子会话层（feature `gm-pq`，默认关闭）。
#[cfg(feature = "gm-pq")]
pub mod gmpq;
