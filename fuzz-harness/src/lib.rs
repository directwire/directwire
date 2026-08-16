//! 确定性 fuzz harness：目标层与引擎层解耦。
//!
//! 架构（按老板验收分工）：
//! - [`targets`]：五个 crate 所有解析入口，统一暴露 `pub fn fuzz(data: &[u8])`。
//!   本地跑确定性引擎；CI 上同一批函数直接编译进 libFuzzer
//!   （`fuzz/fuzz_targets/` 每目标一行适配），零重写。
//! - [`mutator`]：确定性结构化变异器（splitmix64 PRNG，同 seed 完全可复现）。
//! - [`engine`]：`catch_unwind` 崩溃检测 + 崩溃输入落盘。
//!
//! 分层纪律：引擎层不依赖任何被测 crate；目标层不依赖引擎。
//!
//! 运行（本机，无需 C 编译器 / 无需 nightly）：
//! ```sh
//! cargo run -p fuzz-harness --release --bin driver -- homa_transport --time 3600
//! ```

pub mod engine;
pub mod mutator;
pub mod targets;
