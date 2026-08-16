//! 目标层：五个 crate 所有解析入口，统一暴露 `pub fn fuzz(data: &[u8])`。
//!
//! 分层纪律（老板验收分工）：
//! - 每个目标只做「拿字节 → 喂解析/状态机」，**不 panic 是硬性契约**；
//!   对不可信输入的一切长度/分配路径必须在目标内先守卫（见各文件注释）。
//! - 目标函数是纯函数（无全局可变状态），同一份代码：
//!   - 本地：确定性引擎（`engine`）跑，`cargo run -p fuzz-harness --release --bin driver -- <target> --time 3600`；
//!   - CI：`fuzz/fuzz_targets/` 一行适配编译进 libFuzzer，零重写。
//! - 语料在 `corpus()`：每个目标提供若干**结构合法**的种子输入，给变异器好基底。

pub mod gmpq_handshake;
pub mod homa_transport;
pub mod moq_message;
pub mod p2p_proto;
pub mod xdp_pipeline;

/// 一个 fuzz 目标的注册信息
pub struct Target {
    pub name: &'static str,
    /// 目标入口：拿输入字节喂解析/状态机。panic = crash。
    pub f: fn(&[u8]),
    /// 结构合法的种子语料（变异器的基底）
    pub corpus: Vec<Vec<u8>>,
}

/// 全部五个目标（引擎/smoke/CI 共用这一注册表）
pub fn all() -> Vec<Target> {
    vec![
        Target {
            name: "homa_transport",
            f: homa_transport::fuzz,
            corpus: homa_transport::corpus(),
        },
        Target {
            name: "moq_message",
            f: moq_message::fuzz,
            corpus: moq_message::corpus(),
        },
        Target {
            name: "gmpq_handshake",
            f: gmpq_handshake::fuzz,
            corpus: gmpq_handshake::corpus(),
        },
        Target {
            name: "p2p_proto",
            f: p2p_proto::fuzz,
            corpus: p2p_proto::corpus(),
        },
        Target {
            name: "xdp_pipeline",
            f: xdp_pipeline::fuzz,
            corpus: xdp_pipeline::corpus(),
        },
    ]
}

/// 按名字取目标
pub fn by_name(name: &str) -> Option<Target> {
    all().into_iter().find(|t| t.name == name)
}
