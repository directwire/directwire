//! smoke 测试 = 验收线①：五个目标各跑 2 秒确定性 fuzz，必须 0 崩溃。
//!
//! 随主 CI 的 `cargo test --workspace` 运行（永远是 PR 门禁的一部分）。
//! 固定种子保证可复现；时间预算保证 CI 成本恒定（~5×2s，并行）。
//! 长跑在 CI fuzz job（nightly 2h libFuzzer）与本机
//! `cargo run -p fuzz-harness --release --bin driver -- <target> --time 3600` 完成。

use std::path::Path;
use std::time::Duration;

use fuzz_harness::engine;
use fuzz_harness::targets;

#[test]
fn 五个目标_两秒无崩溃() {
    for t in targets::all() {
        let corpus: Vec<&[u8]> = t.corpus.iter().map(|v| v.as_slice()).collect();
        let stats = engine::run(
            &t.name,
            t.f,
            &corpus,
            0x1234_5678,
            8192,
            0,
            Some(Duration::from_secs(2)),
            Path::new(&std::env::temp_dir()),
        );
        assert_eq!(
            stats.crashes, 0,
            "目标 {} 崩溃: {:?}",
            t.name, stats.last_crash
        );
        eprintln!("[smoke] {}: {} 迭代 0 崩溃 ✓", t.name, stats.iterations);
    }
}
