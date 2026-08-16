//! 确定性引擎：跑变异输入 + `catch_unwind` 崩溃检测 + 崩溃输入落盘。
//!
//! 诚实限制：`catch_unwind` 抓不到 **abort**（如 OOM 分配炸弹）。防 abort 的防线是
//! 目标侧的长度守卫（homa `MAX_MSG_LEN`、moq Reader 的剩余长度检查）+ 输入长度上限
//! （默认 8 KiB），保证目标内任何与输入成正比的操作都是有限分配、任何从不可信头部
//! 导出的长度都被守卫拦截。
//!
//! 挂起（hang）检测不在本引擎范围：目标是纯解析/状态机，输入有界，循环结构由实现保证；
//! 若 CI 长跑发现目标超时，用 `fuzz/` 的 libFuzzer `-timeout=` 精确隔离再修。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::mutator::Mutator;

/// 一次 fuzz 运行的统计
#[derive(Debug, Default)]
pub struct RunStats {
    pub iterations: u64,
    pub crashes: u64,
    pub last_crash: Option<Crash>,
}

/// 一次崩溃的完整记录（panic 信息 + 最小输入 + 落盘位置）
#[derive(Debug)]
pub struct Crash {
    pub target: String,
    pub panic_msg: String,
    pub input: Vec<u8>,
    pub file: std::path::PathBuf,
}

/// 跑一个目标，直到时间预算或迭代预算耗尽。
///
/// - 每次输入在 `catch_unwind` 内执行；panic → 记录 + 落盘，**继续跑**（fuzz 不停止）。
/// - 输入从语料（少量直接命中）与变异器（主体）产生，seed 决定全部序列。
/// - 崩溃上限（默认 100）防疯狂落盘。
pub fn run(
    target_name: &str,
    f: fn(&[u8]),
    seed_corpus: &[&[u8]],
    seed: u64,
    max_len: usize,
    iterations: u64,
    time_budget: Option<Duration>,
    save_dir: &Path,
) -> RunStats {
    let mut stats = RunStats::default();
    let mut mutator = Mutator::new(seed);
    let t0 = Instant::now();
    const CRASH_LIMIT: u64 = 100;

    loop {
        if iterations > 0 && stats.iterations >= iterations {
            break;
        }
        if let Some(budget) = time_budget {
            if t0.elapsed() >= budget {
                break;
            }
        }
        // 1/8 概率直接跑语料基底，其余走变异
        let base: &[u8] = if seed_corpus.is_empty() {
            &[]
        } else {
            &seed_corpus[mutator.rng_mut().below(seed_corpus.len())]
        };
        let input = if stats.iterations % 8 == 0 {
            base.to_vec()
        } else {
            mutator.next(base, max_len)
        };
        let input_clone = input.clone();
        let res = catch_unwind(AssertUnwindSafe(|| f(&input)));
        stats.iterations += 1;
        if let Err(e) = res {
            let msg = panic_msg(&e);
            let seq = stats.crashes + 1;
            let file = save_dir.join(format!("{target_name}-{seq:04}.bin"));
            let _ = std::fs::write(&file, &input_clone);
            stats.crashes += 1;
            stats.last_crash = Some(Crash {
                target: target_name.to_string(),
                panic_msg: msg,
                input: input_clone,
                file,
            });
            if stats.crashes >= CRASH_LIMIT {
                break;
            }
        }
    }
    stats
}

fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "非字符串 panic payload".to_string()
    }
}
