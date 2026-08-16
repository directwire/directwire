//! 确定性 fuzz 驱动：`driver <target> [--time <secs>] [--iters <n>] ...`
//!
//! - 无外部依赖，稳定 toolchain 直接跑（本机无需 clang/nightly）。
//! - 崩溃 → 打印 panic 信息 + 输入前 64 字节 hex，退出码 1（CI 判定用）。
//! - 崩溃输入落盘到 `--save-dir`（默认 `fuzz-crashes/`），命名 `<target>-NNNN.bin`。

use std::path::PathBuf;
use std::time::Duration;

use fuzz_harness::engine;
use fuzz_harness::targets;

const DEFAULT_SEED: u64 = 0x5eed_0000_f00d;
const DEFAULT_MAX_LEN: usize = 8192;

fn usage() -> ! {
    eprintln!(
        "用法: driver <target> [--time <秒>] [--iters <n>] [--seed <u64>] [--max-len <n>] [--save-dir <目录>]\n\
         \n\
         目标: {}",
        targets::all()
            .iter()
            .map(|t| t.name)
            .collect::<Vec<_>>()
            .join(", ")
    );
    std::process::exit(2);
}

fn parse_u64(name: &str, s: &str) -> u64 {
    match s.parse::<u64>() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("参数 {name} 非法: {s:?}");
            usage();
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let target_name = &args[1];

    let mut time_secs: Option<u64> = None;
    let mut iters: u64 = 0;
    let mut seed = DEFAULT_SEED;
    let mut max_len = DEFAULT_MAX_LEN;
    let mut save_dir = PathBuf::from("fuzz-crashes");

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--time" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                time_secs = Some(parse_u64("--time", &args[i]));
            }
            "--iters" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                iters = parse_u64("--iters", &args[i]);
            }
            "--seed" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                seed = parse_u64("--seed", &args[i]);
            }
            "--max-len" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                max_len = parse_u64("--max-len", &args[i]) as usize;
            }
            "--save-dir" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                save_dir = PathBuf::from(&args[i]);
            }
            other => {
                eprintln!("未知参数: {other:?}");
                usage();
            }
        }
        i += 1;
    }

    let Some(target) = targets::by_name(target_name) else {
        eprintln!("未知目标: {target_name:?}");
        usage();
    };
    if let Err(e) = std::fs::create_dir_all(&save_dir) {
        eprintln!("无法创建落盘目录 {}: {e}", save_dir.display());
        std::process::exit(2);
    }

    let budget = time_secs.map(Duration::from_secs);
    let corpus: Vec<&[u8]> = target.corpus.iter().map(|v| v.as_slice()).collect();
    let stats = engine::run(
        &target.name,
        target.f,
        &corpus,
        seed,
        max_len,
        iters,
        budget,
        &save_dir,
    );

    println!(
        "[fuzz-harness] {target_name}: {} 次迭代, {} 次崩溃, 种子 {seed:#x}, 输入上限 {max_len}B",
        stats.iterations, stats.crashes
    );

    if let Some(c) = &stats.last_crash {
        println!("最后一次崩溃: {}", c.panic_msg);
        println!("落盘: {}", c.file.display());
        println!(
            "输入前 64 字节 (hex): {}",
            hex(&c.input[..c.input.len().min(64)])
        );
        std::process::exit(1);
    }
}

/// 小 hex 转储（不引第三方 crate）
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}
