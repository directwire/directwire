//! gmpq_handshake 各相位/原语耗时剖析（找 100× 目标被什么吃掉）。
//!
//! 用法: `cargo run -p fuzz-harness --release --bin bench_gmpq -- [ms]`
//! 默认每项测 2000ms，打印「每迭代 µs」。

use std::time::{Duration, Instant};

use fuzz_harness::targets;
use gm_pq_stack::handshake::{Initiator, Responder};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;

fn bench<F: FnMut()>(name: &str, ms: u64, mut f: F) {
    let budget = Duration::from_millis(ms);
    let t0 = Instant::now();
    let mut n: u64 = 0;
    while t0.elapsed() < budget {
        f();
        n += 1;
    }
    let us = t0.elapsed().as_micros() as f64 / n as f64;
    println!("{name:<38} {us:9.1} µs/iter  ({n} iters)");
}

fn main() {
    let ms: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let gmpq = targets::by_name("gmpq_handshake").unwrap();
    let f = gmpq.f;

    let body: Vec<u8> = vec![0xabu8; 16];
    let mk = |phase: u8| {
        let mut v = vec![phase, 0, 0];
        v.extend_from_slice(&body);
        v
    };

    println!("── 相位（fuzz 输入相位选择，含一次密钥池预热） ──");
    // 预热（OnceLock keygen 只该算一次）
    f(&mk(0));
    bench("phase 0: write_msg1 + read_msg2", ms, || f(&mk(0)));
    bench("phase 1: read_msg1 + write_msg2", ms, || f(&mk(1)));
    bench("phase 2: legal prefix + read_msg3(fuzz)", ms, || f(&mk(2)));
    bench("phase 3: golden 互认证", ms, || f(&mk(3)));
    bench("phase 4: PSK 会话恢复", ms, || f(&mk(4)));
    bench("phase 5: 0-RTT early data", ms, || f(&mk(5)));
    bench("phase 6: cookie 挑战", ms, || f(&mk(6)));
    bench("phase 7: PSK msg3 深解析", ms, || f(&mk(7)));

    // 深解析确认：合法 msg3 长度的消息体 → read_msg3 过长度闸门、真跑 decap。
    // 生成一个合法 msg3（与 corpus() 相同的来源路径）。
    let mut rng = SysRng::new();
    let (isk, ipk) = DefaultHybrid::keypair(&mut rng).unwrap();
    let (rsk, rpk) = DefaultHybrid::keypair(&mut rng).unwrap();
    let mut init: Initiator<DefaultHybrid> = Initiator::new(isk, ipk);
    let m1 = init.write_msg1(&mut rng).unwrap();
    let mut resp: Responder<DefaultHybrid> = Responder::new(rsk, rpk);
    resp.read_msg1(&m1).unwrap();
    let m2 = resp.write_msg2(&mut rng).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, _) = init.write_msg3(&mut rng).unwrap();
    let deep2 = [vec![2u8, 0, 0], m3.clone()].concat();
    let deep7 = [vec![7u8, 0, 0], m3].concat();
    bench("phase 2 深解析（合法 msg3 体, 真 decap）", ms, || f(&deep2));
    bench("phase 7 深解析（合法 msg3 体, 真 decap）", ms, || f(&deep7));

    println!("── 底层原语（libsmx 直接计时） ──");
    let mut rng = SysRng::new();
    let mut rng = SysRng::new();
    let (sk, pk) = DefaultHybrid::keypair(&mut rng).unwrap();
    let (ct, ss) = DefaultHybrid::encapsulate(&mut rng, &pk).unwrap();
    assert_eq!(ss.len(), 32);
    bench("DefaultHybrid::keypair", ms, || {
        let _ = DefaultHybrid::keypair(&mut rng).unwrap();
    });
    bench("DefaultHybrid::encapsulate", ms, || {
        let _ = DefaultHybrid::encapsulate(&mut rng, &pk).unwrap();
    });
    bench("DefaultHybrid::decapsulate", ms, || {
        let _ = DefaultHybrid::decapsulate(&sk, &ct).unwrap();
    });
    // 确认没有析构/拷贝尾随成本：Clone 一次 keypair
    bench("SecretKey Clone", ms, || {
        let _c = sk.clone();
    });
    let _ = ss;
}
