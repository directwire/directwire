//! 诊断工具：混合负载下长 RPC 的耗时构成（call_timed 单发不双跑流量）。
//! 分离 send_to（请求发送阶段）与总往返——定位长 RPC 里响应阶段为何占大头。
//! 配合 HOMA_TRACE=1 可进一步导出请求/响应传输分位（benchmark 数字的测量装置）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use homa_rpc::rpc::{RpcClient, RpcServer};
use homa_rpc::transport::TransportConfig;

const WORKERS: usize = 8;
const TOTAL_OPS: u64 = 550;
const SHORT_BYTES: usize = 100;
const LONG_BYTES: usize = 1 << 20;

fn homa_config() -> TransportConfig {
    let oc = std::env::var("HOMA_OVERCOMMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    TransportConfig {
        overcommit: oc,
        grant_increment: 1 << 20,
        ..Default::default()
    }
}

fn main() {
    let server = RpcServer::spawn_with_config("127.0.0.1:0", homa_config(), |req| req.to_vec())
        .unwrap();
    let mut client = RpcClient::new_with_config("127.0.0.1:0", homa_config()).unwrap();
    client.attempt_timeout = Duration::from_secs(5);
    client.max_attempts = 3;
    let short_payload = Arc::new(vec![0xabu8; SHORT_BYTES]);
    let long_payload = Arc::new(vec![0xcdu8; LONG_BYTES]);
    for _ in 0..50 {
        client.call(server.addr(), &short_payload).unwrap();
    }
    let saddr = server.addr();
    let client = Arc::new(client);

    #[derive(Default)]
    struct S {
        long_send: Vec<Duration>,
        long_total: Vec<Duration>,
        short_total: Vec<Duration>,
    }
    let s = Arc::new(Mutex::new(S::default()));
    let counter = Arc::new(AtomicU64::new(0));

    let mut hs = Vec::new();
    for _ in 0..WORKERS {
        let c = Arc::clone(&client);
        let sp = Arc::clone(&short_payload);
        let lp = Arc::clone(&long_payload);
        let counter = Arc::clone(&counter);
        let s = Arc::clone(&s);
        hs.push(std::thread::spawn(move || {
            loop {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                if n >= TOTAL_OPS {
                    break;
                }
                let is_long = n % 11 == 10;
                let payload = if is_long { &lp } else { &sp };
                let start = Instant::now();
                let res = if is_long {
                    c.call_timed(saddr, payload).unwrap()
                } else {
                    c.call(saddr, payload).unwrap();
                    (Duration::ZERO, Duration::ZERO)
                };
                let el = start.elapsed();
                let mut s = s.lock().unwrap();
                if is_long {
                    s.long_send.push(res.0);
                    s.long_total.push(el);
                } else {
                    s.short_total.push(el);
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }

    let pct = |v: &[Duration], p: f64| -> Duration {
        let mut x = v.to_vec();
        x.sort();
        if x.is_empty() {
            return Duration::ZERO;
        }
        let i = ((x.len() as f64 - 1.0) * p).ceil() as usize;
        x[i.min(x.len() - 1)]
    };
    let us = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1e6);

    let s = s.lock().unwrap();
    println!("长RPC send阶段: n={} P50={}µs P90={}µs", s.long_send.len(), us(pct(&s.long_send, 0.5)), us(pct(&s.long_send, 0.9)));
    println!("长RPC 总往返:  n={} P50={}µs P90={}µs", s.long_total.len(), us(pct(&s.long_total, 0.5)), us(pct(&s.long_total, 0.9)));
    println!("短RPC 总往返:  n={} P50={}µs P90={}µs", s.short_total.len(), us(pct(&s.short_total, 0.5)), us(pct(&s.short_total, 0.9)));
    let send_p50 = pct(&s.long_send, 0.5);
    let total_p50 = pct(&s.long_total, 0.5);
    if !total_p50.is_zero() {
        let resp = total_p50.saturating_sub(send_p50);
        println!(
            "send={}µs 响应阶段={}µs (send 占 {:.0}%)",
            us(send_p50),
            us(resp),
            100.0 * send_p50.as_secs_f64() / total_p50.as_secs_f64()
        );
    }
    drop(s);
    println!("[客户端] {}", client.debug_stats());
    println!("[服务端] {}", server.debug_stats());

    // 用 msg_id 配对 trace：请求传输（client send_queued → server deliver）与
    // 响应传输（server send_queued → client deliver）。同一时钟（本机），绝对差有效。
    use std::collections::HashMap;
    let ct = client.take_trace();
    let st = server.take_trace();
    let c_send: HashMap<u64, Instant> = ct
        .iter()
        .filter(|(_, e, _)| e == "send_queued")
        .map(|(t, _, id)| (*id, *t))
        .collect();
    let c_deliv: HashMap<u64, Instant> = ct
        .iter()
        .filter(|(_, e, _)| e == "deliver")
        .map(|(t, _, id)| (*id, *t))
        .collect();
    let s_deliv: HashMap<u64, Instant> = st
        .iter()
        .filter(|(_, e, _)| e == "deliver")
        .map(|(t, _, id)| (*id, *t))
        .collect();
    let s_send: HashMap<u64, Instant> = st
        .iter()
        .filter(|(_, e, _)| e == "send_queued")
        .map(|(t, _, id)| (*id, *t))
        .collect();
    let mut req_xmit: Vec<Duration> = c_send
        .iter()
        .filter_map(|(id, t)| s_deliv.get(id).map(|d| *d - *t))
        .collect();
    let mut resp_xmit: Vec<Duration> = s_send
        .iter()
        .filter_map(|(id, t)| c_deliv.get(id).map(|d| *d - *t))
        .collect();
    let pct = |v: &[Duration], p: f64| -> Duration {
        let mut x = v.to_vec();
        x.sort();
        if x.is_empty() {
            return Duration::ZERO;
        }
        let i = ((x.len() as f64 - 1.0) * p).ceil() as usize;
        x[i.min(x.len() - 1)]
    };
    req_xmit.sort();
    resp_xmit.sort();
    println!(
        "请求传输(client send_queued→server deliver): n={} P50={}µs P90={}µs",
        req_xmit.len(),
        us(pct(&req_xmit, 0.5)),
        us(pct(&req_xmit, 0.9))
    );
    println!(
        "响应传输(server send_queued→client deliver): n={} P50={}µs P90={}µs",
        resp_xmit.len(),
        us(pct(&resp_xmit, 0.5)),
        us(pct(&resp_xmit, 0.9))
    );
    // 长消息的传输耗时（取尾部大样本）：请求传输 P90/P99 大致反映长消息
    if req_xmit.len() >= 4 {
        let i90 = (req_xmit.len() as f64 * 0.90) as usize;
        let i99 = (req_xmit.len() as f64 * 0.99) as usize;
        println!(
            "  请求传输尾部: P90={}µs P99={}µs",
            us(req_xmit[i90.min(req_xmit.len() - 1)]),
            us(req_xmit[i99.min(req_xmit.len() - 1)])
        );
    }
    if resp_xmit.len() >= 4 {
        let i90 = (resp_xmit.len() as f64 * 0.90) as usize;
        let i99 = (resp_xmit.len() as f64 * 0.99) as usize;
        println!(
            "  响应传输尾部: P90={}µs P99={}µs",
            us(resp_xmit[i90.min(resp_xmit.len() - 1)]),
            us(resp_xmit[i99.min(resp_xmit.len() - 1)])
        );
    }
}
