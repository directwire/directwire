//! 诊断工具：单线程长 RPC 的完整时间线拆分（白皮书架构段的数据来源）。
//! HOMA_TRACE=1 下用 transport 事件把一次长 RPC 拆成四段：
//!   req_xmit  = server_deliver[X]  - client_send_queued[X]  （请求传输）
//!   server_gap = server_send_queued[Y] - server_deliver[X]  （服务端处理：handler+echo入队）
//!   resp_xmit = client_deliver[Y]  - server_send_queued[Y]  （响应传输）
//!   client_gap = client_send_queued[X+1] - client_deliver[Y]（客户端下一请求入队延迟）
//! workers=1 时事件严格按序，用时间序配对。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use homa_rpc::rpc::{RpcClient, RpcServer};
use homa_rpc::transport::TransportConfig;

const OPS: usize = 20;
const MB: usize = 1 << 20;

fn main() {
    let cfg = TransportConfig {
        overcommit: 2,
        grant_increment: 1 << 20,
        ..Default::default()
    };
    let server = RpcServer::spawn_with_config("127.0.0.1:0", cfg.clone(), |req| req.to_vec())
        .unwrap();
    let mut client = RpcClient::new_with_config("127.0.0.1:0", cfg).unwrap();
    client.attempt_timeout = Duration::from_secs(5);
    client.max_attempts = 3;
    let payload = vec![0xcdu8; MB];
    // 预热 1 条（打掉首个分配/路径热身后的偏差）
    client
        .call_with_timeout(server.addr(), &payload, Duration::from_secs(5), 3)
        .unwrap();

    let mut req_xmit = Vec::new();
    let mut grant_rtt = Vec::new();
    let mut server_gap = Vec::new();
    let mut resp_xmit = Vec::new();
    let mut client_gap = Vec::new();
    let mut totals = Vec::new();

    for _ in 0..OPS {
        let t0 = Instant::now();
        client.call_with_timeout(server.addr(), &payload, Duration::from_secs(5), 3).unwrap();
        totals.push(t0.elapsed());
        // 收集本调用期间产生的 trace（丢 trace 门控，精确配对）
        let ct = client.take_trace();
        let st = server.take_trace();
        let c_send: HashMap<u64, Instant> = ct.iter().filter(|(_, e, _)| e == "send_queued").map(|(t, _, id)| (*id, *t)).collect();
        let c_grant: HashMap<u64, Instant> = ct.iter().filter(|(_, e, _)| e == "grant").map(|(t, _, id)| (*id, *t)).collect();
        let c_deliv: HashMap<u64, Instant> = ct.iter().filter(|(_, e, _)| e == "deliver").map(|(t, _, id)| (*id, *t)).collect();
        let s_deliv: HashMap<u64, Instant> = st.iter().filter(|(_, e, _)| e == "deliver").map(|(t, _, id)| (*id, *t)).collect();
        let s_send: HashMap<u64, Instant> = st.iter().filter(|(_, e, _)| e == "send_queued").map(|(t, _, id)| (*id, *t)).collect();
        // 请求配对：client 本调用只发了 1 条，其 send_queued 是最晚的 client send_queued
        let &c_req_t = c_send.values().max().unwrap();
        let req_id = *c_send.iter().find(|(_, t)| **t == c_req_t).unwrap().0;
        // 授权往返：客户端发出 unscheduled 首段 → 收到 GRANT
        if let Some(&g) = c_grant.get(&req_id) {
            grant_rtt.push(g - c_req_t);
        }
        let s_del_t = *s_deliv.get(&req_id).unwrap();
        req_xmit.push(s_del_t - c_req_t);
        // 服务端 gap：该请求 deliver 之后最近的服务端 send_queued
        let s_send_t = *s_send.iter().filter(|(_, t)| **t > s_del_t).map(|(_, t)| t).min().unwrap();
        server_gap.push(s_send_t - s_del_t);
        // 响应配对：服务端这条 send_queued 的 msg_id → 客户端 deliver
        let resp_id = *s_send.iter().find(|(_, t)| **t == s_send_t).unwrap().0;
        let c_del_t = *c_deliv.get(&resp_id).unwrap();
        resp_xmit.push(c_del_t - s_send_t);
        // 客户端 gap：本响应 deliver 之后到下一次 send_queued 的间隔
        if let Some(&next) = c_send.values().filter(|t| **t > c_del_t).min() {
            client_gap.push(next - c_del_t);
        }
    }

    let pct = |v: &mut Vec<Duration>, p: f64| -> Duration {
        v.sort();
        if v.is_empty() { return Duration::ZERO; }
        let i = ((v.len() as f64 - 1.0) * p).ceil() as usize;
        v[i.min(v.len() - 1)]
    };
    let us = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1e6);
    println!("单线程 1MiB RPC × {} 次：", OPS);
    println!("  总往返: P50={}µs", us(pct(&mut totals.clone(), 0.5)));
    println!("  授权往返 grant_rtt:      P50={}µs P90={}µs", us(pct(&mut grant_rtt, 0.5)), us(pct(&mut grant_rtt, 0.9)));
    println!("  请求传输 req_xmit:      P50={}µs P90={}µs", us(pct(&mut req_xmit, 0.5)), us(pct(&mut req_xmit, 0.9)));
    println!("  服务端处理 server_gap:   P50={}µs P90={}µs", us(pct(&mut server_gap, 0.5)), us(pct(&mut server_gap, 0.9)));
    println!("  响应传输 resp_xmit:      P50={}µs P90={}µs", us(pct(&mut resp_xmit, 0.5)), us(pct(&mut resp_xmit, 0.9)));
    println!("  客户端衔接 client_gap:   P50={}µs P90={}µs", us(pct(&mut client_gap, 0.5)), us(pct(&mut client_gap, 0.9)));
}
