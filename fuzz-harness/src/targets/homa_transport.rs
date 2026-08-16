//! homa-rpc 传输层目标：homa 包解析 + 收发状态机全链路。
//!
//! 入口面：
//! - `Packet::decode`（22 字节头 + 负载的线格式解析）；
//! - `ReceiverCore`：DATA 重组 / GRANT 调度 / RESEND / BUSY / 防饿死；
//! - `SenderCore`：GRANT 推进 / RESEND 重发 / BUSY / 「确认前重发」窗口 / 停滞探针。
//!
//! 防 abort 守卫（诚实声明）：
//! - 接收缓冲按 `msg_len` 分配（`vec![0u8; total_len]`）。本目标把喂给 receiver
//!   的 DATA 包 `msg_len` 封顶在 1 MiB（[`MAX_FUZZ_MSG_LEN`]），且 `max_incoming`
//!   压到 16——单次迭代内存上界 ≈ 16 MiB，杜绝 OOM abort（`catch_unwind` 抓不到
//!   abort）。16 MiB 的全局 `MAX_MSG_LEN` 守卫由 receiver.rs 单元测试单独覆盖。
//! - 输入长度有界（引擎默认 8 KiB），迭代内一切与输入成正比的分配都有限。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use homa_rpc::transport::packet::{Packet, PacketType};
use homa_rpc::transport::receiver::ReceiverCore;
use homa_rpc::transport::sender::SenderCore;
use homa_rpc::transport::{Action, TransportConfig};

/// 本目标喂给 receiver 的 DATA 包 `msg_len` 上限（防 OOM，见模块注释）
const MAX_FUZZ_MSG_LEN: u32 = 1 << 20;

/// 紧凑参数：小超时让小窗口/重传/过期路径在几次 tick 内全部触发
fn cfg() -> TransportConfig {
    TransportConfig {
        packet_size: 1200,
        unscheduled_bytes: 10_240,
        grant_increment: 4096,
        resend_timeout: Duration::from_millis(1),
        grant_timeout: Duration::from_millis(1),
        poke_timeout: Duration::from_millis(1),
        retransmit_timeout: Duration::from_millis(1),
        linger: Duration::from_millis(16),
        max_incoming: 16,
        overcommit: 2,
        starve_threshold: Duration::from_millis(2),
        ..Default::default()
    }
}

/// 按包类型分发到收发状态机。DATA 走 receiver，GRANT/RESEND/BUSY 走 sender。
fn dispatch(
    send: &mut SenderCore,
    recv: &mut ReceiverCore,
    src: SocketAddr,
    pkt: &Packet,
    payload: &[u8],
    now: Instant,
    actions: &mut Vec<Action>,
) {
    match pkt.typ {
        PacketType::Data => {
            if pkt.msg_len <= MAX_FUZZ_MSG_LEN {
                recv.handle_data(src, pkt, payload, now, actions);
            }
            // msg_len 超 1 MiB：跳过——分配炸弹由 MAX_MSG_LEN 守卫 + 单测覆盖
        }
        PacketType::Grant => send.handle_grant(src, pkt, now, actions),
        PacketType::Resend => send.handle_resend(src, pkt, now, actions),
        PacketType::Busy => send.handle_busy(src, pkt, now),
    }
}

/// 语料：四种包类型的结构合法样本 + 多分片消息首包
pub fn corpus() -> Vec<Vec<u8>> {
    vec![
        Packet::new(PacketType::Data, 0, 1, 100, 0, 3).encode(b"abc"),
        Packet::new(PacketType::Grant, 2, 1, 0, 10_240, 4096).encode(&[]),
        Packet::new(PacketType::Resend, 1, 1, 0, 0, 1200).encode(&[]),
        Packet::new(PacketType::Busy, 0, 1, 0, 0, 0).encode(&[]),
        // 多分片消息的首包（覆盖授权推进/重组位图路径）
        Packet::new(PacketType::Data, 0, 42, 4800, 0, 1200).encode(&[0xabu8; 1200]),
        // 短消息（确认前重发窗口）
        Packet::new(PacketType::Data, 3, 7, 64, 0, 64).encode(&[0x55u8; 64]),
    ]
}

/// 把状态机产出的 Send 动作全部解包喂回对端（构建 send↔recv 交叉反馈环）。
fn echo_back(
    send: &mut SenderCore,
    recv: &mut ReceiverCore,
    now: Instant,
    actions: Vec<Action>,
    out: &mut Vec<Action>,
) {
    for a in actions {
        if let Action::Send { dest, bytes } = a {
            if let Ok((pkt, payload)) = Packet::decode(&bytes) {
                dispatch(send, recv, dest, &pkt, payload, now, out);
            }
        }
    }
}

pub fn fuzz(data: &[u8]) {
    let cfg = cfg();
    let mut recv = ReceiverCore::new(cfg.clone());
    let mut send = SenderCore::new(cfg);
    let now = Instant::now();
    let peer: SocketAddr = "10.0.0.1:5555".parse().unwrap();

    // 1) 纯解析入口：整个输入当一条数据报
    let mut actions = Vec::new();
    if let Ok((pkt, payload)) = Packet::decode(data) {
        dispatch(&mut send, &mut recv, peer, &pkt, payload, now, &mut actions);
    }
    echo_back(&mut send, &mut recv, now, actions, &mut Vec::new());

    // 2) 流式入口：输入切成可变长度数据报（≤32 条），覆盖跨包边界/短包/截断
    let mut off = 0;
    for _ in 0..32 {
        if off >= data.len() {
            break;
        }
        let step = ((data[off] as usize) % 64) + 1;
        let end = (off + step).min(data.len());
        let mut actions = Vec::new();
        if let Ok((pkt, payload)) = Packet::decode(&data[off..end]) {
            dispatch(&mut send, &mut recv, peer, &pkt, payload, now, &mut actions);
        }
        echo_back(&mut send, &mut recv, now, actions, &mut Vec::new());
        off = end;
    }

    // 3) 端到端反馈环：sender 发 → receiver 收 → GRANT/RESEND → sender，有界 4 轮
    let mut actions = send.start_retransmit(peer, 0x7777_7777, data.to_vec(), now);
    for _ in 0..4 {
        let mut next = Vec::new();
        echo_back(&mut send, &mut recv, now, actions, &mut next);
        let t = now + Duration::from_millis(1);
        send.tick(t, &mut next);
        recv.tick(t, &mut next);
        actions = next;
    }

    // 4) confirm 摘除「确认前重发」消息，tick 过 linger 触发回收路径
    send.confirm(peer, 0x7777_7777);
    let mut actions = Vec::new();
    send.tick(now + Duration::from_millis(32), &mut actions);
    recv.tick(now + Duration::from_millis(32), &mut actions);
}
