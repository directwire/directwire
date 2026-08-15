//! 接收端核心：重组 + GRANT 调度器（SRPT + overcommit + 防饿死）。
//!
//! 职责：
//! - 按分片位图乱序重组消息，齐了即交付（Deliver）；
//! - 接收端驱动调度：按「剩余字节数最少」选出前 K 条消息发累计 GRANT（近似 SRPT，
//!   K=overcommit 对标 Homa 的过度承诺，避免单授权饿死长消息）；
//!   新到的更短消息进入前 K 即抢占长消息的授权节奏（授权是累计的，旧消息保留已得额度）；
//! - 防饿死：等待授权超过 starve_threshold 的消息强制进入授权集合；
//! - 授予窗口内缺包超时 → 发 RESEND 请求重发；
//! - 授权后无进展超时 → 重发 GRANT（GRANT 本身可能丢失）。

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use super::packet::{Packet, PacketType};
use super::priority::priority_for_len;
use super::{Action, TransportConfig};

/// 消息键：发送方地址 + 消息 ID
pub type MsgKey = (SocketAddr, u64);

/// 接收中的单条消息
#[derive(Debug)]
struct InMsg {
    total_len: usize,
    buf: Vec<u8>,
    /// 每个分片是否已收到（乱序重组位图）
    received: Vec<bool>,
    /// 已收字节总数（含乱序）
    received_bytes: usize,
    /// 已授权的累计偏移
    granted_to: usize,
    /// 上次有进展的时刻
    last_progress: Instant,
    /// 上次获得 GRANT 的时刻（防饿死用）
    last_grant: Instant,
    /// 连续无进展的 RESEND 次数；超阈值判定发送端已死，放弃该消息
    unanswered_resends: u32,
}

/// 接收端放弃一条消息前的最大连续无应答 RESEND 次数
const MAX_UNANSWERED_RESENDS: u32 = 40;

impl InMsg {
    fn remaining(&self) -> usize {
        self.total_len - self.received_bytes
    }
    fn complete(&self) -> bool {
        self.received_bytes == self.total_len
    }
    /// 第一个缺失分片的字节偏移；全齐返回 None
    fn first_missing_offset(&self, pkt_size: usize) -> Option<usize> {
        self.received.iter().position(|&r| !r).map(|i| i * pkt_size)
    }
}

/// 已交付消息键的缓存上限（用于去重迟到的重复 DATA）
const COMPLETED_CACHE: usize = 4096;

/// 接收端核心状态机
pub struct ReceiverCore {
    cfg: TransportConfig,
    /// 热路径哈希表。ahash 的 RandomState 每实例随机种子（抗哈希洪泛），
    /// 但哈希速度比默认 SipHash 快 ~3×——长消息每分片查一次，是锁内吞吐的主要杠杆。
    incoming: HashMap<MsgKey, InMsg, ahash::RandomState>,
    /// 当前授权集合（SRPT 前 K 名 + 防饿死强制名额）
    granting: Vec<MsgKey>,
    /// 近期已交付消息键（去重）。HashSet 提供 O(1) 成员检查——
    /// 长消息每分片都查 contains，线性 VecDeque 在缓存增长后成为接收端锁内最大热点。
    completed: HashSet<MsgKey, ahash::RandomState>,
    /// FIFO 逐出顺序（仅用于淘汰旧键，不参与成员检查）
    completed_order: VecDeque<MsgKey>,
    /// 防饿死候选最小堆：键 = 到期时刻（最近授权 + 阈值），堆顶最先到期。
    /// 用于 O(1) 即时检查——长消息窗口耗尽后不必等 5ms tick 才被救起；
    /// 未到期条目不会被弹出丢弃，重授权会以新到期时刻重新入堆
    starve_queue: BinaryHeap<Reverse<(Instant, MsgKey)>>,
}

impl ReceiverCore {
    pub fn new(cfg: TransportConfig) -> Self {
        Self {
            cfg,
            incoming: HashMap::with_hasher(ahash::RandomState::new()),
            granting: Vec::new(),
            completed: HashSet::with_hasher(ahash::RandomState::new()),
            completed_order: VecDeque::new(),
            starve_queue: BinaryHeap::new(),
        }
    }

    /// 处理一个 DATA 包：写入重组位图，齐了交付，随后跑一轮调度
    pub fn handle_data(
        &mut self,
        src: SocketAddr,
        pkt: &Packet,
        payload: &[u8],
        now: Instant,
        actions: &mut Vec<Action>,
    ) {
        let key = (src, pkt.msg_id);
        if self.completed.contains(&key) {
            return; // 已交付消息的迟到重复分片，直接丢弃
        }
        let total_len = pkt.msg_len as usize;
        let pkt_size = self.cfg.packet_size;

        // 并发消息数超限 → 回 BUSY，让发送端稍后试探
        if !self.incoming.contains_key(&key) && self.incoming.len() >= self.cfg.max_incoming {
            actions.push(Action::Send {
                dest: src,
                bytes: Packet::new(PacketType::Busy, 0, pkt.msg_id, 0, 0, 0).encode(&[]),
            });
            return;
        }

        let unscheduled = self.cfg.unscheduled_bytes.min(total_len);
        let is_new = !self.incoming.contains_key(&key);
        if is_new {
            // 到期时刻 = 最近授权 + 阈值：没到阈值前不会被弹出丢弃
            self.starve_queue
                .push(Reverse((now + self.cfg.starve_threshold, key)));
        }
        let msg = self.incoming.entry(key).or_insert_with(|| {
            let chunks = total_len.div_ceil(pkt_size).max(1);
            InMsg {
                total_len,
                buf: vec![0u8; total_len],
                received: vec![false; chunks],
                received_bytes: 0,
                granted_to: unscheduled,
                last_progress: now,
                last_grant: now,
                unanswered_resends: 0,
            }
        });

        // 空消息：首包即交付
        if total_len == 0 {
            self.deliver(key, src, Vec::new(), actions);
            self.schedule(now, actions);
            return;
        }

        let offset = pkt.offset as usize;
        let idx = offset / pkt_size;
        if idx < msg.received.len() && !msg.received[idx] && offset + payload.len() <= total_len {
            msg.buf[offset..offset + payload.len()].copy_from_slice(payload);
            msg.received[idx] = true;
            msg.received_bytes += payload.len();
            msg.last_progress = now;
            msg.unanswered_resends = 0; // 有进展，重置无应答计数
        }

        if msg.complete() {
            let data = std::mem::take(&mut msg.buf);
            self.deliver(key, src, data, actions);
            // 释放了授权名额，跑一轮调度让下一条消息补位
            self.schedule(now, actions);
            return;
        }

        // 调度频率节流：新消息才需要全表排序（可能抢占授权集合）；
        // 已在收的消息只按需推进自身窗口（issue_grant 带节流，窗口富余时静默），
        // 避免长消息洪泛下每收一个分片都 O(n log n) 全表排序（状态锁内最大浪费）。
        if is_new {
            self.schedule(now, actions);
        } else if self.granting.contains(&key) {
            self.issue_grant(key, now, actions, false);
        }
        // 即时防饿死：活动流量顺手救起等待超阈值的消息（无需等 tick）
        self.starve_check(now, actions);
    }

    /// 即时防饿死：检查堆顶的挨饿候选是否到期且仍未获授权，是则触发完整调度
    /// 让出授权。候选非挨饿（已完成/已被授权）则弹掉过期项继续看下一个。
    fn starve_check(&mut self, now: Instant, actions: &mut Vec<Action>) {
        while let Some(&Reverse((t, k))) = self.starve_queue.peek() {
            if t > now {
                return; // 无到期候选
            }
            self.starve_queue.pop();
            let starved = self.incoming.get(&k).is_some_and(|m| {
                !self.granting.contains(&k)
                    && m.granted_to < m.total_len
                    && now.duration_since(m.last_grant) >= self.cfg.starve_threshold
            });
            if starved {
                self.schedule(now, actions);
                return;
            }
        }
    }

    /// 周期滴答：缺包超时发 RESEND；授权无进展重发 GRANT；并推进调度
    pub fn tick(&mut self, now: Instant, actions: &mut Vec<Action>) {
        let pkt_size = self.cfg.packet_size;
        let resend_timeout = self.cfg.resend_timeout;
        let grant_timeout = self.cfg.grant_timeout;
        let keys: Vec<_> = self.incoming.keys().copied().collect();
        for key in keys {
            let Some(msg) = self.incoming.get(&key) else {
                continue;
            };
            if now.duration_since(msg.last_progress) < resend_timeout {
                continue;
            }
            let missing = msg.first_missing_offset(pkt_size);
            match missing {
                // 授予窗口内缺包 → RESEND，一次覆盖窗口内全部剩余范围，
                // 批量修复突发丢包（UDP 接收缓冲溢出时可能整片丢失）
                Some(off) if off < msg.granted_to => {
                    let span = (msg.granted_to - off).min(self.cfg.grant_increment);
                    actions.push(Action::Send {
                        dest: key.0,
                        bytes: Packet::new(
                            PacketType::Resend,
                            priority_for_len(msg.total_len),
                            key.1,
                            0,
                            off as u32,
                            span as u32,
                        )
                        .encode(&[]),
                    });
                    let m = self.incoming.get_mut(&key).unwrap();
                    m.last_progress = now;
                    m.unanswered_resends += 1;
                    // 发送端已死（linger 过期/崩溃）：放弃该消息，解除调度器阻塞。
                    // 不进 completed 缓存——若发送端其实还活着，其探针分片会重建消息。
                    if m.unanswered_resends > MAX_UNANSWERED_RESENDS {
                        self.incoming.remove(&key);
                        self.granting.retain(|k| *k != key);
                    }
                }
                // 无缺失但授权停滞（GRANT 可能丢了）→ 由 schedule 重发 GRANT
                _ => {
                    if now.duration_since(msg.last_progress) >= grant_timeout {
                        // 重置计时，避免每 tick 都重复
                        self.incoming.get_mut(&key).unwrap().last_progress = now;
                        if self.granting.contains(&key) {
                            self.issue_grant(key, now, actions, true);
                        }
                    }
                }
            }
        }
        self.schedule(now, actions);
    }

    /// SRPT 调度：授权集合 = 剩余字节最少的前 K 条（overcommit）+ 防饿死强制名额
    pub fn schedule(&mut self, now: Instant, actions: &mut Vec<Action>) {
        let k = self.cfg.overcommit.max(1);
        let starve = self.cfg.starve_threshold;
        // 候选 = 所有未完整且仍需授权的消息，按剩余字节升序
        let mut cands: Vec<(MsgKey, usize)> = self
            .incoming
            .iter()
            .filter(|(_, m)| !m.complete() && m.granted_to < m.total_len)
            .map(|(key, m)| (*key, m.remaining()))
            .collect();
        cands.sort_by_key(|(_, rem)| *rem);
        let mut selected: Vec<MsgKey> = cands.into_iter().take(k).map(|(key, _)| key).collect();
        // 防饿死：久未获得授权的长消息强制入列（Homa 里由 overcommit 间接缓解，这里显式兜底）
        for (key, m) in self.incoming.iter() {
            if !m.complete()
                && m.granted_to < m.total_len
                && now.duration_since(m.last_grant) >= starve
                && !selected.contains(key)
            {
                selected.push(*key);
            }
        }
        self.granting = selected.clone();
        for key in selected {
            self.issue_grant(key, now, actions, false);
        }
    }

    /// 为指定消息维护授予窗口（节流版）：仅当在途未收额度低于半个增量时才追加授权，
    /// 避免「每收一个分片发一个 GRANT」的自时钟碎包开销
    fn issue_grant(&mut self, key: MsgKey, now: Instant, actions: &mut Vec<Action>, force: bool) {
        let increment = self.cfg.grant_increment;
        let Some(msg) = self.incoming.get_mut(&key) else {
            return;
        };
        let outstanding = msg.granted_to.saturating_sub(msg.received_bytes);
        if !force && outstanding >= increment / 2 {
            return; // 窗口尚有富余，无需新授权
        }
        let target = (msg.received_bytes + increment)
            .min(msg.total_len)
            .max(msg.granted_to);
        if target == msg.granted_to && !force {
            return;
        }
        let added = target.saturating_sub(msg.granted_to);
        msg.granted_to = target;
        msg.last_grant = now;
        actions.push(Action::Send {
            dest: key.0,
            bytes: Packet::new(
                PacketType::Grant,
                priority_for_len(msg.total_len),
                key.1,
                0,
                target as u32,
                added as u32,
            )
            .encode(&[]),
        });
        // 刚获授权：以新的到期时刻重排防饿死候选（堆里旧条目过期后会被弹掉）
        self.starve_queue
            .push(Reverse((now + self.cfg.starve_threshold, key)));
    }

    /// 交付一条完整消息
    fn deliver(&mut self, key: MsgKey, src: SocketAddr, data: Vec<u8>, actions: &mut Vec<Action>) {
        self.incoming.remove(&key);
        self.granting.retain(|k| *k != key);
        self.completed.insert(key);
        self.completed_order.push_back(key);
        if self.completed_order.len() > COMPLETED_CACHE {
            if let Some(old) = self.completed_order.pop_front() {
                self.completed.remove(&old);
            }
        }
        actions.push(Action::Deliver {
            src,
            msg_id: key.1,
            data,
        });
    }

    /// 测试/观测用：当前在收消息数
    pub fn in_flight(&self) -> usize {
        self.incoming.len()
    }

    /// 调试快照
    pub fn debug_dump(&self) -> String {
        let mut s = String::new();
        for ((addr, id), m) in &self.incoming {
            s.push_str(&format!(
                "  [{addr}#{id}] len={} recv={}/{} granted_to={} granting={}\n",
                m.total_len,
                m.received_bytes,
                m.total_len,
                m.granted_to,
                self.granting.contains(&(*addr, *id))
            ));
        }
        s
    }
}
