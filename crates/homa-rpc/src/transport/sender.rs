//! 发送端核心：无 IO 纯状态机。
//!
//! 职责：
//! - 消息切分为定长分片（chunk），首 RTT 的 unscheduled 窗口立即发出；
//! - 之后的字节必须等接收端 GRANT（累计授权）才能发；
//! - 响应 RESEND 重发丢失分片；
//! - 停滞时重发最后一个已发分片作为「探针」（at-least-once 的发送端正）；
//! - 发完后保留状态一小段 linger 期：尾部分片若丢失，接收端迟到的 RESEND 仍能触发重发，
//!   否则「发完即销毁」会造成对端永久等包（Homa 中由 DONE/ACK 机制解决，这里简化）；
//! - **「确认前重发」窗口**（修复短消息单包丢失的死区）：带 retransmit 标志的消息
//!   （RPC 请求）整条发出后，在保守 RTT 估计窗口内未收到确认（响应 = 隐式 ACK，
//!   由上层 confirm 摘除）则重发首分片。接收端对「从没见过」的消息无法发 RESEND，
//!   这是唯一能让它建立重组的途径。详见 tick 的 done 分支。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use super::packet::{Packet, PacketType};
use super::priority::priority_for_len;
use super::{Action, TransportConfig};

/// 发送中的单条消息状态
#[derive(Debug)]
struct OutMsg {
    data: Vec<u8>,
    /// 接收端累计授权到的偏移（不含）
    granted_to: usize,
    /// 下一个待发送偏移
    next_send: usize,
    /// 全部发出的时刻（进入 linger 期）；None = 还在发
    done_at: Option<Instant>,
    /// 上次有发送进展的时刻（用于停滞探测）
    last_progress: Instant,
    /// 是否参与「确认前重发」窗口。RPC 请求置位（响应=隐式 ACK，confirm 摘除）；
    /// 响应不置位——响应的重发由客户端重发请求触发服务端幂等回放，发送端自身
    /// 重发会造成双倍响应流量，违反「无丢包零额外重发」。
    retransmit: bool,
}

impl OutMsg {
    /// offset 所在分片的 [start, end)
    fn chunk_range(&self, offset: usize, packet_size: usize) -> (usize, usize) {
        let start = (offset / packet_size) * packet_size;
        (start, (start + packet_size).min(self.data.len()))
    }
}

/// 发送端核心状态机
pub struct SenderCore {
    cfg: TransportConfig,
    out: HashMap<(SocketAddr, u64), OutMsg>,
    /// 调试：确认前重发窗口触发的首分片重发次数（net_probe 用它验证「无丢包零重发」）
    retransmits: u64,
}

/// 构造一个 DATA 包（自由函数，规避借用冲突）
fn data_packet(data: &[u8], msg_id: u64, start: usize, end: usize) -> Vec<u8> {
    let payload = &data[start..end];
    Packet::new(
        PacketType::Data,
        priority_for_len(data.len()),
        msg_id,
        data.len() as u32,
        start as u32,
        payload.len() as u32,
    )
    .encode(payload)
}

impl SenderCore {
    pub fn new(cfg: TransportConfig) -> Self {
        Self {
            cfg,
            out: HashMap::new(),
            retransmits: 0,
        }
    }

    /// 启动一条新消息：立即发出 unscheduled 窗口内的所有分片（首 RTT 不等授权）
    pub fn start(
        &mut self,
        dest: SocketAddr,
        msg_id: u64,
        data: Vec<u8>,
        now: Instant,
    ) -> Vec<Action> {
        self.start_inner(dest, msg_id, data, now, false)
    }

    /// 启动一条「确认前重发」消息（RPC 请求路径）：发完后若未确认，tick 会按
    /// 保守 RTT 估计重发首分片，修复短消息单包丢失时接收端无法 RESEND 的死区
    pub fn start_retransmit(
        &mut self,
        dest: SocketAddr,
        msg_id: u64,
        data: Vec<u8>,
        now: Instant,
    ) -> Vec<Action> {
        self.start_inner(dest, msg_id, data, now, true)
    }

    fn start_inner(
        &mut self,
        dest: SocketAddr,
        msg_id: u64,
        data: Vec<u8>,
        now: Instant,
        retransmit: bool,
    ) -> Vec<Action> {
        let unscheduled = self.cfg.unscheduled_bytes.min(data.len());
        let msg = OutMsg {
            data,
            granted_to: unscheduled,
            next_send: 0,
            done_at: None,
            last_progress: now,
            retransmit,
        };
        let key = (dest, msg_id);
        self.out.insert(key, msg);
        let mut actions = Vec::new();
        self.pump(key, unscheduled, now, &mut actions);
        actions
    }

    /// 处理 GRANT：推进累计授权，补发新解锁的分片
    pub fn handle_grant(
        &mut self,
        src: SocketAddr,
        pkt: &Packet,
        now: Instant,
        actions: &mut Vec<Action>,
    ) {
        let key = (src, pkt.msg_id);
        let new_limit = (pkt.offset as usize).min(self.out.get(&key).map_or(0, |m| m.data.len()));
        let Some(msg) = self.out.get(&key) else {
            return; // 消息已回收（linger 过期），忽略迟到的 GRANT
        };
        if new_limit <= msg.granted_to {
            return; // 重复/过期的累计授权
        }
        self.pump(key, new_limit, now, actions);
    }

    /// 处理 RESEND：重发 [offset, offset+length) 覆盖的分片。
    /// 注意：对端的授权视角可能超前于本地 next_send（末尾 GRANT 丢失时），
    /// RESEND 范围仍在授权窗口内，重发是合法的——但必须把这部分补进记账，
    /// 否则对端收全交付后不再授权，本地 next_send 永远追不上，造成停滞。
    pub fn handle_resend(
        &mut self,
        src: SocketAddr,
        pkt: &Packet,
        now: Instant,
        actions: &mut Vec<Action>,
    ) {
        let key = (src, pkt.msg_id);
        let pkt_size = self.cfg.packet_size;
        let Some(msg) = self.out.get(&key) else {
            return;
        };
        let start = (pkt.offset as usize).min(msg.data.len());
        let end = (start + pkt.length as usize).min(msg.data.len());
        let mut off = start;
        while off < end {
            let (s, e) = msg.chunk_range(off, pkt_size);
            actions.push(Action::Send {
                dest: src,
                bytes: data_packet(&msg.data, pkt.msg_id, s, e),
            });
            off = e.max(s + 1);
        }
        let msg = self.out.get_mut(&key).unwrap();
        // RESEND 范围即授权范围：补记 granted_to 与 next_send
        msg.granted_to = msg.granted_to.max(end);
        if msg.next_send < end {
            msg.next_send = end;
            if msg.next_send >= msg.data.len() && msg.done_at.is_none() {
                msg.done_at = Some(now);
            }
        }
        msg.last_progress = now;
    }

    /// 处理 BUSY：接收端过载，重置停滞计时，稍后由 tick 探针重新发起
    pub fn handle_busy(&mut self, src: SocketAddr, pkt: &Packet, now: Instant) {
        if let Some(m) = self.out.get_mut(&(src, pkt.msg_id)) {
            m.last_progress = now;
        }
    }

    /// 周期滴答：
    /// - 已完成但未确认的消息（短消息重发窗口）→ 超窗重发**首分片**；
    /// - 进行中的停滞消息 → 重发最后一个已发分片作探针，触发对端 RESEND/GRANT；
    /// - 回收 linger 期已过的已完成消息
    pub fn tick(&mut self, now: Instant, actions: &mut Vec<Action>) {
        let poke_timeout = self.cfg.poke_timeout;
        let retransmit_timeout = self.cfg.retransmit_timeout;
        let linger = self.cfg.linger;
        let pkt_size = self.cfg.packet_size;
        // 回收 linger 期结束的完成消息
        self.out
            .retain(|_, m| m.done_at.is_none_or(|t| now.duration_since(t) < linger));
        let keys: Vec<_> = self.out.keys().copied().collect();
        for key in keys {
            let Some(msg) = self.out.get(&key) else {
                continue;
            };
            if msg.done_at.is_some() {
                // 「确认前重发」窗口：整条消息已发出但未确认（响应 = 隐式 ACK，
                // 见 rpc/mod.rs 的 confirm 调用）。接收端对从未见过的消息无法发
                // RESEND，唯一恢复途径是发送端重发首分片让它建立重组、驱动后续
                // RESEND/GRANT。窗口用保守 RTT 估计（无 RTT 样本时 = 配置值，
                // 默认 500ms）：无丢包时响应先到、confirm 摘除消息，本分支从不触发
                // ——即「无丢包零额外重发」。
                if msg.retransmit && now.duration_since(msg.last_progress) >= retransmit_timeout {
                    let (s, e) = (0usize, pkt_size.min(msg.data.len()));
                    actions.push(Action::Send {
                        dest: key.0,
                        bytes: data_packet(&msg.data, key.1, s, e),
                    });
                    self.retransmits += 1;
                    self.out.get_mut(&key).unwrap().last_progress = now;
                }
                continue;
            }
            if now.duration_since(msg.last_progress) < poke_timeout {
                continue;
            }
            // 进行中的消息：接收端已知其存在（首分片已到），重发最后一个已发分片
            // 触发 RESEND/GRANT 即可，无需回到首分片
            let last_off = if msg.next_send == 0 {
                0
            } else {
                ((msg.next_send - 1) / pkt_size) * pkt_size
            };
            let (s, e) = msg.chunk_range(last_off, pkt_size);
            actions.push(Action::Send {
                dest: key.0,
                bytes: data_packet(&msg.data, key.1, s, e),
            });
            self.out.get_mut(&key).unwrap().last_progress = now;
        }
    }

    /// 消息是否已完全发出（linger 期内的消息视为 done，但仍可响应 RESEND）
    pub fn is_done(&self, dest: SocketAddr, msg_id: u64) -> bool {
        self.out
            .get(&(dest, msg_id))
            .is_none_or(|m| m.done_at.is_some())
    }

    /// 立即回收（超时放弃等场景）；正常完成的消息靠 linger 自动回收
    pub fn finish(&mut self, dest: SocketAddr, msg_id: u64) {
        self.out.remove(&(dest, msg_id));
    }

    /// 确认消息已被对端完整接收（收到响应 = 隐式 ACK，RPC 层调用）：
    /// 已发完则立即回收，停掉「确认前重发」窗口；未发完（长消息仍在授权流程）
    /// 仅关闭重传标志、不破坏进行中的发送，完成后由 linger 自动回收。
    /// 对端收全即不会再发 RESEND，故确认后无需保留 linger。
    pub fn confirm(&mut self, dest: SocketAddr, msg_id: u64) {
        let Some(m) = self.out.get_mut(&(dest, msg_id)) else {
            return;
        };
        if m.done_at.is_some() {
            self.out.remove(&(dest, msg_id));
        } else {
            m.retransmit = false;
        }
    }

    /// 调试：确认前重发窗口触发次数
    pub fn retransmit_count(&self) -> u64 {
        self.retransmits
    }

    /// 调试快照
    pub fn debug_dump(&self) -> String {
        let mut s = String::new();
        for ((addr, id), m) in &self.out {
            s.push_str(&format!(
                "  [{addr}#{id}] len={} sent={}/{} granted_to={} done={:?}\n",
                m.data.len(),
                m.next_send,
                m.data.len(),
                m.granted_to,
                m.done_at.is_some()
            ));
        }
        s
    }

    /// 将 [next_send, limit) 区间内的分片发出
    fn pump(
        &mut self,
        key: (SocketAddr, u64),
        limit: usize,
        now: Instant,
        actions: &mut Vec<Action>,
    ) {
        let pkt_size = self.cfg.packet_size;
        let Some(msg) = self.out.get_mut(&key) else {
            return;
        };
        if msg.done_at.is_some() {
            return;
        }
        let limit = limit.min(msg.data.len());
        while msg.next_send < limit {
            let (s, e) = (
                msg.next_send,
                (msg.next_send + pkt_size).min(msg.data.len()),
            );
            actions.push(Action::Send {
                dest: key.0,
                bytes: data_packet(&msg.data, key.1, s, e),
            });
            msg.next_send = e;
        }
        msg.granted_to = msg.granted_to.max(limit);
        msg.last_progress = now;
        if msg.next_send >= msg.data.len() {
            msg.done_at = Some(now); // 进入 linger 期，继续响应迟到 RESEND
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dest() -> SocketAddr {
        "127.0.0.1:9999".parse().unwrap()
    }

    fn cfg() -> TransportConfig {
        TransportConfig {
            retransmit_timeout: Duration::from_millis(500),
            ..Default::default()
        }
    }

    fn send_bytes(a: &Action) -> &Vec<u8> {
        match a {
            Action::Send { bytes, .. } => bytes,
            _ => panic!("expected Action::Send, got {a:?}"),
        }
    }

    /// 验收线①的单元证明：「无丢包时零额外重发」。
    /// 模拟正常流程——请求发出 → 响应到达（隐式 ACK）→ 上层 confirm → 消息回收；
    /// 之后推进远超重发窗口的时间，不得产生任何重发。
    #[test]
    fn 无丢包_confirm后_重发窗口零触发() {
        let mut s = SenderCore::new(cfg());
        let now = Instant::now();
        let data = vec![0xabu8; 100]; // 单包短消息（< unscheduled）
        let actions = s.start_retransmit(dest(), 1, data, now);
        assert_eq!(actions.len(), 1, "单包短消息只应发一个分片");
        // 响应到达 = 隐式 ACK，RPC 层调用 confirm
        s.confirm(dest(), 1);
        assert!(s.out.is_empty(), "confirm 应摘除已完成消息");
        let mut actions = Vec::new();
        s.tick(now + Duration::from_secs(10), &mut actions);
        assert!(actions.is_empty(), "无丢包时不得重发: {actions:?}");
        assert_eq!(s.retransmit_count(), 0);
    }

    /// 丢包恢复：请求首包丢失（对端从未见过此消息，无法 RESEND），
    /// 超过保守 RTT 窗口后应重发首分片；重发后 last_progress 刷新，窗口内不重复。
    #[test]
    fn 丢包_超窗重发首分片_窗口内不重复() {
        let mut s = SenderCore::new(cfg());
        let now = Instant::now();
        let data = vec![0xabu8; 100];
        let _ = s.start_retransmit(dest(), 1, data, now);
        // 窗口内：不触发
        let mut actions = Vec::new();
        s.tick(now + Duration::from_millis(499), &mut actions);
        assert!(actions.is_empty(), "窗口内不得提前重发");
        // 超窗：触发首分片重发
        let mut actions = Vec::new();
        s.tick(now + Duration::from_millis(501), &mut actions);
        assert_eq!(actions.len(), 1, "超窗应重发一个分片");
        let (pkt, _) = Packet::decode(send_bytes(&actions[0])).unwrap();
        assert_eq!(pkt.offset, 0, "重发应落在首分片（对端建立重组靠它）");
        assert_eq!(s.retransmit_count(), 1);
        // 重发后计时刷新：窗口内不再重复
        let mut actions = Vec::new();
        s.tick(now + Duration::from_millis(550), &mut actions);
        assert!(actions.is_empty());
    }

    /// 响应路径（send_vec，非重传标志）done 后不得被重发——否则每次响应都双发，
    /// 违反「无丢包零额外重发」。
    #[test]
    fn 非重传消息_永不被重发() {
        let mut s = SenderCore::new(cfg());
        let now = Instant::now();
        let data = vec![0xabu8; 100];
        let _ = s.start(dest(), 1, data, now); // 普通发送（响应路径）
        let mut actions = Vec::new();
        s.tick(now + Duration::from_secs(10), &mut actions);
        assert!(actions.is_empty(), "非重传消息不得进入重发窗口");
        assert_eq!(s.retransmit_count(), 0);
    }

    /// 多分片短消息（仍 < unscheduled）：重发窗口应发首分片（offset 0），
    /// 让完全不知此消息的对端建立重组并驱动 RESEND/GRANT 补齐其余分片。
    #[test]
    fn 多分片短消息_重发首分片() {
        let mut s = SenderCore::new(cfg());
        let now = Instant::now();
        let data = vec![0xcdu8; 4 * 1200]; // 4 分片，仍 < 10KB unscheduled
        let msg_len = data.len();
        let actions = s.start_retransmit(dest(), 1, data, now);
        assert_eq!(actions.len(), 4, "初始应发满 4 个分片");
        let mut actions = Vec::new();
        s.tick(now + Duration::from_millis(501), &mut actions);
        assert_eq!(actions.len(), 1);
        let (pkt, _) = Packet::decode(send_bytes(&actions[0])).unwrap();
        assert_eq!(pkt.offset, 0, "重发必须落在首分片");
        assert_eq!(pkt.msg_len as usize, msg_len);
    }

    /// 永不确认 + 对端失联的极端情况：重传必须有界——linger 过后消息被回收。
    #[test]
    fn 永不确认_linger后回收() {
        let mut s = SenderCore::new(cfg());
        let now = Instant::now();
        let _ = s.start_retransmit(dest(), 1, vec![0xabu8; 100], now);
        let mut actions = Vec::new();
        s.tick(now + Duration::from_millis(501), &mut actions); // 超窗重发一次
        assert_eq!(s.retransmit_count(), 1);
        let mut actions = Vec::new();
        s.tick(now + Duration::from_secs(10), &mut actions); // linger(5s) 过后回收
        assert!(s.out.is_empty(), "linger 过后未确认消息应被回收");
    }
}
