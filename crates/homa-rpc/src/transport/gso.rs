//! UDP GSO（Generic Segmentation Offload）发送聚合。
//!
//! 长消息的高分片洪泛逐包 syscall 是发送吞吐瓶颈（loopback ~5µs/包，
//! 1MiB 消息 874 片 ≈ 5ms）。GSO 一次 syscall 提交 ≤64KB 大缓冲，
//! 内核按段大小切成多个数据报，对端收到正常小数据报（**透明**，接收侧零改动）。
//! 1MiB 消息 874 分片 → ~17 段，send_loop 吞吐提升 ~50×。
//!
//! 聚合规则（安全前提）：**仅同一条消息的连续满 DATA 包**可拼接进段。
//! 内核切分点 = 满包长度，段内每个数据报必须恰好是一个完整 Homa 包；
//! 尾包/非满包/重发包（offset 回退）不得入段，否则切分点会落进包中间
//! 破坏线格式。聚合在发送线程出队后做，不改队列的优先级顺序语义
//! （同优先级内 FIFO，跨消息绝不聚合）。
//!
//! 平台：Windows 用 WSASendMsg 的 `UDP_SEND_MSG_SIZE` control 消息
//! （逐次指定段长，spike 已在 loopback 实测生效）；Linux 的 `UDP_SEGMENT`
//! 是 setsockopt 全局选项，此路径待补，当前非 Windows 逐包回退。

use std::io::IoSlice;
use std::net::SocketAddr;

use socket2::{MsgHdr, SockAddr, SockRef};

use super::Inner;
use super::packet::{HEADER_LEN, PacketType};

/// GSO 段缓冲上限：Windows UDP 数据报上限 ~64KB。
/// 满包 1222B × 53 = 64766 ≤ 65536（实际按 mss 动态算）
const MAX_GSO_BYTES: usize = 64 << 10;

/// Windows WSACMSGHDR control 常量（ws2ipdef.h）：`UDP_SEND_MSG_SIZE = 2`
#[cfg(windows)]
const IPPROTO_UDP: i32 = 17;
#[cfg(windows)]
const UDP_SEND_MSG_SIZE: i32 = 2;

/// GSO 聚合器：把同消息连续满 DATA 包拼成段。跨 batch 持有以最大化聚合窗口。
pub struct GsoAggregator {
    /// 满包字节数 = HEADER_LEN + packet_size（内核切分粒度）
    mss: usize,
    /// 相邻满包的 offset 步进 = packet_size
    stride: usize,
    /// 当前段的目标地址
    dest: Option<SocketAddr>,
    /// 当前段的 msg_id
    msg_id: u64,
    /// 期望的下一包 offset（连续校验）
    next_offset: u64,
    /// 段缓冲（编码后的完整包拼接）
    buf: Vec<u8>,
    /// 段内包数
    count: usize,
}

impl GsoAggregator {
    pub fn new(packet_size: usize) -> Self {
        Self {
            mss: HEADER_LEN + packet_size,
            stride: packet_size,
            dest: None,
            msg_id: 0,
            next_offset: 0,
            buf: Vec::with_capacity(MAX_GSO_BYTES),
            count: 0,
        }
    }

    /// 尝试把包并入 GSO 段。成功返回 true（追加到当前段或开新段）。
    /// 返回 false = 该包不能被聚合（非满包 / 非 DATA / 异消息 / 不连续），
    /// 调用方应先 `finish` 冲掉当前段，再把该包单独发出。
    pub fn try_push(&mut self, dest: SocketAddr, bytes: &[u8]) -> bool {
        if self.can_append(dest, bytes) {
            self.append(bytes);
            return true;
        }
        if self.count == 0 && self.start(dest, bytes) {
            return true;
        }
        false
    }

    /// 冲掉当前段：返回 (dest, 拼接段, 包数)。无段返回 None。
    pub fn finish(&mut self) -> Option<(SocketAddr, Vec<u8>, usize)> {
        if self.count == 0 {
            return None;
        }
        let out = (
            self.dest.unwrap(),
            std::mem::take(&mut self.buf),
            self.count,
        );
        self.dest = None;
        self.count = 0;
        Some(out)
    }

    fn can_append(&self, dest: SocketAddr, bytes: &[u8]) -> bool {
        if self.count == 0 || bytes.len() != self.mss || bytes[0] != PacketType::Data as u8 {
            return false;
        }
        let Some(d) = self.dest else { return false };
        d == dest
            && self.msg_id == u64::from_le_bytes(bytes[2..10].try_into().unwrap())
            && self.next_offset == u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as u64
            && self.buf.len() + self.mss <= MAX_GSO_BYTES
    }

    fn append(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        self.count += 1;
        self.next_offset += self.stride as u64;
    }

    fn start(&mut self, dest: SocketAddr, bytes: &[u8]) -> bool {
        if bytes.len() != self.mss || bytes[0] != PacketType::Data as u8 {
            return false;
        }
        self.dest = Some(dest);
        self.msg_id = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        self.next_offset =
            u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as u64 + self.stride as u64;
        self.buf.clear();
        self.buf.extend_from_slice(bytes);
        self.count = 1;
        true
    }
}

/// 8 字节对齐的 control 缓冲（WSACMSGHDR 要求指针 8 字节对齐）
#[cfg(windows)]
#[repr(align(8))]
struct Aligned([u8; 24]);

/// 发出一个 GSO 段。单包段退化为 send_to；多包段用 WSASendMsg + UDP_SEND_MSG_SIZE
/// 一次 syscall 提交，内核切分为 mss 大小数据报（每报恰一个 Homa 包）。
#[cfg(windows)]
pub(super) fn send_segment(inner: &Inner, dest: SocketAddr, seg: &[u8], count: usize) {
    if count <= 1 {
        let _ = inner.socket.send_to(seg, dest);
        return;
    }
    let mss = (HEADER_LEN + inner.packet_size) as u32;
    // 构造 UDP_SEND_MSG_SIZE control：cmsg_len=20（对齐头 16 + 数据 4），
    // level=IPPROTO_UDP(17)，type=UDP_SEND_MSG_SIZE(2)，data=mss
    let mut ctrl = Aligned([0u8; 24]);
    ctrl.0[0..8].copy_from_slice(&20usize.to_le_bytes());
    ctrl.0[8..12].copy_from_slice(&IPPROTO_UDP.to_le_bytes());
    ctrl.0[12..16].copy_from_slice(&UDP_SEND_MSG_SIZE.to_le_bytes());
    ctrl.0[16..20].copy_from_slice(&mss.to_le_bytes());
    let sock = SockRef::from(&inner.socket);
    let iov = [IoSlice::new(seg)];
    let saddr = SockAddr::from(dest);
    let msg = MsgHdr::new()
        .with_addr(&saddr)
        .with_buffers(&iov)
        .with_control(&ctrl.0);
    let _ = sock.sendmsg(&msg, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet::Packet;

    const PS: usize = 1200;

    fn full_pkt(msg_id: u64, offset: usize) -> Vec<u8> {
        Packet::new(
            PacketType::Data,
            0,
            msg_id,
            1 << 20,
            offset as u32,
            PS as u32,
        )
        .encode(&vec![0x5a; PS])
    }

    #[test]
    fn 连续满包聚合为段() {
        let mut agg = GsoAggregator::new(PS);
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // 3 个连续满包 offset 0/1200/2400
        for i in 0..3 {
            assert!(agg.try_push(dest, &full_pkt(7, i * PS)));
        }
        let (d, seg, n) = agg.finish().unwrap();
        assert_eq!(d, dest);
        assert_eq!(n, 3);
        assert_eq!(seg.len(), 3 * (HEADER_LEN + PS));
    }

    #[test]
    fn 异消息不聚合() {
        let mut agg = GsoAggregator::new(PS);
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(agg.try_push(dest, &full_pkt(1, 0)));
        // 同 offset 但不同 msg_id → 不聚合
        assert!(!agg.try_push(dest, &full_pkt(2, PS)));
        // 当前段只有 1 包,finish 返回单包段
        let (_, _, n) = agg.finish().unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn offset不连续不聚合() {
        let mut agg = GsoAggregator::new(PS);
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(agg.try_push(dest, &full_pkt(1, 0)));
        // 跳过一个 offset(重发旧包等) → 不聚合
        assert!(!agg.try_push(dest, &full_pkt(1, 0)));
        // 但后续连续包仍可开新段
        assert!(agg.try_push(dest, &full_pkt(1, PS)));
    }

    #[test]
    fn 非满包不聚合() {
        let mut agg = GsoAggregator::new(PS);
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let tail = Packet::new(PacketType::Data, 0, 1, 5000, 2400, 100).encode(&[0x5a; 100]);
        assert!(!agg.try_push(dest, &tail));
        assert!(agg.finish().is_none());
    }
}
