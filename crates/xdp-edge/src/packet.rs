//! 报文抽象与 XDP 动作语义。
//!
//! 用户态模拟器不解析真实字节流，而是直接操作五元组结构，
//! 与 bpf/xdp_edge.c 中解析出的字段一一对应。

/// TCP 标志位（与内核 tcp_hdr 一致）
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// IP 协议号
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// 五元组，连接跟踪与 Maglev 哈希的输入
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// 模拟报文
#[derive(Debug, Clone, Copy)]
pub struct Packet {
    pub tuple: FiveTuple,
    pub tcp_flags: u8,
    pub len: u32,
}

impl Packet {
    pub fn new(tuple: FiveTuple, tcp_flags: u8, len: u32) -> Self {
        Self { tuple, tcp_flags, len }
    }

    pub fn is_syn(&self) -> bool {
        self.tcp_flags & TCP_SYN != 0 && self.tcp_flags & TCP_ACK == 0
    }

    pub fn is_ack(&self) -> bool {
        self.tcp_flags & TCP_ACK != 0
    }
}

/// XDP 程序对单个报文的判决动作。
/// 与内核侧 XDP_DROP / XDP_PASS / XDP_TX 对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// XDP_DROP：快速路径丢包（限速 / SYN flood 触发）
    Drop,
    /// XDP_PASS：上送内核协议栈（本项目的边缘网关场景下极少发生）
    Pass,
    /// XDP_TX：IPIP 封装后转发到指定后端（值为后端内网 IP）
    Forward(u32),
}

impl Action {
    pub fn is_drop(&self) -> bool {
        matches!(self, Action::Drop)
    }
}
