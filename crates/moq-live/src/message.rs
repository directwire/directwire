//! 消息帧编解码（MoQ-lite 控制面 + 数据面）。
//!
//! 帧格式（所有多字节整数均为 QUIC varint）：
//! ```text
//! +----------+----------+====================+
//! | type     | length   | payload ...        |
//! | (varint) | (varint) | (length 字节)      |
//! +----------+----------+====================+
//! ```
//!
//! 通道模型（对齐 MoQ Transport 的核心范式）：
//! - 控制面：每条 QUIC 连接的首条双向流，承载 SETUP/ANNOUNCE/SUBSCRIBE 等控制消息；
//! - 数据面：stream-per-group——每个 group 一条独立单向流，首帧为 GROUP_HEADER
//!   （TrackRef + group_id），其后跟随该 group 的 OBJECT 帧序列；
//! - TrackRef：SUBSCRIBE 协商出 varint track alias，之后数据帧头用 alias 代替
//!   完整 track 字符串（alias 尚未协商时回退 Full 形式）。

use std::io;

use crate::track::{Object, Priority, TrackId};
use crate::varint;

/// 协议版本（自定义 MoQ-lite 版本号，非 IETF draft 编号）。
pub const PROTO_VERSION: u64 = 0x6d6f716c; // "moql"

/// 会话角色（SETUP 消息中协商）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Publisher = 1,
    Subscriber = 2,
    Both = 3,
}

impl Role {
    fn from_u64(v: u64) -> io::Result<Self> {
        match v {
            1 => Ok(Self::Publisher),
            2 => Ok(Self::Subscriber),
            3 => Ok(Self::Both),
            _ => Err(invalid(format!("未知角色: {v}"))),
        }
    }
}

/// 订阅起始位置（追赶语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// 从最新 group 的开头开始（直播追赶：跳过陈旧 group，保证低延迟）。
    LatestGroup = 0,
    /// 只收订阅之后的新 object（不追赶）。
    NextObject = 1,
}

impl StartMode {
    fn from_u64(v: u64) -> io::Result<Self> {
        match v {
            0 => Ok(Self::LatestGroup),
            1 => Ok(Self::NextObject),
            _ => Err(invalid(format!("未知起始模式: {v}"))),
        }
    }
}

/// SUBSCRIBE_ERROR 错误码：命名空间未发布。
pub const ERR_NAMESPACE_NOT_FOUND: u64 = 1;

/// 数据帧头中的 track 引用：alias（压缩形态）或完整标识（协商前回退）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackRef {
    /// SUBSCRIBE 协商出的 varint alias。
    Alias(u64),
    /// 完整 namespace + track_name。
    Full(TrackId),
}

const REF_ALIAS: u64 = 0;
const REF_FULL: u64 = 1;

/// 全部消息类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// 会话建立：版本 + 角色协商（控制流，双向均发送）。
    Setup { version: u64, role: Role },
    /// 发布端声明命名空间。
    Announce { namespace: String },
    /// 命名空间声明确认。
    AnnounceOk { namespace: String },
    /// 订阅一条轨道；track_alias 由订阅方选定，后续数据帧头引用之。
    Subscribe {
        subscribe_id: u64,
        track_alias: u64,
        track: TrackId,
        start: StartMode,
        priority: Priority,
    },
    /// 订阅确认。
    SubscribeOk { subscribe_id: u64 },
    /// 订阅失败。
    SubscribeError {
        subscribe_id: u64,
        code: u64,
        reason: String,
    },
    /// 取消订阅。
    Unsubscribe { subscribe_id: u64 },
    /// 优雅关闭通告：对端即将关闭连接，停止发送新请求。
    Goaway { reason: String },
    /// group 数据流首帧（每个 group 一条独立单向流）。
    GroupHeader { track_ref: TrackRef, group_id: u64 },
    /// 数据 object（位于 GROUP_HEADER 之后的同一单向流上）。
    Object { object: Object },
}

// 消息类型码（MoQ-lite 私有编号空间）。
const T_SETUP: u64 = 0x01;
const T_ANNOUNCE: u64 = 0x02;
const T_ANNOUNCE_OK: u64 = 0x03;
const T_SUBSCRIBE: u64 = 0x04;
const T_SUBSCRIBE_OK: u64 = 0x05;
const T_SUBSCRIBE_ERROR: u64 = 0x06;
const T_UNSUBSCRIBE: u64 = 0x07;
const T_GOAWAY: u64 = 0x08;
const T_GROUP_HEADER: u64 = 0x10;
const T_OBJECT: u64 = 0x11;

impl Message {
    /// 编码为完整帧（type + length + payload）。
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        let type_code = match self {
            Message::Setup { version, role } => {
                varint::encode(*version, &mut payload);
                varint::encode(*role as u64, &mut payload);
                T_SETUP
            }
            Message::Announce { namespace } | Message::AnnounceOk { namespace } => {
                encode_str(namespace, &mut payload);
                if matches!(self, Message::Announce { .. }) {
                    T_ANNOUNCE
                } else {
                    T_ANNOUNCE_OK
                }
            }
            Message::Subscribe {
                subscribe_id,
                track_alias,
                track,
                start,
                priority,
            } => {
                varint::encode(*subscribe_id, &mut payload);
                varint::encode(*track_alias, &mut payload);
                encode_str(&track.namespace, &mut payload);
                encode_str(&track.name, &mut payload);
                varint::encode(*start as u64, &mut payload);
                varint::encode(*priority as u64, &mut payload);
                T_SUBSCRIBE
            }
            Message::SubscribeOk { subscribe_id } => {
                varint::encode(*subscribe_id, &mut payload);
                T_SUBSCRIBE_OK
            }
            Message::SubscribeError {
                subscribe_id,
                code,
                reason,
            } => {
                varint::encode(*subscribe_id, &mut payload);
                varint::encode(*code, &mut payload);
                encode_str(reason, &mut payload);
                T_SUBSCRIBE_ERROR
            }
            Message::Unsubscribe { subscribe_id } => {
                varint::encode(*subscribe_id, &mut payload);
                T_UNSUBSCRIBE
            }
            Message::Goaway { reason } => {
                encode_str(reason, &mut payload);
                T_GOAWAY
            }
            Message::GroupHeader {
                track_ref,
                group_id,
            } => {
                match track_ref {
                    TrackRef::Alias(a) => {
                        varint::encode(REF_ALIAS, &mut payload);
                        varint::encode(*a, &mut payload);
                    }
                    TrackRef::Full(t) => {
                        varint::encode(REF_FULL, &mut payload);
                        encode_str(&t.namespace, &mut payload);
                        encode_str(&t.name, &mut payload);
                    }
                }
                varint::encode(*group_id, &mut payload);
                T_GROUP_HEADER
            }
            Message::Object { object } => {
                varint::encode(object.object_id, &mut payload);
                varint::encode(object.priority as u64, &mut payload);
                varint::encode(object.timestamp_ms, &mut payload);
                varint::encode(object.payload.len() as u64, &mut payload);
                payload.extend_from_slice(&object.payload);
                T_OBJECT
            }
        };
        let mut frame = Vec::with_capacity(8 + payload.len());
        varint::encode(type_code, &mut frame);
        varint::encode(payload.len() as u64, &mut frame);
        frame.extend_from_slice(&payload);
        frame
    }

    /// 从帧切片解码（入参为完整的一帧：type + length + payload）。
    pub fn decode(frame: &[u8]) -> io::Result<Self> {
        let (type_code, n1) = varint::decode(frame)?;
        let (len, n2) = varint::decode(&frame[n1..])?;
        let payload = &frame[n1 + n2..];
        if payload.len() != len as usize {
            return Err(invalid(format!(
                "帧长度不匹配: 声明 {len}, 实际 {}",
                payload.len()
            )));
        }
        let mut r = Reader { buf: payload, pos: 0 };
        let msg = match type_code {
            T_SETUP => Message::Setup {
                version: r.varint()?,
                role: Role::from_u64(r.varint()?)?,
            },
            T_ANNOUNCE => Message::Announce {
                namespace: r.string()?,
            },
            T_ANNOUNCE_OK => Message::AnnounceOk {
                namespace: r.string()?,
            },
            T_SUBSCRIBE => Message::Subscribe {
                subscribe_id: r.varint()?,
                track_alias: r.varint()?,
                track: TrackId::new(r.string()?, r.string()?),
                start: StartMode::from_u64(r.varint()?)?,
                priority: r.varint()? as Priority,
            },
            T_SUBSCRIBE_OK => Message::SubscribeOk {
                subscribe_id: r.varint()?,
            },
            T_SUBSCRIBE_ERROR => Message::SubscribeError {
                subscribe_id: r.varint()?,
                code: r.varint()?,
                reason: r.string()?,
            },
            T_UNSUBSCRIBE => Message::Unsubscribe {
                subscribe_id: r.varint()?,
            },
            T_GOAWAY => Message::Goaway { reason: r.string()? },
            T_GROUP_HEADER => {
                let track_ref = match r.varint()? {
                    REF_ALIAS => TrackRef::Alias(r.varint()?),
                    REF_FULL => TrackRef::Full(TrackId::new(r.string()?, r.string()?)),
                    t => return Err(invalid(format!("未知 TrackRef 标签: {t}"))),
                };
                Message::GroupHeader {
                    track_ref,
                    group_id: r.varint()?,
                }
            }
            T_OBJECT => {
                let object_id = r.varint()?;
                let priority = r.varint()? as Priority;
                let timestamp_ms = r.varint()?;
                let payload = r.bytes()?;
                // group_id 不在 OBJECT 帧内（由所属流的 GROUP_HEADER 携带），此处填 0 占位，
                // 接收方解复用时回填。
                Message::Object {
                    object: Object::new(0, object_id, priority, timestamp_ms, payload.into()),
                }
            }
            t => return Err(invalid(format!("未知消息类型: {t:#x}"))),
        };
        if r.pos != payload.len() {
            return Err(invalid("帧尾部存在多余字节"));
        }
        Ok(msg)
    }
}

/// 编码长度前缀字符串。
fn encode_str(s: &str, out: &mut Vec<u8>) {
    varint::encode(s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// 载荷游标读取器。
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn varint(&mut self) -> io::Result<u64> {
        let (v, n) = varint::decode(&self.buf[self.pos..])?;
        self.pos += n;
        Ok(v)
    }

    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.varint()? as usize;
        if self.buf.len() - self.pos < len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "载荷数据不足",
            ));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    fn string(&mut self) -> io::Result<String> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("非法 UTF-8: {e}")))
    }
}
