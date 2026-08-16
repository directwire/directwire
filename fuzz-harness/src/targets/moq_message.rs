//! moq-live 目标：MoQ-lite 消息帧 + QUIC varint 解码入口。
//!
//! 入口面：
//! - `varint::decode`：在输入的每个偏移都试解一次（覆盖跨边界/截断的 varint）；
//! - `Message::decode`：完整帧解析（type + length + payload + 各消息体）；
//! - 解码成功 → `encode` 回编 → 再解码（解码产物不得让编码器崩溃）。
//!
//! 防 abort：`Reader::bytes/string` 都有剩余长度检查（分配以输入为界），
//! `varint::decode` 输出 ≤ 2^62-1，回编时 `varint::encode` 的 assert 永不触发
//! ——无 OOM 炸弹。输入长度上限（引擎默认 8 KiB）即全部防线。

use moq_live::message::Message;
use moq_live::varint;

pub fn corpus() -> Vec<Vec<u8>> {
    use moq_live::message::{PROTO_VERSION, Role, StartMode, TrackRef};
    use moq_live::track::{Object, PRIORITY_HIGHEST, TrackId};

    let mut v = vec![
        Message::Setup {
            version: PROTO_VERSION,
            role: Role::Both,
        }
        .encode(),
        Message::Announce {
            namespace: "live/cam".into(),
        }
        .encode(),
        Message::Subscribe {
            subscribe_id: 1,
            track_alias: 1,
            track: TrackId::new("live/cam", "video"),
            start: StartMode::LatestGroup,
            priority: PRIORITY_HIGHEST,
        }
        .encode(),
        Message::Goaway {
            reason: "bye".into(),
        }
        .encode(),
    ];
    // TrackRef 两种形态 + 数据面对象帧
    v.push(
        Message::GroupHeader {
            track_ref: TrackRef::Alias(7),
            group_id: 3,
        }
        .encode(),
    );
    v.push(
        Message::GroupHeader {
            track_ref: TrackRef::Full(TrackId::new("live/cam", "audio")),
            group_id: 4,
        }
        .encode(),
    );
    let obj = Object::new(0, 0, 5, 1000, b"payload".to_vec().into());
    v.push(Message::Object { object: obj }.encode());
    v
}

pub fn fuzz(data: &[u8]) {
    // 1) varint 在每个偏移解码（上限 4096 个偏移，控制迭代成本）
    let n = data.len().min(4096);
    for i in 0..n {
        let _ = varint::decode(&data[i..]);
    }

    // 2) 完整帧解码（含帧长度不匹配 / 尾部多余字节等拒绝路径）
    if let Ok(msg) = Message::decode(data) {
        // 3) 往返：解码产物 → 编码器 → 再解码
        let enc = msg.encode();
        let _ = Message::decode(&enc);
    }

    // 4) 每 64 字节截断一个前缀帧，覆盖截断帧路径
    for end in (1..n).step_by(64) {
        let _ = Message::decode(&data[..end]);
    }
}
