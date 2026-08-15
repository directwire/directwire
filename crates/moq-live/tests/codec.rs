//! 帧编解码往返测试：varint 边界、全消息类型 roundtrip、畸形帧拒绝。

use bytes::Bytes;
use moq_live::message::{Message, Role, StartMode, TrackRef, PROTO_VERSION};
use moq_live::track::{Object, TrackId};
use moq_live::varint;

// ---------- varint ----------

#[test]
fn varint_roundtrip_boundaries() {
    // RFC 9000 各编码长度段的边界值。
    let cases = [
        0,
        1,
        63,
        64,
        16383,
        16384,
        1_073_741_823,
        1_073_741_824,
        varint::VARINT_MAX,
    ];
    for v in cases {
        let mut buf = Vec::new();
        varint::encode(v, &mut buf);
        assert_eq!(buf.len(), varint::encoded_len(v), "长度不符: {v}");
        let (decoded, n) = varint::decode(&buf).expect("解码失败");
        assert_eq!((decoded, n), (v, buf.len()), "往返不一致: {v}");
    }
}

#[test]
fn varint_encoded_length_classes() {
    assert_eq!(varint::encoded_len(63), 1);
    assert_eq!(varint::encoded_len(64), 2);
    assert_eq!(varint::encoded_len(16383), 2);
    assert_eq!(varint::encoded_len(16384), 4);
    assert_eq!(varint::encoded_len(1_073_741_824), 8);
}

#[test]
fn varint_decode_rejects_truncated() {
    assert!(varint::decode(&[]).is_err());
    // 2 字节 varint 只给 1 字节。
    assert!(varint::decode(&[0x40]).is_err());
    // 8 字节 varint 只给 3 字节。
    assert!(varint::decode(&[0xC0, 0x00, 0x00]).is_err());
}

// ---------- 消息帧 ----------

fn roundtrip(msg: Message) {
    let frame = msg.encode();
    let decoded = Message::decode(&frame).expect("解码失败");
    assert_eq!(decoded, msg);
}

#[test]
fn setup_roundtrip() {
    for role in [Role::Publisher, Role::Subscriber, Role::Both] {
        roundtrip(Message::Setup {
            version: PROTO_VERSION,
            role,
        });
    }
}

#[test]
fn announce_roundtrip() {
    roundtrip(Message::Announce {
        namespace: "live/camera-01".into(),
    });
    roundtrip(Message::AnnounceOk {
        namespace: "live/camera-01".into(),
    });
}

#[test]
fn subscribe_roundtrip() {
    for start in [StartMode::LatestGroup, StartMode::NextObject] {
        roundtrip(Message::Subscribe {
            subscribe_id: 42,
            track_alias: 7,
            track: TrackId::new("live/camera-01", "video"),
            start,
            priority: 0,
        });
    }
}

#[test]
fn subscribe_ok_error_unsubscribe_roundtrip() {
    roundtrip(Message::SubscribeOk { subscribe_id: 7 });
    roundtrip(Message::SubscribeError {
        subscribe_id: 7,
        code: 1,
        reason: "命名空间未发布".into(),
    });
    roundtrip(Message::Unsubscribe { subscribe_id: 7 });
}

#[test]
fn goaway_roundtrip() {
    roundtrip(Message::Goaway {
        reason: "relay 优雅关闭".into(),
    });
}

#[test]
fn group_header_roundtrip_alias_and_full() {
    // alias 形态（SUBSCRIBE 协商后）。
    roundtrip(Message::GroupHeader {
        track_ref: TrackRef::Alias(9),
        group_id: 100,
    });
    // Full 形态（协商前回退）。
    roundtrip(Message::GroupHeader {
        track_ref: TrackRef::Full(TrackId::new("live/camera-01", "video")),
        group_id: 100,
    });
}

#[test]
fn alias_header_is_smaller_than_full() {
    let alias_frame = Message::GroupHeader {
        track_ref: TrackRef::Alias(9),
        group_id: 100,
    }
    .encode();
    let full_frame = Message::GroupHeader {
        track_ref: TrackRef::Full(TrackId::new("live/camera-01", "video")),
        group_id: 100,
    }
    .encode();
    assert!(
        alias_frame.len() < full_frame.len(),
        "alias 压缩应显著减小帧头: {} vs {}",
        alias_frame.len(),
        full_frame.len()
    );
}

#[test]
fn object_roundtrip() {
    // OBJECT 帧不再携带 track/group（由所属流的 GROUP_HEADER 携带）。
    let payload = Bytes::from(vec![0x5Au8; 16 * 1024]); // 模拟一帧视频
    roundtrip(Message::Object {
        object: Object::new(0, 17, 128, 1_700_000_000_000, payload),
    });
}

#[test]
fn decode_rejects_length_mismatch() {
    let frame = Message::Announce {
        namespace: "x".into(),
    }
    .encode();
    // 截掉一字节载荷 → 声明长度与实际不符。
    assert!(Message::decode(&frame[..frame.len() - 1]).is_err());
}

#[test]
fn decode_rejects_unknown_type() {
    let mut frame = Vec::new();
    varint::encode(0x7E, &mut frame); // 未分配类型码
    varint::encode(0, &mut frame);
    assert!(Message::decode(&frame).is_err());
}

#[test]
fn decode_rejects_trailing_garbage() {
    let frame = Message::SubscribeOk { subscribe_id: 1 }.encode();
    // 伪造更长的声明长度并填充垃圾字节。
    let payload_len = frame.len() - 1; // type(1B) + len(1B) 的短帧场景
    let mut forged = Vec::new();
    varint::encode(0x05, &mut forged); // T_SUBSCRIBE_OK
    varint::encode((payload_len + 3) as u64, &mut forged);
    forged.extend_from_slice(&frame[2..]);
    forged.extend_from_slice(&[0u8; 3]);
    assert!(Message::decode(&forged).is_err());
}
