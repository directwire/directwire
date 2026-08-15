//! 扇出逻辑测试：Hub 的 publish/subscribe/replay/lag 行为。

use bytes::Bytes;
use moq_live::hub::Hub;
use moq_live::message::StartMode;
use moq_live::track::{Object, TrackId};

fn obj(group: u64, id: u64) -> Object {
    Object::new(group, id, 128, 0, Bytes::from_static(b"f"))
}

#[tokio::test]
async fn publish_fans_out_to_all_subscribers() {
    let hub = Hub::new(4);
    let track = TrackId::new("ns", "v");
    let mut sub1 = hub.subscribe(&track, StartMode::NextObject);
    let mut sub2 = hub.subscribe(&track, StartMode::NextObject);
    assert!(sub1.replay.is_empty());

    hub.publish(&track, obj(0, 0));
    hub.publish(&track, obj(0, 1));

    for rx in [&mut sub1.live, &mut sub2.live] {
        let a = rx.recv().await.expect("sub 应收到 object 0");
        let b = rx.recv().await.expect("sub 应收到 object 1");
        assert_eq!((a.group_id, a.object_id), (0, 0));
        assert_eq!((b.group_id, b.object_id), (0, 1));
    }
}

#[tokio::test]
async fn late_subscriber_replays_latest_group_then_live() {
    let hub = Hub::new(2);
    let track = TrackId::new("ns", "v");
    // 推两个 group：group 0（旧）+ group 1（新，3 个 object）。
    hub.publish(&track, obj(0, 0));
    for i in 0..3 {
        hub.publish(&track, obj(1, i));
    }

    let mut sub = hub.subscribe(&track, StartMode::LatestGroup);
    // 追赶：只回放最新 group 的 3 个 object，不含 group 0。
    assert_eq!(sub.replay.len(), 3);
    assert!(sub.replay.iter().all(|o| o.group_id == 1));

    // 之后的新 object 走实时通道。
    hub.publish(&track, obj(1, 3));
    let live = sub.live.recv().await.expect("应收到实时 object");
    assert_eq!(live.object_id, 3);
}

#[tokio::test]
async fn publish_without_subscribers_is_ok() {
    let hub = Hub::new(2);
    let track = TrackId::new("ns", "v");
    assert!(hub.publish(&track, obj(0, 0)));
    assert_eq!(hub.latest_group_id(&track), Some(0));
}

#[tokio::test]
async fn late_object_is_dropped_by_cache_and_not_fanned_out() {
    let hub = Hub::new(2);
    let track = TrackId::new("ns", "v");
    let mut sub = hub.subscribe(&track, StartMode::NextObject);
    hub.publish(&track, obj(10, 0));
    hub.publish(&track, obj(11, 0));
    assert_eq!(sub.live.recv().await.unwrap().group_id, 10);
    assert_eq!(sub.live.recv().await.unwrap().group_id, 11);
    // group 9 已滑出窗口 → 不缓存、不扇出。
    assert!(!hub.publish(&track, obj(9, 0)));
}

#[tokio::test]
async fn lagged_subscriber_gets_error_not_block() {
    // broadcast 容量 256：溢出后 recv 返回 Lagged 而非阻塞发布端。
    let hub = Hub::new(8);
    let track = TrackId::new("ns", "v");
    let mut sub = hub.subscribe(&track, StartMode::NextObject);
    for i in 0..300u64 {
        hub.publish(&track, obj(0, i));
    }
    use tokio::sync::broadcast::error::RecvError;
    match sub.live.recv().await {
        Err(RecvError::Lagged(n)) => assert!(n > 0),
        other => panic!("预期 Lagged，实际 {other:?}"),
    }
    // 溢出后仍可继续接收（缓冲区保留最新 256 个：44..=299）。
    let latest = sub.live.recv().await.expect("Lagged 后应能续收");
    assert_eq!(latest.object_id, 300 - 256);
}
