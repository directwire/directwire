//! track 缓存逻辑测试：滑动窗口淘汰、乱序插入、晚到丢弃、追赶快照。

use std::sync::Arc;

use bytes::Bytes;
use moq_live::cache::GroupCache;
use moq_live::track::Object;

fn obj(group: u64, id: u64) -> Arc<Object> {
    Arc::new(Object::new(group, id, 128, 0, Bytes::from_static(b"f")))
}

#[test]
fn keeps_only_latest_n_groups() {
    let mut cache = GroupCache::new(2);
    for g in 0..4 {
        assert!(cache.insert(obj(g, 0)));
    }
    assert_eq!(cache.group_count(), 2);
    // 最旧的 group 0/1 已被淘汰，窗口内只剩 2、3。
    assert_eq!(cache.latest_group_id(), Some(3));
    // 请求起点过旧 → 返回窗口内全部（group 2、3）。
    let snap = cache.snapshot_from_group(0);
    assert_eq!(snap.len(), 2);
    assert!(snap.iter().all(|o| o.group_id >= 2));
    // 请求起点在未来（还没播到）→ 回退到最新 group 切入。
    let snap = cache.snapshot_from_group(99);
    assert!(snap.iter().all(|o| o.group_id == 3));
}

#[test]
fn out_of_order_insert_within_group_stays_sorted() {
    let mut cache = GroupCache::new(3);
    cache.insert(obj(0, 2));
    cache.insert(obj(0, 0));
    cache.insert(obj(0, 1));
    let snap = cache.snapshot_from_latest_group();
    let ids: Vec<u64> = snap.iter().map(|o| o.object_id).collect();
    assert_eq!(ids, vec![0, 1, 2]);
}

#[test]
fn late_packet_older_than_window_is_dropped() {
    let mut cache = GroupCache::new(2);
    cache.insert(obj(5, 0));
    cache.insert(obj(6, 0));
    // group 4 已滑出窗口 → 拒绝并计数。
    assert!(!cache.insert(obj(4, 0)));
    assert_eq!(cache.dropped_late(), 1);
    assert_eq!(cache.object_count(), 2);
}

#[test]
fn snapshot_from_latest_group_returns_newest_only() {
    let mut cache = GroupCache::new(3);
    for g in 0..3 {
        for i in 0..3 {
            cache.insert(obj(g, i));
        }
    }
    let snap = cache.snapshot_from_latest_group();
    assert_eq!(snap.len(), 3);
    assert!(snap.iter().all(|o| o.group_id == 2));
}

#[test]
fn snapshot_from_group_returns_suffix() {
    let mut cache = GroupCache::new(4);
    for g in 0..4 {
        cache.insert(obj(g, 0));
    }
    let snap = cache.snapshot_from_group(1);
    let groups: Vec<u64> = snap.iter().map(|o| o.group_id).collect();
    assert_eq!(groups, vec![1, 2, 3]);
}

#[test]
fn empty_cache_snapshots_are_empty() {
    let cache = GroupCache::new(2);
    assert!(cache.snapshot_from_latest_group().is_empty());
    assert!(cache.snapshot_from_group(9).is_empty());
    assert_eq!(cache.latest_group_id(), None);
}
