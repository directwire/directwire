//! 优先级分级丢弃队列测试：容量、驱逐策略、group 头保护。

use std::sync::Arc;

use bytes::Bytes;
use moq_live::dropq::{PriorityDropQueue, PushOutcome};
use moq_live::track::Object;

fn obj(group: u64, id: u64, priority: u8) -> Arc<Object> {
    Arc::new(Object::new(
        group,
        id,
        priority,
        0,
        Bytes::from_static(b"f"),
    ))
}

#[test]
fn queues_until_capacity() {
    let mut q = PriorityDropQueue::new(3);
    for i in 0..3 {
        assert!(matches!(q.push(obj(0, i, 128)), PushOutcome::Queued));
    }
    assert_eq!(q.len(), 3);
    assert_eq!(q.dropped(), 0);
}

#[test]
fn drops_incoming_when_it_is_lowest_priority() {
    let mut q = PriorityDropQueue::new(2);
    q.push(obj(0, 0, 0)); // group 头
    q.push(obj(0, 1, 64));
    // 新 object 优先级 128，比队中 64 更低 → 丢弃自身。
    assert!(matches!(q.push(obj(0, 2, 128)), PushOutcome::DroppedSelf));
    assert_eq!(q.dropped(), 1);
    assert_eq!(q.len(), 2);
}

#[test]
fn evicts_lower_priority_non_head_for_higher_priority() {
    let mut q = PriorityDropQueue::new(2);
    q.push(obj(0, 0, 0)); // group 头（受保护）
    q.push(obj(0, 1, 200)); // 低优先级 P 帧
    // 新 object 优先级 64 > 200 → 驱逐 200。
    match q.push(obj(0, 2, 64)) {
        PushOutcome::Evicted(old) => assert_eq!(old.object_id, 1),
        other => panic!("预期 Evicted，实际 {other:?}"),
    }
    // 幸存：group 头 + 高优先级 object。
    assert_eq!(q.pop().unwrap().object_id, 0);
    assert_eq!(q.pop().unwrap().object_id, 2);
}

#[test]
fn group_head_never_evicted_by_non_head() {
    let mut q = PriorityDropQueue::new(2);
    q.push(obj(0, 0, 0)); // group 头
    q.push(obj(1, 0, 0)); // 又一个 group 头
    // 队满且全是 group 头：非头 object 到达只能自弃，不能驱逐头。
    assert!(matches!(q.push(obj(1, 1, 255)), PushOutcome::DroppedSelf));
    assert_eq!(q.len(), 2);
}

#[test]
fn group_head_can_evict_non_head() {
    let mut q = PriorityDropQueue::new(2);
    q.push(obj(0, 0, 0));
    q.push(obj(0, 1, 128));
    // 新 group 头到达，队满 → 驱逐 P 帧保住关键帧。
    match q.push(obj(1, 0, 0)) {
        PushOutcome::Evicted(old) => assert_eq!(old.object_id, 1),
        other => panic!("预期 Evicted，实际 {other:?}"),
    }
    assert_eq!(q.pop().unwrap().object_id, 0);
    assert_eq!(q.pop().unwrap().group_id, 1);
}

#[test]
fn fifo_order_among_survivors() {
    let mut q = PriorityDropQueue::new(4);
    for i in 0..4 {
        q.push(obj(0, i, 128));
    }
    for i in 0..4 {
        assert_eq!(q.pop().unwrap().object_id, i);
    }
    assert!(q.pop().is_none());
}
