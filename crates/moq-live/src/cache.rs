//! 中继缓存：每条 track 保留最近 N 个 group，支撑订阅者的追赶（catch-up）语义。
//!
//! 直播场景的核心取舍：迟到的新订阅者不应从头播放陈旧内容，
//! 而是从「最新 group 的开头」（即最新一个 GOP 的关键帧）切入，
//! 牺牲少量历史换取最低端到端延迟——这正是中继按 group 缓存的意义。

use std::collections::VecDeque;
use std::sync::Arc;

use crate::track::Object;

/// 按 group 组织的滑动窗口缓存。
///
/// 不变式：groups 内 group_id 严格递增；object 乱序到达时按 (group_id, object_id) 排序插入。
#[derive(Debug)]
pub struct GroupCache {
    /// 最多保留的 group 数。
    capacity: usize,
    /// 滑动窗口：(group_id, 该 group 已收到的 object 列表)。
    groups: VecDeque<(u64, Vec<Arc<Object>>)>,
    /// 因过旧被丢弃的 object 计数（晚到的乱序包）。
    dropped_late: u64,
}

impl GroupCache {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "缓存容量至少为 1 个 group");
        Self {
            capacity,
            groups: VecDeque::with_capacity(capacity + 1),
            dropped_late: 0,
        }
    }

    /// 插入一个 object。返回是否被缓存（过旧的晚到包会被拒绝）。
    pub fn insert(&mut self, obj: Arc<Object>) -> bool {
        // 情况 1：比窗口内最旧的 group 还老 → 晚到乱序包，直接丢弃。
        if let Some((oldest, _)) = self.groups.front()
            && obj.group_id < *oldest
        {
            self.dropped_late += 1;
            return false;
        }
        // 情况 2：比最新 group 更新 → 开新 group，触发窗口滑动淘汰。
        if self.groups.back().is_none_or(|(g, _)| obj.group_id > *g) {
            self.groups.push_back((obj.group_id, vec![obj]));
            while self.groups.len() > self.capacity {
                self.groups.pop_front();
            }
            return true;
        }
        // 情况 3：落在窗口内的既有 group → 按 object_id 有序插入。
        let entry = self
            .groups
            .iter_mut()
            .find(|(g, _)| *g == obj.group_id)
            .expect("group_id 落在窗口内必然存在对应 group");
        let pos = entry.1.partition_point(|o| o.object_id < obj.object_id);
        entry.1.insert(pos, obj);
        true
    }

    /// 最新 group 的 id（缓存为空时返回 None）。
    pub fn latest_group_id(&self) -> Option<u64> {
        self.groups.back().map(|(g, _)| *g)
    }

    /// 追赶快照：返回「最新 group 开头起」的全部 object（直播切入语义）。
    pub fn snapshot_from_latest_group(&self) -> Vec<Arc<Object>> {
        match self.groups.back() {
            Some((_, objs)) => objs.clone(),
            None => Vec::new(),
        }
    }

    /// 返回指定 group 起（含）的窗口内全部 object；起点在未来（尚未播到）时回退到最新 group。
    pub fn snapshot_from_group(&self, group_id: u64) -> Vec<Arc<Object>> {
        let mut out = Vec::new();
        for (g, objs) in &self.groups {
            if *g >= group_id {
                out.extend(objs.iter().cloned());
            }
        }
        if out.is_empty() {
            // 请求的起点已不在窗口内 → 从最新 group 切入。
            return self.snapshot_from_latest_group();
        }
        out
    }

    /// 当前缓存的 group 数。
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// 当前缓存的 object 总数。
    pub fn object_count(&self) -> usize {
        self.groups.iter().map(|(_, o)| o.len()).sum()
    }

    /// 被丢弃的晚到包计数。
    pub fn dropped_late(&self) -> u64 {
        self.dropped_late
    }
}
