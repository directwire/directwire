//! 连接跟踪表：LRU 哈希 + 超时过期。
//!
//! 对应 bpf 侧 BPF_MAP_TYPE_LRU_HASH 的语义：
//! - 固定容量，满时淘汰最久未使用（LRU）的连接；
//! - 每条连接带 last_seen 时间戳，超过 timeout 判定过期，等价于新连接。
//!
//! 实现：HashMap<五元组, 节点下标> + 侵入式双向链表（slab 分配），
//! 查找 / 插入 / 淘汰均 O(1)，与内核 LRU map 的摊还复杂度一致。

use crate::packet::FiveTuple;
use std::collections::HashMap;

/// 连接表项值：选路决策结果（后端内网 IP）+ 活跃时间
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnEntry {
    pub backend_ip: u32,
    pub last_seen_ns: u64,
}

/// 链表节点（slab 内）
#[derive(Debug, Clone, Copy)]
struct Node {
    key: FiveTuple,
    value: ConnEntry,
    prev: u32,
    next: u32,
    used: bool,
}

const NIL: u32 = u32::MAX;

/// LRU 连接跟踪表
pub struct ConnTrack {
    map: HashMap<FiveTuple, u32>,
    nodes: Vec<Node>,
    free: Vec<u32>,
    /// 链表头 = 最近使用；尾 = 最久未使用
    head: u32,
    tail: u32,
    capacity: usize,
    timeout_ns: u64,
    /// 统计：LRU 淘汰次数
    pub evictions: u64,
}

impl ConnTrack {
    pub fn new(capacity: usize, timeout_ns: u64) -> Self {
        assert!(capacity > 0);
        Self {
            map: HashMap::with_capacity(capacity),
            nodes: Vec::with_capacity(capacity),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            capacity,
            timeout_ns,
            evictions: 0,
        }
    }

    /// 查询连接。命中且未过期则刷新 LRU 位置与活跃时间。
    /// 过期条目按未命中处理并顺带清除。
    pub fn lookup(&mut self, key: &FiveTuple, now_ns: u64) -> Option<ConnEntry> {
        let idx = *self.map.get(key)?;
        let entry = self.nodes[idx as usize].value;
        if now_ns.saturating_sub(entry.last_seen_ns) > self.timeout_ns {
            // 已过期：摘除，调用方将走新建连接流程
            self.remove_at(idx);
            return None;
        }
        // 刷新活跃时间并提升至链表头
        self.nodes[idx as usize].value.last_seen_ns = now_ns;
        self.move_to_head(idx);
        Some(entry)
    }

    /// 插入/覆盖连接。容量满时淘汰 LRU 尾部。
    pub fn insert(&mut self, key: FiveTuple, value: ConnEntry) {
        if let Some(&idx) = self.map.get(&key) {
            self.nodes[idx as usize].value = value;
            self.move_to_head(idx);
            return;
        }
        if self.map.len() >= self.capacity {
            // 淘汰最久未使用连接
            let victim = self.tail;
            debug_assert!(victim != NIL);
            self.evictions += 1;
            self.remove_at(victim);
        }
        let idx = self.alloc_node(key, value);
        self.push_head(idx);
        self.map.insert(key, idx);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn timeout_ns(&self) -> u64 {
        self.timeout_ns
    }

    /// 周期清扫：摘除所有过期连接，返回清扫条数。
    /// 对应内核侧「LRU map 无原生 TTL、需控制面 bpf_map_lookup batch 清扫」的产品化做法；
    /// 数据面 lookup 路径的惰性过期不受影响，两者可叠加。
    pub fn sweep_expired(&mut self, now_ns: u64) -> usize {
        // 先收集过期节点下标，再统一摘除（避免遍历中修改 map）
        let victims: Vec<u32> = self
            .map
            .values()
            .copied()
            .filter(|&idx| {
                let e = &self.nodes[idx as usize];
                now_ns.saturating_sub(e.value.last_seen_ns) > self.timeout_ns
            })
            .collect();
        let n = victims.len();
        for idx in victims {
            self.remove_at(idx);
        }
        n
    }

    // ---- 内部：slab + 侵入式链表操作 ----

    fn alloc_node(&mut self, key: FiveTuple, value: ConnEntry) -> u32 {
        if let Some(idx) = self.free.pop() {
            self.nodes[idx as usize] = Node { key, value, prev: NIL, next: NIL, used: true };
            idx
        } else {
            let idx = self.nodes.len() as u32;
            self.nodes.push(Node { key, value, prev: NIL, next: NIL, used: true });
            idx
        }
    }

    fn push_head(&mut self, idx: u32) {
        self.nodes[idx as usize].prev = NIL;
        self.nodes[idx as usize].next = self.head;
        if self.head != NIL {
            self.nodes[self.head as usize].prev = idx;
        }
        self.head = idx;
        if self.tail == NIL {
            self.tail = idx;
        }
    }

    fn unlink(&mut self, idx: u32) {
        let (prev, next) = {
            let n = &self.nodes[idx as usize];
            (n.prev, n.next)
        };
        if prev != NIL {
            self.nodes[prev as usize].next = next;
        } else {
            self.head = next;
        }
        if next != NIL {
            self.nodes[next as usize].prev = prev;
        } else {
            self.tail = prev;
        }
    }

    fn move_to_head(&mut self, idx: u32) {
        if self.head == idx {
            return;
        }
        self.unlink(idx);
        self.push_head(idx);
    }

    fn remove_at(&mut self, idx: u32) {
        self.unlink(idx);
        let key = self.nodes[idx as usize].key;
        self.map.remove(&key);
        self.nodes[idx as usize].used = false;
        self.free.push(idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FiveTuple, PROTO_TCP};

    fn key(port: u16) -> FiveTuple {
        FiveTuple { src_ip: 0x0a00_0001, dst_ip: 0x0a00_0002, src_port: port, dst_port: 80, protocol: PROTO_TCP }
    }

    fn entry(t: u64) -> ConnEntry {
        ConnEntry { backend_ip: 0xc0a8_0001, last_seen_ns: t }
    }

    #[test]
    fn lru_evicts_coldest() {
        let mut ct = ConnTrack::new(3, 1_000_000_000);
        ct.insert(key(1), entry(0));
        ct.insert(key(2), entry(1));
        ct.insert(key(3), entry(2));
        // 访问 key(1)，使其成为最新
        assert!(ct.lookup(&key(1), 3).is_some());
        // 插入第 4 条，应淘汰 key(2)（最久未用）
        ct.insert(key(4), entry(4));
        assert_eq!(ct.evictions, 1);
        assert!(ct.lookup(&key(2), 5).is_none());
        assert!(ct.lookup(&key(1), 6).is_some());
        assert!(ct.lookup(&key(4), 7).is_some());
    }

    #[test]
    fn timeout_expires_entry() {
        let mut ct = ConnTrack::new(8, 1_000);
        ct.insert(key(9), entry(100));
        assert!(ct.lookup(&key(9), 500).is_some()); // 命中并把 last_seen 刷新到 500
        // 相对上次活跃（500）超过 timeout(1000)，视为新连接
        assert!(ct.lookup(&key(9), 1601).is_none());
        assert_eq!(ct.len(), 0);
    }
}
