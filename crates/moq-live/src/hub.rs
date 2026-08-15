//! 扇出枢纽（Fan-out Hub）：relay 的核心状态。
//!
//! 每条 track 一份状态：GroupCache（追赶缓存）+ broadcast 通道（实时扇出）。
//! 发布端 publish 一次，N 个订阅端各自从 broadcast 通道接收，
//! relay 无需为每个订阅者复制媒体载荷（Arc 共享）。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;

use crate::cache::GroupCache;
use crate::message::StartMode;
use crate::track::{Object, TrackId};

/// broadcast 通道容量：拥塞时慢订阅者收到 Lagged 错误而非阻塞发布端，
/// 这是中继「丢帧保活」优先级的第一道防线。
const BROADCAST_CAPACITY: usize = 256;

/// 单个订阅的初始视图：追赶快照 + 实时接收器。
pub struct Subscription {
    /// 订阅建立瞬间的追赶数据（按 StartMode 决定起点）。
    pub replay: Vec<Arc<Object>>,
    /// 实时 object 流（可能含与 replay 重叠的 object，由消费方按 (group, object) 去重）。
    pub live: broadcast::Receiver<Arc<Object>>,
}

struct TrackState {
    cache: GroupCache,
    sender: broadcast::Sender<Arc<Object>>,
}

impl TrackState {
    fn new(group_capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            cache: GroupCache::new(group_capacity),
            sender,
        }
    }
}

/// 中继扇出枢纽：发布 → 缓存 + 扇出；订阅 → 追赶 + 实时。
#[derive(Clone)]
pub struct Hub {
    inner: Arc<RwLock<HashMap<TrackId, Arc<RwLock<TrackState>>>>>,
    /// 已发布的命名空间注册表（ANNOUNCE 控制面语义：订阅前校验）。
    namespaces: Arc<RwLock<HashSet<String>>>,
    /// 每条 track 缓存的 group 数。
    group_capacity: usize,
}

impl Hub {
    pub fn new(group_capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            namespaces: Arc::new(RwLock::new(HashSet::new())),
            group_capacity,
        }
    }

    /// 发布端声明命名空间（ANNOUNCE）。
    pub fn announce_namespace(&self, namespace: &str) {
        self.namespaces
            .write()
            .expect("hub 锁中毒")
            .insert(namespace.to_string());
    }

    /// 命名空间是否已发布（SUBSCRIBE 前的存在性校验）。
    pub fn namespace_announced(&self, namespace: &str) -> bool {
        self.namespaces
            .read()
            .expect("hub 锁中毒")
            .contains(namespace)
    }

    /// 发布端声明轨道（幂等）。
    pub fn announce(&self, track: &TrackId) {
        self.announce_namespace(&track.namespace);
        self.state(track);
    }

    /// 发布一个 object：写入缓存并扇出给全部在线订阅者。
    /// 返回是否被缓存接受（false = 晚到的过旧包）。
    pub fn publish(&self, track: &TrackId, obj: Object) -> bool {
        let obj = Arc::new(obj);
        let state = self.state(track);
        // 数据面首帧到达即视为命名空间隐式发布（兼容未走 ANNOUNCE 的发布端）。
        self.announce_namespace(&track.namespace);
        let mut guard = state.write().expect("hub 锁中毒");
        let cached = guard.cache.insert(Arc::clone(&obj));
        if cached {
            // 无订阅者时 send 返回 Err，属于正常情况，忽略。
            let _ = guard.sender.send(obj);
        }
        cached
    }

    /// 订阅一条轨道：返回追赶快照与实时接收器。
    pub fn subscribe(&self, track: &TrackId, start: StartMode) -> Subscription {
        let state = self.state(track);
        let guard = state.write().expect("hub 锁中毒");
        let replay = match start {
            StartMode::LatestGroup => guard.cache.snapshot_from_latest_group(),
            StartMode::NextObject => Vec::new(),
        };
        Subscription {
            replay,
            live: guard.sender.subscribe(),
        }
    }

    /// 查询轨道最新 group id（用于重连续传）。
    pub fn latest_group_id(&self, track: &TrackId) -> Option<u64> {
        let inner = self.inner.read().expect("hub 锁中毒");
        inner
            .get(track)
            .and_then(|s| s.read().expect("hub 锁中毒").cache.latest_group_id())
    }

    /// 当前已声明的 track 数。
    pub fn track_count(&self) -> usize {
        self.inner.read().expect("hub 锁中毒").len()
    }

    /// 获取（或惰性创建）track 状态。
    fn state(&self, track: &TrackId) -> Arc<RwLock<TrackState>> {
        {
            let inner = self.inner.read().expect("hub 锁中毒");
            if let Some(s) = inner.get(track) {
                return Arc::clone(s);
            }
        }
        let mut inner = self.inner.write().expect("hub 锁中毒");
        Arc::clone(
            inner
                .entry(track.clone())
                .or_insert_with(|| Arc::new(RwLock::new(TrackState::new(self.group_capacity)))),
        )
    }
}
