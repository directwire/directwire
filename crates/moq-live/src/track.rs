//! Track 抽象：MoQ 的核心寻址模型。
//!
//! 层级为 namespace / track_name / group_id / object_id：
//! - namespace：业务命名空间（如 "live/camera-01"），ANNOUNCE 的粒度；
//! - track：一条媒体轨道（如 "video"），SUBSCRIBE 的粒度；
//! - group：独立可解码单元（视频即一个 GOP），缓存与追赶（catch-up）的粒度；
//! - object：group 内的最小传输单元（一帧 / 一个切片），可独立丢弃。
//!
//! 优先级约定与 MoQ Transport 一致：数值越小优先级越高，中继拥塞时优先丢大值。

use bytes::Bytes;

/// 轨道唯一标识（namespace + track_name）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrackId {
    pub namespace: String,
    pub name: String,
}

impl TrackId {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for TrackId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// 优先级：0 最高，255 最低（与 draft-ietf-moq-transport 的 publisher priority 对齐）。
pub type Priority = u8;

/// 最高优先级（关键帧/I 帧所在 object 建议使用）。
pub const PRIORITY_HIGHEST: Priority = 0;

/// 一个媒体 object（MVP：对应一帧模拟视频数据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub group_id: u64,
    pub object_id: u64,
    pub priority: Priority,
    /// 发布端发送时刻（UNIX 毫秒），用于端到端延迟统计。
    pub timestamp_ms: u64,
    pub payload: Bytes,
}

impl Object {
    pub fn new(
        group_id: u64,
        object_id: u64,
        priority: Priority,
        timestamp_ms: u64,
        payload: Bytes,
    ) -> Self {
        Self {
            group_id,
            object_id,
            priority,
            timestamp_ms,
            payload,
        }
    }

    /// 是否为一个 group 的首个 object（直播场景通常是关键帧）。
    pub fn is_group_head(&self) -> bool {
        self.object_id == 0
    }
}
