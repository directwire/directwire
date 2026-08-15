//! 优先级分级丢弃队列：中继在下行拥塞时的丢包决策单元。
//!
//! 策略（对齐 MoQ「中继可感知优先级做丢包决策」的范式）：
//! - 容量未满：正常入队（FIFO）；
//! - 容量已满且新 object 为 group 头（关键帧）：驱逐队中优先级最低的非头 object；
//!   若全队都是 group 头（极端情况），丢弃新 object 自身；
//! - 容量已满且新 object 非 group 头：若队中存在优先级更低（数值更大）的非头
//!   object，驱逐之；否则丢弃新 object 自身。
//!
//! 不变式：group 头永不因「非头 object 到达」而被驱逐——保住可解码起点。

use std::collections::VecDeque;
use std::sync::Arc;

use crate::track::Object;

/// push 的结果。
#[derive(Debug)]
pub enum PushOutcome {
    /// 正常入队。
    Queued,
    /// 入队并驱逐了一个更低优先级的 object。
    Evicted(Arc<Object>),
    /// 新 object 自身被丢弃（优先级不够高或队满且全是 group 头）。
    DroppedSelf,
}

#[derive(Debug)]
pub struct PriorityDropQueue {
    capacity: usize,
    queue: VecDeque<Arc<Object>>,
    /// 累计丢弃数（含驱逐与自弃）。
    dropped: u64,
}

impl PriorityDropQueue {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "队列容量至少为 1");
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            dropped: 0,
        }
    }

    pub fn push(&mut self, obj: Arc<Object>) -> PushOutcome {
        if self.queue.len() < self.capacity {
            self.queue.push_back(obj);
            return PushOutcome::Queued;
        }
        // 队满：找「优先级最低的非 group 头」（数值最大；tie 取最新，保住更旧内容的时序）。
        let victim = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, o)| !o.is_group_head())
            .max_by_key(|(_, o)| o.priority)
            .map(|(i, _)| i);
        match victim {
            Some(i) if obj.is_group_head() || obj.priority < self.queue[i].priority => {
                let evicted = self.queue.remove(i).expect("下标有效");
                self.queue.push_back(obj);
                self.dropped += 1;
                PushOutcome::Evicted(evicted)
            }
            _ => {
                // 无牺牲品或新 object 优先级不够 → 丢弃自身。
                self.dropped += 1;
                PushOutcome::DroppedSelf
            }
        }
    }

    pub fn pop(&mut self) -> Option<Arc<Object>> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// 累计丢弃数。
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
