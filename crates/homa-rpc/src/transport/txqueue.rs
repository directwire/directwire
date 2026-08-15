//! 发送侧 8 级优先级 QoS 队列：DATA 包按包头优先级入队，高优先级（编号小）先出队。
//!
//! 跨线程设计（多 IO 线程）：状态机线程把待发包压入队列（`push`，锁内只做入队，
//! 不碰 socket），专职发送线程调用 `wait_batch` 批量弹出并在**锁外**执行
//! `UDP send_to`。这样 socket syscall 不再占用状态锁，长消息的高分片洪泛
//! 不会卡死短消息的调度活性。
//!
//! 控制包（GRANT/RESEND/BUSY）走独立的 control 队列、出队时优先级最高——
//! 它们小且影响调度活性，必须比任何 DATA 都先发出。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

use super::packet::PacketType;
use super::priority::NUM_PRIORITIES;

/// 发送线程单次批量弹出的最大包数。限额让同批积压内高优先级包插队（QoS 生效窗口），
/// 且不阻塞发送线程太久——积压由后续迭代继续冲刷。
/// 1024 ≈ 1MB 长消息单次 GRANT 解锁的分片量（1200B × 873），减少批边界唤醒停顿
pub const FLUSH_BUDGET: usize = 1024;

struct TxInner {
    /// 控制包：GRANT / RESEND / BUSY，出队时绝对优先
    control: VecDeque<(SocketAddr, Vec<u8>)>,
    /// 8 级优先级 DATA 队列
    queues: [VecDeque<(SocketAddr, Vec<u8>)>; NUM_PRIORITIES as usize],
}

/// 8 级优先级发送队列（跨线程共享）
pub struct TxQueues {
    inner: Mutex<TxInner>,
    /// 队列从空变非空时唤醒发送线程
    cv: Condvar,
    /// 关闭标志：置位后 wait_batch 在空队列时返回空批（发送线程得以退出）
    shutdown: AtomicBool,
}

impl TxQueues {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TxInner {
                control: VecDeque::new(),
                queues: Default::default(),
            }),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
        }
    }

    /// 把一个待发包按类型入队：DATA 按优先级入队，控制包进 control 队列。
    /// 入队后唤醒发送线程。
    pub fn push(&self, dest: SocketAddr, bytes: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        // 头两字节 = 类型 + 优先级（见 packet.rs 线格式）
        let is_data = bytes.len() >= 2 && bytes[0] == PacketType::Data as u8;
        if is_data {
            let prio = bytes[1].min(NUM_PRIORITIES - 1);
            inner.queues[prio as usize].push_back((dest, bytes));
        } else {
            inner.control.push_back((dest, bytes));
        }
        // 多发送线程时须唤醒全部（单发送线程下等价于 notify_one）
        self.cv.notify_all();
    }

    /// 阻塞直到队列非空；弹出至多 budget 个包（control 全清 + 按优先级高到低 DATA）。
    /// 队列为空且无新包时挂起等待。
    pub fn wait_batch(&self, budget: usize) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            let mut out = Vec::new();
            // control 绝对优先
            while let Some(item) = inner.control.pop_front() {
                out.push(item);
            }
            // 按优先级从高到低弹 DATA（同级 FIFO）
            for q in &mut inner.queues {
                while out.len() < budget {
                    match q.pop_front() {
                        Some(item) => out.push(item),
                        None => break,
                    }
                }
                if out.len() >= budget {
                    break;
                }
            }
            if !out.is_empty() {
                return out;
            }
            // 关闭已置位：空队列直接返回空批，让发送线程退出（不再等待）
            if self.shutdown.load(Ordering::Relaxed) {
                return out;
            }
            // 空队列：等待唤醒
            inner = self.cv.wait(inner).unwrap();
        }
    }

    /// 关闭：置位标志并唤醒可能挂起的发送线程，使其从 wait_batch 返回空批并退出
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.cv.notify_all();
    }

    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.control.is_empty() && inner.queues.iter().all(|q| q.is_empty())
    }

    /// 观测用：积压总数
    pub fn backlog(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner
            .queues
            .iter()
            .map(|q| q.len())
            .sum::<usize>()
            + inner.control.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet::Packet;

    fn data_pkt(prio: u8, msg_id: u64) -> Vec<u8> {
        Packet::new(PacketType::Data, prio, msg_id, 100, 0, 4).encode(b"data")
    }

    /// 测试辅助：非阻塞弹出一批（等 100ms 超时返回，若空则驱动一次 wake_all）
    fn pop_with_timeout(tx: &TxQueues, budget: usize, timeout: std::time::Duration) -> Vec<(SocketAddr, Vec<u8>)> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(batch) = try_pop(tx, budget) {
                return batch;
            }
            if std::time::Instant::now() >= deadline {
                return Vec::new();
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn try_pop(tx: &TxQueues, budget: usize) -> Option<Vec<(SocketAddr, Vec<u8>)>> {
        let inner = tx.inner.lock().unwrap();
        if inner.control.is_empty() && inner.queues.iter().all(|q| q.is_empty()) {
            return None;
        }
        drop(inner);
        Some(tx.wait_batch(budget))
    }

    #[test]
    fn 高优先级先出队() {
        let tx = TxQueues::new();
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // 乱序入队：5, 0, 3, 7, 0
        for (prio, id) in [(5u8, 1u64), (0, 2), (3, 3), (7, 4), (0, 5)] {
            tx.push(dest, data_pkt(prio, id));
        }
        let batch = pop_with_timeout(&tx, 100, std::time::Duration::from_secs(1));
        let order: Vec<u64> = batch
            .iter()
            .map(|(_, b)| Packet::decode(b).unwrap().0.msg_id)
            .collect();
        // 优先级 0 的两个按 FIFO 在前，然后 3、5、7
        assert_eq!(order, vec![2, 5, 3, 1, 4]);
        assert!(tx.is_empty());
    }

    #[test]
    fn 限额制造积压且高优先级插队() {
        let tx = TxQueues::new();
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // 先入队 FLUSH_BUDGET+40 个低优先级（长消息突发），超过单次 budget
        for i in 0..(FLUSH_BUDGET as u64 + 40) {
            tx.push(dest, data_pkt(7, i));
        }
        // 再来 1 个高优先级（短 RPC）
        tx.push(dest, data_pkt(0, 999));
        let batch = pop_with_timeout(&tx, FLUSH_BUDGET, std::time::Duration::from_secs(1));
        assert_eq!(batch.len(), FLUSH_BUDGET);
        // 高优先级包必须在本批第一个出队，而不是排在所有低优先级之后
        assert_eq!(Packet::decode(&batch[0].1).unwrap().0.msg_id, 999);
        assert_eq!(tx.backlog(), 40 + 1);
    }

    #[test]
    fn 控制包直发不入队() {
        let tx = TxQueues::new();
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let grant = Packet::new(PacketType::Grant, 0, 1, 0, 100, 100).encode(&[]);
        tx.push(dest, grant.clone());
        // 控制包在 control 队列，出队时优先于任何 DATA
        let batch = pop_with_timeout(&tx, 10, std::time::Duration::from_secs(1));
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1, grant);
        assert!(tx.is_empty());
    }
}
