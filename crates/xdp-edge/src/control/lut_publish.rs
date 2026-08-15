//! Maglev LUT 热下发：双缓冲 + 原子版本切换（RCU-lite）。
//!
//! 产品语义（对应内核侧做法）：控制面在用户态算好新 LUT 后，
//! 写入非激活副本，最后原子翻转「激活版本」——数据面任何时刻
//! 读到的都是完整一致的某一版，绝不暴露半更新表。
//!
//! 正确性机制：
//! - 写者（单写者假设，控制面单线程 publish）只写非激活缓冲；
//! - 读者进入时对目标缓冲的读者计数 +1 并复核激活下标（经典
//!   RCU 读侧临界区），退出时 -1；
//! - 写者翻转下标后、复用旧缓冲前，自旋等待其读者计数归零
//!   （读者临界区仅一次 LUT 查询，等待时间有界）。

use crate::maglev::build_lut;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// 内部可变性封装：安全性由双缓冲协议保证（见模块注释）
struct SyncCell<T>(std::cell::UnsafeCell<T>);
unsafe impl<T: Send> Send for SyncCell<T> {}
unsafe impl<T: Send> Sync for SyncCell<T> {}

/// LUT 只读快照：持有期间对应缓冲不会被写者复用（RAII 读者计数）
pub struct LutSnapshot<'a> {
    pub version: u64,
    pub backends: &'a [u32],
    pub table: &'a [u32],
    readers: &'a AtomicUsize,
}

impl LutSnapshot<'_> {
    pub fn lookup(&self, flow_key: u64) -> u32 {
        let idx = (flow_key % self.table.len() as u64) as usize;
        self.backends[self.table[idx] as usize]
    }
}

impl Drop for LutSnapshot<'_> {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::Release);
    }
}

/// 双缓冲 LUT 发布器（单写者 / 多读者，无锁读路径）
pub struct LutPublisher {
    m: usize,
    /// 双缓冲：backends[i] 与 tables[i] 构成版本 i 的完整镜像
    backends: [SyncCell<Vec<u32>>; 2],
    tables: [SyncCell<Vec<u32>>; 2],
    /// 每个缓冲的活跃读者数
    readers: [AtomicUsize; 2],
    /// 激活缓冲下标（0/1）
    active: AtomicUsize,
    /// 单调递增版本号
    version: AtomicU64,
}

impl LutPublisher {
    /// 创建并以初始后端集合发布版本 1
    pub fn new(m: usize, initial_backends: &[u32]) -> Self {
        let table = build_lut(m, initial_backends);
        Self {
            m,
            backends: [
                SyncCell(std::cell::UnsafeCell::new(initial_backends.to_vec())),
                SyncCell(std::cell::UnsafeCell::new(Vec::new())),
            ],
            tables: [
                SyncCell(std::cell::UnsafeCell::new(table)),
                SyncCell(std::cell::UnsafeCell::new(vec![u32::MAX; m])),
            ],
            readers: [AtomicUsize::new(0), AtomicUsize::new(0)],
            active: AtomicUsize::new(0),
            version: AtomicU64::new(1),
        }
    }

    /// 用新后端集合构建并原子切换，返回新版本号。
    /// 构建期间读者继续使用旧版本，零停顿。
    pub fn publish(&self, backends: &[u32]) -> u64 {
        let cur = self.active.load(Ordering::Acquire);
        let shadow = 1 - cur;

        // 复用 shadow 缓冲前，等待其残留读者全部退出
        // （上一轮切换前的读者可能还持有 shadow 的快照）
        while self.readers[shadow].load(Ordering::Acquire) != 0 {
            std::hint::spin_loop();
        }

        // 在非激活缓冲上完整构建
        let table = build_lut(self.m, backends);
        unsafe {
            *self.tables[shadow].0.get() = table;
            *self.backends[shadow].0.get() = backends.to_vec();
        }
        let ver = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        // Release：保证缓冲写入先于下标翻转对读者可见
        self.active.store(shadow, Ordering::Release);
        ver
    }

    /// 取当前激活版本快照（读者入口，无锁）。
    /// 计数 +1 后复核激活下标：若写者恰在期间完成翻转，
    /// 本读者所在的旧缓冲已被计数保护，写者复用前会等待。
    pub fn snapshot(&self) -> LutSnapshot<'_> {
        loop {
            let idx = self.active.load(Ordering::Acquire);
            self.readers[idx].fetch_add(1, Ordering::AcqRel);
            // 复核：若翻转发生在计数之前，改用新激活缓冲重试
            if self.active.load(Ordering::Acquire) == idx {
                return LutSnapshot {
                    version: self.version.load(Ordering::Acquire),
                    backends: unsafe { &*self.backends[idx].0.get() },
                    table: unsafe { &*self.tables[idx].0.get() },
                    readers: &self.readers[idx],
                };
            }
            self.readers[idx].fetch_sub(1, Ordering::Release);
        }
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maglev::flow_hash;
    use crate::packet::{FiveTuple, PROTO_TCP};

    fn flow(i: u32) -> FiveTuple {
        FiveTuple {
            src_ip: 0xc000_0001 + i,
            dst_ip: 0xcb00_7101,
            src_port: 1024 + (i % 1000) as u16,
            dst_port: 443,
            protocol: PROTO_TCP,
        }
    }

    #[test]
    fn publish_switches_atomically() {
        let puber = LutPublisher::new(4099, &[1, 2, 3, 4]);
        let before: Vec<u32> = {
            let s1 = puber.snapshot();
            assert_eq!(s1.version, 1);
            (0..10_000u32).map(|i| s1.lookup(flow_hash(&flow(i)))).collect()
        };

        let v2 = puber.publish(&[1, 2, 3, 4, 5]); // 扩容一个后端
        assert_eq!(v2, 2);
        let s2 = puber.snapshot();
        assert_eq!(s2.version, 2);
        assert_eq!(s2.backends, &[1, 2, 3, 4, 5]);
        // 新版本映射有界变化（约 1/5），未受影响连接不动
        let moved = (0..10_000u32)
            .filter(|&i| s2.lookup(flow_hash(&flow(i))) != before[i as usize])
            .count();
        assert!(moved > 0 && moved < 4000, "扩容迁移量异常: {}", moved);
    }

    #[test]
    fn held_snapshot_stays_valid_across_publish() {
        // 持有旧快照期间发生 publish：写者改用对侧缓冲，旧快照保持完整可读
        let puber = LutPublisher::new(1013, &[10, 20, 30]);
        let old = puber.snapshot();
        let v_before = old.version;
        let r_before = old.lookup(42);
        puber.publish(&[10, 20]); // 写入非激活缓冲，不影响 old 所持缓冲
        assert_eq!(old.version, v_before);
        assert_eq!(old.lookup(42), r_before);
        // 读者退出后，其缓冲才能被下一轮 publish 复用
        drop(old);
        puber.publish(&[10, 20, 30, 40]);
        puber.publish(&[10]);
        assert_eq!(puber.version(), 4);
    }

    #[test]
    fn readers_never_see_partial_table() {
        // 多线程：单写者反复 publish，多读者持续 lookup，
        // 任何时刻 lookup 都不能越界（越界 = 读到半更新表）
        use std::sync::Arc;
        let puber = Arc::new(LutPublisher::new(1013, &[10, 20, 30]));
        let mut handles = Vec::new();
        for t in 0..3u64 {
            let p = Arc::clone(&puber);
            handles.push(std::thread::spawn(move || {
                for i in 0..20_000u64 {
                    let s = p.snapshot();
                    let _ = s.lookup(i.wrapping_mul(2_654_435_761) + t);
                }
            }));
        }
        for round in 0..50u32 {
            let n = 3 + (round % 5);
            let be: Vec<u32> = (0..n).map(|i| 10 + i).collect();
            puber.publish(&be);
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(puber.version(), 51);
    }
}
