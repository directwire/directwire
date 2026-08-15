//! conntrack TTL 周期清扫器。
//!
//! 产品背景：内核 BPF_MAP_TYPE_LRU_HASH 没有原生 TTL，数据面 lookup
//! 只做惰性过期（命中过期条目按 miss 处理），过期条目仍占容量。
//! 生产方案是控制面周期批量清扫（bpf_map_lookup_and_delete_batch）。
//! 本骨架复刻该节奏：按 sweep_interval 驱动 ConnTrack::sweep_expired。

use crate::conntrack::ConnTrack;

/// 周期清扫器（虚拟时钟驱动）
pub struct ConntrackSweeper {
    interval_ns: u64,
    next_run_ns: u64,
    /// 累计清扫条数（观测指标）
    pub total_swept: u64,
    /// 累计清扫轮次
    pub rounds: u64,
}

impl ConntrackSweeper {
    pub fn new(interval_ns: u64) -> Self {
        Self {
            interval_ns,
            next_run_ns: interval_ns,
            total_swept: 0,
            rounds: 0,
        }
    }

    /// 每个控制面 tick 调用；到点则执行一轮清扫，返回本轮清扫条数
    pub fn tick(&mut self, ct: &mut ConnTrack, now_ns: u64) -> Option<usize> {
        if now_ns < self.next_run_ns {
            return None;
        }
        self.next_run_ns = now_ns + self.interval_ns;
        let n = ct.sweep_expired(now_ns);
        self.total_swept += n as u64;
        self.rounds += 1;
        Some(n)
    }

    pub fn next_run_ns(&self) -> u64 {
        self.next_run_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::ConnEntry;
    use crate::packet::{FiveTuple, PROTO_TCP};

    const S: u64 = 1_000_000_000;

    fn key(i: u32) -> FiveTuple {
        FiveTuple {
            src_ip: i,
            dst_ip: 0xcb00_7101,
            src_port: 1024,
            dst_port: 443,
            protocol: PROTO_TCP,
        }
    }

    #[test]
    fn sweep_removes_only_expired() {
        let mut ct = ConnTrack::new(1024, 10 * S); // TTL 10s
        // t=0 插入 5 条，t=8s 插入 5 条
        for i in 0..5 {
            ct.insert(
                key(i),
                ConnEntry {
                    backend_ip: 1,
                    last_seen_ns: 0,
                },
            );
        }
        for i in 5..10 {
            ct.insert(
                key(i),
                ConnEntry {
                    backend_ip: 1,
                    last_seen_ns: 8 * S,
                },
            );
        }
        // t=12s 清扫：前 5 条过期（12s>10s），后 5 条存活（4s<10s）
        let n = ct.sweep_expired(12 * S);
        assert_eq!(n, 5);
        assert_eq!(ct.len(), 5);
        // 存活条目仍可查
        assert!(ct.lookup(&key(7), 12 * S).is_some());
        assert!(ct.lookup(&key(2), 12 * S).is_none());
    }

    #[test]
    fn sweeper_runs_on_schedule() {
        let mut sw = ConntrackSweeper::new(30 * S); // 30s 一轮
        let mut ct = ConnTrack::new(1024, 10 * S);
        ct.insert(
            key(1),
            ConnEntry {
                backend_ip: 1,
                last_seen_ns: 0,
            },
        );

        assert_eq!(sw.tick(&mut ct, 10 * S), None, "未到清扫时间");
        let n = sw.tick(&mut ct, 31 * S);
        assert_eq!(n, Some(1), "到点应清扫掉过期条目");
        assert_eq!(sw.rounds, 1);
        assert_eq!(sw.total_swept, 1);
        assert_eq!(sw.next_run_ns(), 61 * S);
        // 下一轮空扫
        assert_eq!(sw.tick(&mut ct, 62 * S), Some(0));
        assert_eq!(sw.rounds, 2);
    }
}
