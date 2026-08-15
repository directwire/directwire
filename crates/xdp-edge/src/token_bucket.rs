//! 令牌桶限速器（per-源 IP），对应 bpf 侧 ratelimit map 的语义。
//!
//! 单桶模型：以固定速率补充令牌，容量为 burst；
//! 报文到达消耗一个令牌，令牌不足则拒绝（XDP_DROP）。
//! 时间使用调用方注入的纳秒时钟（虚拟时钟，测试可确定性驱动）。

use std::collections::HashMap;

/// 单源令牌桶
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// 补充速率（令牌/纳秒）
    rate_per_ns: f64,
    /// 桶容量（允许的最大突发）
    burst: f64,
    /// 当前令牌数
    tokens: f64,
    /// 上次补充时间（纳秒）
    last_refill_ns: u64,
}

impl TokenBucket {
    /// rate: 每秒允许的报文数；burst: 突发容量（报文数）
    pub fn new(rate: f64, burst: f64) -> Self {
        assert!(rate > 0.0 && burst >= 1.0);
        Self {
            rate_per_ns: rate / 1e9,
            burst,
            tokens: burst, // 新源视为满桶，允许初始突发
            last_refill_ns: 0,
        }
    }

    /// 在 now_ns 时刻尝试取一个令牌
    pub fn allow(&mut self, now_ns: u64) -> bool {
        self.refill(now_ns);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// 按流逝时间补充令牌（封顶 burst）
    fn refill(&mut self, now_ns: u64) {
        if now_ns > self.last_refill_ns {
            let elapsed = (now_ns - self.last_refill_ns) as f64;
            self.tokens = (self.tokens + elapsed * self.rate_per_ns).min(self.burst);
            self.last_refill_ns = now_ns;
        }
    }

    /// 当前可用令牌数（测试观测用）
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

/// per-源 IP 限速器：源地址 -> 令牌桶
///
/// 与 bpf 侧一致，map 满时对新源直接放行并计数（真实产品中
/// 应淘汰最久未活跃的桶，此处为架构骨架的简化）。
pub struct RateLimiter {
    buckets: HashMap<u32, TokenBucket>,
    rate: f64,
    burst: f64,
    max_entries: usize,
    /// map 满时被跳过限速的新源计数
    pub overflow_count: u64,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64, max_entries: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            rate: rate_per_sec,
            burst,
            max_entries,
            overflow_count: 0,
        }
    }

    /// 判决 src_ip 在 now_ns 时刻的报文是否放行
    pub fn allow(&mut self, src_ip: u32, now_ns: u64) -> bool {
        match self.buckets.get_mut(&src_ip) {
            Some(b) => b.allow(now_ns),
            None => {
                if self.buckets.len() >= self.max_entries {
                    self.overflow_count += 1;
                    return true;
                }
                let mut b = TokenBucket::new(self.rate, self.burst);
                let ok = b.allow(now_ns);
                self.buckets.insert(src_ip, b);
                ok
            }
        }
    }

    pub fn entry_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_throttle() {
        let mut b = TokenBucket::new(1000.0, 10.0);
        // 瞬间消耗整个突发
        for _ in 0..10 {
            assert!(b.allow(0));
        }
        assert!(!b.allow(0)); // 桶空，拒绝
        // 前进 5ms，应补回 ~5 个令牌
        let t = 5_000_000u64;
        let mut ok = 0;
        for i in 0..10 {
            if b.allow(t + i) {
                ok += 1;
            }
        }
        assert!(ok >= 4 && ok <= 6, "补桶精度异常: {}", ok);
    }
}
