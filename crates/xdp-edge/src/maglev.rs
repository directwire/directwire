//! Maglev 一致性哈希（Google, NSDI'16）。
//!
//! 与 Katran / Unimog 数据面同款选后端算法：
//! 每个后端通过两个独立哈希生成对查找表（LUT）的随机置换，
//! 轮流填充空槽，直至表满。后端扩缩容时只有约 1/N 的映射迁移，
//! 其余连接的选路结果保持不变（连接亲和性）。
//!
//! 表大小 M 必须为质数，保证 skip 步长可遍历全部槽位。

/// 判断质数（构建期调用一次，无需性能）
fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    let mut i = 2;
    while i * i <= n {
        if n % i == 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// splitmix64 风格的 64 位混合函数，用于把后端编号打散
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// 后端身份哈希 1（决定置换起点 offset）
fn hash_offset(backend: u32, m: u64) -> u64 {
    mix64(backend as u64 ^ 0x9e37_79b9_7f4a_7c15) % m
}

/// 后端身份哈希 2（决定置换步长 skip，范围 [1, m-1]）
fn hash_skip(backend: u32, m: u64) -> u64 {
    mix64(backend as u64 ^ 0xc2b2_ae3d_27d4_eb4f) % (m - 1) + 1
}

/// 用给定的后端集合构建 LUT（纯函数，供实例方法与控制面双缓冲发布复用）。
/// 后端增减时重建；Maglev 保证未受影响连接的映射基本不变。
pub fn build_lut(m: usize, backends: &[u32]) -> Vec<u32> {
    assert!(is_prime(m), "Maglev 表大小必须为质数");
    assert!(!backends.is_empty(), "后端列表不能为空");
    let mut table = vec![u32::MAX; m];

    let m64 = m as u64;
    let n = backends.len();
    // 每个后端的置换游标
    let mut next = vec![0u64; n];
    // 预计算每个后端的 offset / skip
    let offsets: Vec<u64> = backends.iter().map(|&b| hash_offset(b, m64)).collect();
    let skips: Vec<u64> = backends.iter().map(|&b| hash_skip(b, m64)).collect();

    let mut filled = 0usize;
    while filled < m {
        for i in 0..n {
            // 沿该后端的置换序列找到下一个空槽
            loop {
                let c = (offsets[i].wrapping_add(next[i].wrapping_mul(skips[i]))) % m64;
                next[i] += 1;
                if table[c as usize] == u32::MAX {
                    table[c as usize] = i as u32;
                    filled += 1;
                    break;
                }
            }
            if filled == m {
                break;
            }
        }
    }
    table
}

/// Maglev 一致性哈希表
pub struct Maglev {
    /// 查找表大小（质数）
    m: usize,
    /// LUT：槽位 -> 后端索引（未填充时为 u32::MAX）
    table: Vec<u32>,
    /// 当前生效的后端列表（索引与 table 中值对应）
    backends: Vec<u32>,
}

impl Maglev {
    /// 创建 Maglev 实例。m 必须为大质数（Katran 默认 65537）。
    pub fn new(m: usize) -> Self {
        assert!(is_prime(m), "Maglev 表大小必须为质数");
        Self { m, table: vec![u32::MAX; m], backends: Vec::new() }
    }

    /// 用给定的后端集合重建 LUT。
    pub fn rebuild(&mut self, backends: &[u32]) {
        self.table = build_lut(self.m, backends);
        self.backends = backends.to_vec();
    }

    /// 直接装载控制面构建好的 LUT（热下发路径：数据面不重算，仅切换指针）。
    pub fn load_table(&mut self, backends: Vec<u32>, table: Vec<u32>) {
        assert_eq!(table.len(), self.m, "LUT 尺寸与表大小不符");
        assert!(table.iter().all(|&v| (v as usize) < backends.len()), "LUT 含越界后端索引");
        self.backends = backends;
        self.table = table;
    }

    /// 按流键（已混合为 64 位）查找后端内网 IP。
    pub fn lookup(&self, flow_key: u64) -> u32 {
        let idx = (flow_key % self.m as u64) as usize;
        self.backends[self.table[idx] as usize]
    }

    /// 供测试观察：后端占据的槽位数（负载均衡度）
    pub fn slot_counts(&self) -> Vec<usize> {
        let mut counts = vec![0usize; self.backends.len()];
        for &v in &self.table {
            counts[v as usize] += 1;
        }
        counts
    }

    pub fn table_size(&self) -> usize {
        self.m
    }

    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }
}

/// 五元组 -> 64 位流键（与 bpf 侧 jhash 语义对应的软件混合）
pub fn flow_hash(t: &crate::packet::FiveTuple) -> u64 {
    let mut x = (t.src_ip as u64) << 32 | t.dst_ip as u64;
    x = x.wrapping_mul(0x100_0000_01b3); // FNV prime 低段
    x ^= ((t.src_port as u64) << 16) | t.dst_port as u64;
    x ^= (t.protocol as u64) << 48;
    mix64(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lut_fully_populated() {
        let mut mg = Maglev::new(101);
        mg.rebuild(&[10, 20, 30, 40]);
        assert!(mg.table.iter().all(|&v| v != u32::MAX));
        // 4 个后端应大致均分 101 个槽
        for c in mg.slot_counts() {
            assert!(c >= 15 && c <= 40, "负载严重不均: {}", c);
        }
    }

    #[test]
    fn lookup_deterministic() {
        let mut mg = Maglev::new(257);
        mg.rebuild(&[1, 2, 3]);
        for k in 0..1000u64 {
            assert_eq!(mg.lookup(mix64(k)), mg.lookup(mix64(k)));
        }
    }
}
