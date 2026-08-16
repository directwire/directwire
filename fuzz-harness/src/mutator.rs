//! 确定性字节变异器（结构化 fuzz 的引擎层基石）。
//! 纯 std，splitmix64 PRNG —— 同一 seed 产出完全相同的变异序列，可复现、可回归。
//! 引擎层不依赖任何被测 crate。

/// splitmix64：小而快的确定性 PRNG（net-sim 同款风格）。
#[derive(Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// [0, n)
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// 常见「有趣」字节：边界值、varint 高两位、非法 varint 前缀、ASCII/UTF-8 片段。
const INTERESTING: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x07, 0x08, 0x0f, 0x10, 0x1f, 0x20, 0x21, 0x7e, 0x7f, // 边界
    0x80, 0x81, 0xfe, 0xff, // 符号位 / 全 1
    0x40, 0xbf, // varint 2 字节前缀
    0x80, 0xbf, // varint 4 字节前缀
    0xc0, 0xbf, // varint 8 字节前缀（62 bit 上限）
    0xc2, 0xa2, 0xe2, 0x82, 0xac, // UTF-8 片段（¢ / €）
];

/// 4 字节「有趣值」（长度炸弹 / 偏移炸弹）。
const INTERESTING_U32: &[u32] = &[
    0,
    1,
    u32::MAX,
    u32::MAX - 1,
    0x7fff_ffff,
    0x00ff_ffff,
    1 << 24,
    16 << 20, // 正好等于 homa MAX_MSG_LEN
    17 << 20, // 超过 MAX_MSG_LEN
];

/// 结构化变异器：对种子输入做字节级/块级操作，每次生成一条新输入。
pub struct Mutator {
    rng: Rng,
    /// 每轮变异算子数上限（随机 1..=max_ops）
    max_ops: usize,
}

impl Mutator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::new(seed),
            max_ops: 16,
        }
    }

    /// 供引擎选取语料基底的随机数源
    pub fn rng_mut(&mut self) -> &mut Rng {
        &mut self.rng
    }

    /// 基于 base 生成下一条输入（一半概率从 base 起步，一半从空起步）。
    pub fn next(&mut self, base: &[u8], max_len: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = if self.rng.below(2) == 1 {
            base.to_vec()
        } else {
            Vec::new()
        };
        let ops = 1 + self.rng.below(self.max_ops);
        for _ in 0..ops {
            self.mutate(&mut buf, max_len);
        }
        buf.truncate(max_len);
        buf
    }

    fn mutate(&mut self, buf: &mut Vec<u8>, max_len: usize) {
        let len = buf.len();
        match self.rng.below(8) {
            // 0: 位翻转
            0 => {
                if len > 0 {
                    let i = self.rng.below(len);
                    buf[i] ^= 1 << self.rng.below(8);
                }
            }
            // 1: 写有趣字节
            1 => {
                if len > 0 {
                    let i = self.rng.below(len);
                    buf[i] = INTERESTING[self.rng.below(INTERESTING.len())];
                }
            }
            // 2: 插入有趣字节
            2 => {
                if len < max_len {
                    let i = if len == 0 { 0 } else { self.rng.below(len) };
                    buf.insert(i, INTERESTING[self.rng.below(INTERESTING.len())]);
                }
            }
            // 3: 删除一段
            3 => {
                if len > 1 {
                    let a = self.rng.below(len);
                    let b = (a + 1 + self.rng.below(len - a)).min(len);
                    buf.drain(a..b);
                }
            }
            // 4: 复制重叠段（splice）
            4 => {
                if len > 0 && len < max_len {
                    let a = self.rng.below(len);
                    let b = (a + 1 + self.rng.below(len - a)).min(len);
                    let copy: Vec<u8> = buf[a..b].to_vec();
                    let ins = if len == 0 { 0 } else { self.rng.below(len) };
                    let take = copy.len().min(max_len - len);
                    let mut it = copy.into_iter().take(take);
                    buf.splice(ins..ins, it.by_ref());
                }
            }
            // 5: 写 4 字节有趣值（长度/偏移炸弹）
            5 => {
                if len >= 4 {
                    let i = self.rng.below(len - 3);
                    let v = INTERESTING_U32[self.rng.below(INTERESTING_U32.len())];
                    buf[i..i + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
            // 6: 整块重复（构造长同型输入）
            6 => {
                if len > 0 && len < max_len {
                    let i = self.rng.below(len);
                    let take = (len - i).max(1).min(max_len - len);
                    let copy: Vec<u8> = buf[i..(i + take).min(len)].to_vec();
                    buf.extend_from_slice(&copy);
                }
            }
            // 7: 追加字符串（覆盖 UTF-8 / 协议标签路径）
            7 => {
                if len < max_len {
                    const S: &[u8] = b"Directwire\0\x00varint\xC0\x80\xE2\x82\xAC\xFF";
                    let take = S.len().min(max_len - len);
                    buf.extend_from_slice(&S[..take]);
                }
            }
            _ => unreachable!(),
        }
    }
}
