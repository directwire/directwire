//! QUIC 变长整数（RFC 9000 §16）编解码。
//!
//! 高两位表示字节长度：00=1 字节，01=2 字节，10=4 字节，11=8 字节，
//! 剩余 62 bit 为有效载荷，取值范围 [0, 2^62-1]。MoQ Transport 全线使用该编码。

use std::io;

/// varint 最大值（62 bit）。
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// 计算编码所需字节数。
pub fn encoded_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => {
            assert!(v <= VARINT_MAX, "varint 超出 62 bit 上限: {v}");
            8
        }
    }
}

/// 将 varint 追加编码到缓冲区（大端序）。
pub fn encode(v: u64, out: &mut Vec<u8>) {
    match encoded_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// 从切片头部解码 varint，返回 (值, 消耗字节数)。
pub fn decode(buf: &[u8]) -> io::Result<(u64, usize)> {
    let Some(&first) = buf.first() else {
        return Err(eof());
    };
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(eof());
    }
    let mut v = (first & 0x3F) as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    Ok((v, len))
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "varint 数据不足")
}
