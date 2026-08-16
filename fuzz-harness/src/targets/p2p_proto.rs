//! p2p-mesh 目标：relay 线协议帧 + 打洞包 + GM-PQ BIND 的解析入口。
//!
//! 入口面：
//! - `proto::decode`：relay 帧解析（tag + NodeId + 候选地址 + 载荷）；
//! - `holepunch::decode_punch_packet`：PMP1 打洞包解析（魔数 + 32 字节 NodeId）；
//! - `gmpq::parse_bind`：国密通道 BIND 身份绑定消息解析（fuzz-harness 的
//!   Cargo.toml 对 p2p-mesh 开启了 `gm-pq` feature，故该模块始终可用）。
//!
//! 防 abort：`Cursor` 全部 take 前查边界，长度字段随后才消费，任何分配都以
//! 输入为界——无 OOM 炸弹。

use p2p_mesh::gmpq;
use p2p_mesh::holepunch;
use p2p_mesh::identity::NodeId;
use p2p_mesh::proto;

pub fn corpus() -> Vec<Vec<u8>> {
    use p2p_mesh::proto::{Frame, encode};
    let id = NodeId::from_bytes([3u8; 32]);
    let mut v = vec![
        encode(&Frame::Hello {
            node_id: id,
            cands: vec![],
        }),
        encode(&Frame::HelloAck {
            observed: "127.0.0.1:1234".parse().unwrap(),
        }),
        encode(&Frame::RelayData {
            to: id,
            from: id,
            payload: vec![1, 2, 3],
        }),
        encode(&Frame::Error { msg: "x".into() }),
        holepunch::encode_punch_packet(&id),
    ];
    // 带候选地址的帧：多地址 + 跨地址族
    let mut cands = vec![
        ("192.168.1.2:9000".parse().unwrap(), proto::CAND_PUNCH),
        ("10.0.0.1:443".parse().unwrap(), proto::CAND_QUIC),
    ];
    v.push(encode(&Frame::Hello {
        node_id: id,
        cands: cands.clone(),
    }));
    // IPv6 候选（打洞成功路径的地址族覆盖）
    cands.push(("[::1]:1".parse().unwrap(), proto::CAND_PUNCH));
    v.push(encode(&Frame::Hello { node_id: id, cands }));
    v
}

pub fn fuzz(data: &[u8]) {
    // 1) relay 帧：整输入 + 前缀截断（≤256 个前缀，覆盖截断帧/长度不匹配）
    let _ = proto::decode(data);
    let n = data.len().min(256);
    for end in 0..n {
        let _ = proto::decode(&data[..end]);
    }

    // 2) 打洞包：PMP1 魔数 + 32 字节 NodeId
    let _ = holepunch::decode_punch_packet(data);

    // 3) GM-PQ BIND 解析：预期 peer 用固定假键——所有 fuzz 签名都验不过，
    //    安全返回 Err，覆盖解析 + 签名校验路径
    let peer = NodeId::from_bytes([7u8; 32]);
    let gm_pk = [0x42u8; 32];
    let sid = [0x24u8; 32];
    let _ = gmpq::parse_bind(data, &peer, &gm_pk, &sid);
}
