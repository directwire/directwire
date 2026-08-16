//! gm-pq-stack 目标：国密+后量子 Noise 握手三消息的解析入口 + 深层状态专探。
//!
//! 入口面：
//! - msg1（`-> e`：临时公钥）→ `Responder::read_msg1`（validate_public）；
//! - msg2（`<- e_r || ct_ee || AEAD(s_r)`）→ `Initiator::read_msg2`
//!   （validate_public + KEM decapsulate + transcript mix）；
//! - msg3（`-> ct_se || ct_ss || AEAD(s_i || sig)`）→ `Responder::read_msg3`
//!   （decapsulate se/ss + AEAD open + split）。
//! - 深层状态（③ 扩展）：golden 互认证（SM2 签名 proof-of-possession + peer_static 锚定）、
//!   PSK 会话恢复、0-RTT early data 往返不变式、stateless cookie 挑战、PSK 模式 msg3 深解析。
//!
//! 成本声明（③ 重构后实测，本机 release，libsmx 0.3.0 ML-KEM-768）：
//! - 静态密钥对**预生成一次**（8 init + 8 resp，OnceLock），每次调用只 Clone
//!   （`HybridSecretKey` 手写 Clone ≈ 0.3µs）——keygen 不再烧进迭代预算；
//! - 底层原语实测：`keypair` 284µs / `encapsulate` 804µs / `decapsulate` 804µs
//!   （`-C target-cpu=native` 无改善，libsmx 为纯标量恒定时间实现，无 SIMD feature）。
//!   深层相位成本全部来自这些协议固有的 KEM 运算：msg3 深解析 ≈ 1.4ms（前缀
//!   write_msg1/2 = 2 keygen + 1 encapsulate），黄金握手 ≈ 6.2ms（3 encap + 3 decap
//!   + SM2 签名/验签）。这些 KEM 运算是「探到深层状态」本身的价格，任何 harness
//!   结构调整都去不掉——**100× 迭代率的真正杠杆在 libsmx 的 ML-KEM 实现，不在
//!   harness**；迭代率提升到 ~1.4× 是 keygen 消除的真实收益，深层状态密度则大幅
//!   提升（详见下）。
//! - 深度覆盖保证：corpus 预生成**合法 msg3** 作基底，mutator 保长变异 → 消息体能过
//!   `read_msg3` 的长度闸门，真正跑到 decapsulate + AEAD open（而非只跑前缀）。
//! - 防误报说明：解析路径全部用**无 trust-anchor** 的变体，fuzz 输入不可能满足
//!   签名校验，误报路径自然返回 Err 而非 panic；golden/PSK 路径用 AllowAllAnchor +
//!   真签名，panic 只可能来自状态机/密码学库的真实 bug。

use gm_pq_stack::handshake::cookie::CookieIssuer;
use gm_pq_stack::handshake::{Initiator, Responder};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;
use gm_pq_stack::trust::AllowAllAnchor;
use std::sync::OnceLock;

/// 预生成的静态密钥池大小（每侧）。keygen 只跑一次，之后全部 Clone。
const POOL_SIZE: usize = 8;
/// 固定 PSK（会话恢复/0-RTT 用，双方一致即可；fuzz 只管消息字节）。
const PSK: [u8; 32] = [0x42; 32];

struct KeyPool {
    init: Vec<(<DefaultHybrid as Kem>::SecretKey, Vec<u8>)>,
    resp: Vec<(<DefaultHybrid as Kem>::SecretKey, Vec<u8>)>,
}

fn pool() -> &'static KeyPool {
    static POOL: OnceLock<KeyPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut rng = SysRng::new();
        let mut make_pool = |n: usize| {
            (0..n)
                .map(|_| {
                    DefaultHybrid::keypair(&mut rng)
                        .expect("OS CSPRNG unavailable; cannot build key pool")
                })
                .collect::<Vec<_>>()
        };
        KeyPool {
            init: make_pool(POOL_SIZE),
            resp: make_pool(POOL_SIZE),
        }
    })
}

/// 从输入字节选密钥对下标（越界回退 0），再从池中 Clone。
/// `data[0]`=相位、`data[1]`=init 键、`data[2]`=resp 键、`data[3..]`=消息体。
fn idx(b: Option<&u8>) -> usize {
    b.copied().unwrap_or(0) as usize % POOL_SIZE
}

pub fn corpus() -> Vec<Vec<u8>> {
    // 生成合法 msg3 字节作深解析基底：mutator 保长变异 → 消息体能过 read_msg3
    // 的长度闸门，真正跑到 decapsulate + AEAD open（而不只是前缀）。
    let mut rng = SysRng::new();
    let (isk, ipk) = DefaultHybrid::keypair(&mut rng).expect("OS CSPRNG unavailable");
    let (rsk, rpk) = DefaultHybrid::keypair(&mut rng).expect("OS CSPRNG unavailable");
    let mut init: Initiator<DefaultHybrid> = Initiator::new(isk, ipk);
    let m1 = init.write_msg1(&mut rng).expect("write_msg1");
    let mut resp: Responder<DefaultHybrid> = Responder::new(rsk, rpk);
    resp.read_msg1(&m1).expect("read_msg1");
    let m2 = resp.write_msg2(&mut rng).expect("write_msg2");
    init.read_msg2(&m2).expect("read_msg2");
    let (m3, _) = init.write_msg3(&mut rng).expect("write_msg3");

    let mut p2 = vec![2u8, 0, 0];
    p2.extend_from_slice(&m3);
    let mut p7 = vec![7u8, 0, 0];
    p7.extend_from_slice(&m3);

    vec![
        Vec::new(),
        vec![0u8],
        vec![3u8, 0, 0],          // golden 互认证（第一对密钥）
        vec![4u8, 1, 2],          // PSK 会话恢复
        vec![5u8, 2, 1],          // 0-RTT early data
        vec![6u8, 0, 0],          // cookie 挑战
        vec![7u8, 3, 3],          // PSK msg3 深解析（短体，过闸门）
        p2,                        // phase 2 + 合法 msg3（真正 decap）
        p7,                        // phase 7 + 合法 msg3（真正 decap）
        vec![0xabu8; 8],
        vec![0xffu8; 32],
        vec![0u8; 64],
        vec![0x01u8; 128],
    ]
}

pub fn fuzz(data: &[u8]) {
    let p = pool();
    let (init_sk, init_pk) = p.init[idx(data.get(1))].clone();
    let (resp_sk, resp_pk) = p.resp[idx(data.get(2))].clone();

    let phase = data.first().copied().unwrap_or(0) % 8;
    let body: &[u8] = data.get(3..).unwrap_or(&[]);
    let mut rng = SysRng::new();

    match phase {
        // 0: 客户端解析 msg2（写 msg1 后把 fuzz 当 msg2 喂）
        0 => {
            let mut init: Initiator<DefaultHybrid> = Initiator::new(init_sk, init_pk);
            let _ = init.write_msg1(&mut rng);
            let _ = init.read_msg2(body);
        }
        // 1: 服务端解析 msg1 + 生成 msg2
        1 => {
            let mut resp: Responder<DefaultHybrid> = Responder::new(resp_sk, resp_pk);
            if resp.read_msg1(body).is_ok() {
                let _ = resp.write_msg2(&mut rng);
            }
        }
        // 2: 服务端解析 msg3（先走合法 msg1/msg2 建立状态，再喂 fuzz）
        2 => {
            let mut init: Initiator<DefaultHybrid> = Initiator::new(init_sk, init_pk);
            let m1 = init.write_msg1(&mut rng).unwrap();
            let mut resp: Responder<DefaultHybrid> = Responder::new(resp_sk, resp_pk);
            resp.read_msg1(&m1).unwrap();
            let _ = resp.write_msg2(&mut rng).unwrap();
            let _ = resp.read_msg3(body);
        }
        // 3: golden 完整握手（互认证 + AllowAllAnchor）——合法流程永不 panic
        3 => {
            let anchor = AllowAllAnchor;
            let mut init: Initiator<DefaultHybrid> = Initiator::new(init_sk, init_pk);
            let m1 = init.write_msg1(&mut rng).unwrap();
            let mut resp: Responder<DefaultHybrid> = Responder::new(resp_sk, resp_pk.clone());
            resp.read_msg1(&m1).unwrap();
            let m2 = resp.write_msg2(&mut rng).unwrap();
            init.read_msg2(&m2).unwrap();
            let (m3, sess_a) = init.write_msg3_with_auth(&mut rng, &anchor).unwrap();
            let (sess_b, _pk) = resp.read_msg3_with_auth(&m3, &anchor).unwrap();
            assert_eq!(
                sess_a.session_id(),
                sess_b.session_id(),
                "golden 握手两侧 session_id 必须一致"
            );
            // 互认证后：initiator 应拿到 responder 的静态公钥（对方身份锚定）
            assert_eq!(
                init.peer_static(),
                Some(resp_pk.as_slice()),
                "golden 握手后 initiator 应持有 responder 静态公钥"
            );
        }
        // 4: PSK 会话恢复（双方同 PSK 的完整握手）——session_id 仍须一致
        4 => {
            let anchor = AllowAllAnchor;
            let mut init: Initiator<DefaultHybrid> = Initiator::new_with_psk(init_sk, init_pk, &PSK);
            let m1 = init.write_msg1(&mut rng).unwrap();
            let mut resp: Responder<DefaultHybrid> = Responder::new_with_psk(resp_sk, resp_pk, &PSK);
            resp.read_msg1(&m1).unwrap();
            let m2 = resp.write_msg2(&mut rng).unwrap();
            init.read_msg2(&m2).unwrap();
            let (m3, sess_a) = init.write_msg3_with_auth(&mut rng, &anchor).unwrap();
            let (sess_b, _pk) = resp.read_msg3_with_auth(&m3, &anchor).unwrap();
            assert_eq!(
                sess_a.session_id(),
                sess_b.session_id(),
                "PSK 握手两侧 session_id 必须一致"
            );
        }
        // 5: 0-RTT early data——fuzz 尾巴加密后必须原样还原（单跳 AEAD 往返不变式）
        5 => {
            let mut init: Initiator<DefaultHybrid> = Initiator::new_with_psk(init_sk, init_pk, &PSK);
            let m1 = init.write_msg1(&mut rng).unwrap();
            // 密封任意明文（长度随 fuzz 输入有界）都必须成功
            let sealed = init
                .seal_early_data(body)
                .expect("seal_early_data 对任意明文必须成功");
            let mut resp: Responder<DefaultHybrid> = Responder::new_with_psk(resp_sk, resp_pk, &PSK);
            resp.read_msg1(&m1).unwrap();
            let opened = resp
                .open_early_data(&sealed)
                .expect("合法 sealed early data 必须可开");
            assert_eq!(opened, body, "0-RTT early data 往返必须一致");
            // 0-RTT 之后继续完整握手，状态机必须还能走到会话建立
            let m2 = resp.write_msg2(&mut rng).unwrap();
            init.read_msg2(&m2).unwrap();
            let (m3, _sess_a) = init.write_msg3(&mut rng).unwrap();
            let _sess_b = resp.read_msg3(&m3).unwrap();
        }
        // 6: stateless cookie 挑战——自签 cookie 必须通过，对抗组合必须返回 Err 而非 panic
        6 => {
            let issuer = CookieIssuer::from_secret([0x5e; 32], 60);
            let legal_tag = [0xaau8; 16];
            let legal_pk = [0xbbu8; 65]; // e_pk 长度任意（cookie 只做 HMAC）
            let cookie = issuer.issue(&legal_tag, &legal_pk);
            assert!(
                issuer.verify(&legal_tag, &legal_pk, &cookie).is_ok(),
                "自签 cookie 必须通过校验"
            );
            // fuzz 提供的 tag / e_pk / cookie 任意组合：只允许 Err
            let f_tag: &[u8] = body.get(..16).unwrap_or(body);
            let f_pk: &[u8] = body.get(16..).unwrap_or(&[]);
            let _ = issuer.verify(f_tag, f_pk, body);
        }
        // 7: PSK 模式 msg3 深解析（合法 PSK msg1/msg2 后喂 fuzz 当 msg3）
        _ => {
            let mut init: Initiator<DefaultHybrid> = Initiator::new_with_psk(init_sk, init_pk, &PSK);
            let m1 = init.write_msg1(&mut rng).unwrap();
            let mut resp: Responder<DefaultHybrid> = Responder::new_with_psk(resp_sk, resp_pk, &PSK);
            resp.read_msg1(&m1).unwrap();
            let _ = resp.write_msg2(&mut rng).unwrap();
            let _ = resp.read_msg3(body);
        }
    }
}
