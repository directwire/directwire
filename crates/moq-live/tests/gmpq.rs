//! GM-PQ 会话层集成测试（feature gm-pq）：混合握手门控 + 全链路 + 0-RTT 恢复 + 负路径。
#![cfg(feature = "gm-pq")]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use gm_pq_stack::trust::PinFileAnchor;
use moq_live::client::{Publisher, Subscriber, now_ms};
use moq_live::gmpq::{self, ClientIdentity, ServerIdentity};
use moq_live::hub::Hub;
use moq_live::message::StartMode;
use moq_live::net;
use moq_live::relay::Relay;
use moq_live::track::{Object, TrackId};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const GROUPS: u64 = 3;
const FRAMES_PER_GROUP: u64 = 5;

/// 测试部署：relay 钉扎 publisher/subscriber 公钥，客户端钉扎 relay 公钥。
struct Fixture {
    addr: std::net::SocketAddr,
    pinned: CertificateDer<'static>,
    relay_pk: Vec<u8>,
    pub_id: Arc<ClientIdentity>,
    sub_id: Arc<ClientIdentity>,
    _relay: Arc<Relay>,
}

async fn setup() -> Fixture {
    let (relay_sk, relay_pk) = gmpq::generate_keypair().unwrap();
    let (pub_sk, pub_pk) = gmpq::generate_keypair().unwrap();
    let (sub_sk, sub_pk) = gmpq::generate_keypair().unwrap();

    let relay_anchor =
        PinFileAnchor::from_keys([("publisher", &*pub_pk), ("subscriber", &*sub_pk)]);
    let server_id = Arc::new(ServerIdentity::new(
        relay_sk,
        relay_pk.clone(),
        relay_anchor,
        3600,
    ));
    let pub_id = Arc::new(ClientIdentity::new(
        pub_sk,
        pub_pk,
        PinFileAnchor::from_keys([("relay", &*relay_pk)]),
    ));
    let sub_id = Arc::new(ClientIdentity::new(
        sub_sk,
        sub_pk,
        PinFileAnchor::from_keys([("relay", &*relay_pk)]),
    ));

    let (certs, key) = self_signed_cert();
    let pinned = certs[0].clone();
    let endpoint = net::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let relay = Arc::new(Relay::new(endpoint, Hub::new(3)).with_gmpq(server_id));
    let r = Arc::clone(&relay);
    tokio::spawn(async move { r.run().await });

    Fixture {
        addr,
        pinned,
        relay_pk,
        pub_id,
        sub_id,
        _relay: relay,
    }
}

/// 全链路：GM-PQ 握手门控下 publisher → relay → subscriber 收齐全量 object。
#[tokio::test]
async fn full_pipeline_over_gmpq_session() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let f = setup().await;
        let track = TrackId::new("test/gmpq", "video");

        let pub_ep = net::client_endpoint_pinned(f.pinned.clone()).unwrap();
        let (publisher, info) = Publisher::connect_gmpq(&pub_ep, f.addr, f.pub_id)
            .await
            .unwrap();
        assert!(!info.resumed, "首次应为完整握手");
        println!(
            "[test] publisher 握手: {} {:?}",
            info.mode_label(),
            info.elapsed
        );
        publisher.announce(&track.namespace).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let sub_ep = net::client_endpoint_pinned(f.pinned.clone()).unwrap();
        let (sub, sinfo) = Subscriber::connect_gmpq(&sub_ep, f.addr, f.sub_id)
            .await
            .unwrap();
        println!(
            "[test] subscriber 握手: {} {:?}",
            sinfo.mode_label(),
            sinfo.elapsed
        );
        let mut rx = sub
            .subscribe(1, &track, StartMode::LatestGroup, 0)
            .await
            .unwrap()
            .expect("订阅应成功");

        let total = (GROUPS * FRAMES_PER_GROUP) as usize;
        let pub_task = tokio::spawn(async move {
            for g in 0..GROUPS {
                let mut gw = publisher.begin_group(&track, g).await.unwrap();
                for i in 0..FRAMES_PER_GROUP {
                    gw.write_object(&Object::new(g, i, 128, now_ms(), Bytes::from_static(b"f")))
                        .await
                        .unwrap();
                }
                gw.finish();
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            publisher.close().await;
        });

        let mut got = 0usize;
        while got < total {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(_)) => got += 1,
                other => panic!("收流中断于 {got}/{total}: {other:?}"),
            }
        }
        pub_task.await.unwrap();
        println!("[test] GM-PQ 会话层全链路收齐 {total} 帧");
    })
    .await
    .expect("测试超时（30s）");
}

/// 0-RTT 恢复：同一 ClientIdentity 二次连接应 resumed=true。
#[tokio::test]
async fn second_connection_resumes_with_zero_rtt() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let f = setup().await;
        let sub_ep = net::client_endpoint_pinned(f.pinned.clone()).unwrap();

        let (_s1, i1) = Subscriber::connect_gmpq(&sub_ep, f.addr, Arc::clone(&f.sub_id))
            .await
            .unwrap();
        assert!(!i1.resumed);
        let full_ms = i1.elapsed;

        let (_s2, i2) = Subscriber::connect_gmpq(&sub_ep, f.addr, Arc::clone(&f.sub_id))
            .await
            .unwrap();
        assert!(i2.resumed, "二次连接应走 0-RTT 恢复");
        println!(
            "[test] 完整握手 {:?} → 0-RTT 恢复 {:?}（early: {}）",
            full_ms,
            i2.elapsed,
            String::from_utf8_lossy(i2.early_data.as_deref().unwrap_or_default())
        );
    })
    .await
    .expect("测试超时（30s）");
}

/// 负路径：未在 relay 锚中登记的客户端，握手必须失败（PeerAuth），
/// 且不得放行任何控制消息。
#[tokio::test]
async fn unpinned_client_is_rejected() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let f = setup().await;
        // 攻击者：自造密钥对（不在 relay 锚内），但钉扎 relay 公钥（能过传输层 QUIC TLS）。
        let (evil_sk, evil_pk) = gmpq::generate_keypair().unwrap();
        let evil_anchor = PinFileAnchor::from_keys([("relay", &*f.relay_pk)]);
        let evil_id = Arc::new(ClientIdentity::new(evil_sk, evil_pk, evil_anchor));
        let ep = net::client_endpoint_pinned(f.pinned.clone()).unwrap();
        let result = Subscriber::connect_gmpq(&ep, f.addr, evil_id).await;
        match result {
            Err(e) => println!("[test] 未登记客户端按预期被拒: {e}"),
            Ok(_) => panic!("未登记客户端必须被握手拒绝"),
        }
    })
    .await
    .expect("测试超时（30s）");
}

fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}
