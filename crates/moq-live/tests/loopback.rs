//! 端到端 loopback 集成测试：真实 QUIC 连接上的 relay 扇出、追赶与 alias 协商。
//!
//! 数据面为 stream-per-group（每个 group 一条单向流），证书走公钥钉扎。
//! 全程 127.0.0.1，外层 20s 兜底超时防挂死。

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moq_live::client::{Publisher, Subscriber};
use moq_live::hub::Hub;
use moq_live::message::StartMode;
use moq_live::net;
use moq_live::relay::Relay;
use moq_live::track::{Object, TrackId};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const GROUPS: u64 = 4;
const FRAMES_PER_GROUP: u64 = 5;

#[tokio::test]
async fn relay_fans_out_and_late_subscriber_catches_up() {
    tokio::time::timeout(Duration::from_secs(20), scenario())
        .await
        .expect("loopback 测试超时（20s）");
}

async fn scenario() {
    // 1. relay @ loopback:0（证书钉扎：客户端钉扎该证书）。
    let (certs, key) = self_signed_cert();
    let pinned = certs[0].clone();
    let endpoint = net::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let relay = Relay::new(endpoint, Hub::new(3));
    tokio::spawn(async move { relay.run().await });

    let track = TrackId::new("test/live", "video");

    // 2. publisher 先连接并声明命名空间（subscriber 依赖命名空间已发布）。
    let pub_ep = net::client_endpoint_pinned(pinned.clone()).unwrap();
    let publisher = Publisher::connect(&pub_ep, addr).await.unwrap();
    publisher.announce(&track.namespace).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. subscriber 1：从头订阅。
    let s1 = spawn_subscriber(pinned.clone(), addr, track.clone());

    // 4. publisher：推 GROUPS * FRAMES_PER_GROUP 个 object（每 group 一条单向流）。
    let stats = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let stats2 = Arc::clone(&stats);
    let track2 = track.clone();
    let pinned2 = pinned.clone();
    let s2 = tokio::spawn(async move {
        // subscriber 2：推迟 0.8s 加入 → 应从「当时最新 group 的开头」追赶。
        tokio::time::sleep(Duration::from_millis(800)).await;
        let r = run_subscriber(pinned2, addr, track2).await;
        stats2.lock().await.push(r);
    });

    let pub_task = {
        let track = track.clone();
        tokio::spawn(async move {
            for g in 0..GROUPS {
                let mut gw = publisher.begin_group(&track, g).await.unwrap();
                for i in 0..FRAMES_PER_GROUP {
                    let o = Object::new(
                        g,
                        i,
                        if i == 0 { 0 } else { 128 },
                        moq_live::client::now_ms(),
                        Bytes::from_static(b"frame"),
                    );
                    gw.write_object(&o).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                gw.finish();
            }
            publisher
        })
    };

    // 5. 断言：subscriber 1 收齐全量；subscriber 2 追赶切入（首帧 group > 0）。
    let (n1, first_g1) = s1.await.unwrap();
    assert_eq!(n1, (GROUPS * FRAMES_PER_GROUP) as usize, "全量订阅者应收齐");
    assert_eq!(first_g1, 0, "全量订阅者从 group 0 开始");

    s2.await.unwrap();
    let lats = stats.lock().await;
    let (n2, first_g2) = lats[0];
    assert!(
        n2 >= FRAMES_PER_GROUP as usize,
        "追赶订阅者至少收到一个完整 group"
    );
    assert!(
        first_g2 > 0,
        "追赶订阅者应从更晚的 group 切入，实际 {first_g2}"
    );
    println!("sub1: n={n1} first_group={first_g1}; sub2: n={n2} first_group={first_g2}");

    // 6. alias 协商生效：订阅发生后 publisher 应已记录 relay 分配的 alias，
    //    后续 group 流头使用 alias（帧头压缩路径真实走过）。
    let publisher = pub_task.await.unwrap();
    assert!(
        publisher.alias_of(&track).await.is_some(),
        "订阅发生后 publisher 应已协商出 track alias"
    );
    println!(
        "publisher 已协商 alias: {:?}",
        publisher.alias_of(&track).await
    );

    // 优雅收尾：留出尾帧投递窗口再断开。
    tokio::time::sleep(Duration::from_millis(300)).await;
    publisher.close().await;
}

/// 起订阅端任务，返回 (收到帧数, 首帧 group_id)。
fn spawn_subscriber(
    pinned: CertificateDer<'static>,
    addr: std::net::SocketAddr,
    track: TrackId,
) -> tokio::task::JoinHandle<(usize, u64)> {
    tokio::spawn(async move { run_subscriber(pinned, addr, track).await })
}

async fn run_subscriber(
    pinned: CertificateDer<'static>,
    addr: std::net::SocketAddr,
    track: TrackId,
) -> (usize, u64) {
    let ep = net::client_endpoint_pinned(pinned).unwrap();
    let sub = Subscriber::connect(&ep, addr).await.unwrap();
    let mut rx = sub
        .subscribe(1, &track, StartMode::LatestGroup, 0)
        .await
        .unwrap()
        .expect("订阅应成功");
    let mut count = 0usize;
    let mut first_group = u64::MAX;
    let total = (GROUPS * FRAMES_PER_GROUP) as usize;
    let idle = Duration::from_secs(2);
    while count < total {
        match tokio::time::timeout(idle, rx.recv()).await {
            Ok(Some(o)) => {
                first_group = first_group.min(o.group_id);
                count += 1;
            }
            _ => break,
        }
    }
    (count, first_group)
}

/// 自签名证书（仅测试用）。
fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}
