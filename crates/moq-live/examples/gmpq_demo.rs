//! GM-PQ 会话层演示（feature gm-pq）：publisher → relay → 2 个 subscriber
//! 全链路在 SM2+ML-KEM-768 混合握手保护下运行；subscriber B 二次连接演示 0-RTT 恢复。
//!
//! 运行：cargo run --example gmpq_demo --features gm-pq

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
const FRAMES_PER_GROUP: u64 = 25; // 25fps × 1s GOP

#[tokio::main]
async fn main() {
    tokio::time::timeout(Duration::from_secs(60), run())
        .await
        .expect("演示超时（60s）");
}

async fn run() {
    // ---- 0. GM-PQ 身份与信任锚（钉扎对端静态公钥）----
    let (relay_sk, relay_pk) = gmpq::generate_keypair().expect("relay 密钥对");
    let (pub_sk, pub_pk) = gmpq::generate_keypair().expect("publisher 密钥对");
    let (sub_sk, sub_pk) = gmpq::generate_keypair().expect("subscriber 密钥对");
    let sub_sk_b = sub_sk.clone(); // B 复用同一身份（演示恢复语义）

    // relay 锚：钉扎 publisher/subscriber 公钥（生产换 PinFileAnchor::from_file）。
    let relay_anchor =
        PinFileAnchor::from_keys([("publisher", &*pub_pk), ("subscriber", &*sub_pk)]);
    let server_id = Arc::new(ServerIdentity::new(
        relay_sk,
        relay_pk.clone(),
        relay_anchor,
        3600,
    ));
    // 客户端锚：钉扎 relay 公钥。
    let pub_id = Arc::new(ClientIdentity::new(
        pub_sk,
        pub_pk,
        PinFileAnchor::from_keys([("relay", &*relay_pk)]),
    ));
    let sub_id = Arc::new(ClientIdentity::new(
        sub_sk,
        sub_pk.clone(),
        PinFileAnchor::from_keys([("relay", &*relay_pk)]),
    ));
    println!("== GM-PQ 算法: {} ==\n", gmpq::algorithm_name());

    // ---- 1. relay（QUIC TLS 钉扎证书 + GM-PQ 会话层）----
    let (certs, key) = self_signed_cert();
    let pinned = certs[0].clone();
    let endpoint = net::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let relay = Arc::new(Relay::new(endpoint, Hub::new(2)).with_gmpq(Arc::clone(&server_id)));
    {
        let r = Arc::clone(&relay);
        tokio::spawn(async move { r.run().await });
    }
    println!("== relay 已启动 @ {addr}（QUIC TLS + GM-PQ 会话层）==\n");

    let track = TrackId::new("live/camera-01", "video");

    // ---- 2. publisher：完整握手 + ANNOUNCE + 推流 ----
    let pub_ep = net::client_endpoint_pinned(pinned.clone()).unwrap();
    let (publisher, info) = Publisher::connect_gmpq(&pub_ep, addr, Arc::clone(&pub_id))
        .await
        .expect("publisher GM-PQ 握手");
    println!(
        "publisher: 握手模式 {} 耗时 {:?} session={}",
        info.mode_label(),
        info.elapsed,
        hex8(&info.session_id)
    );
    publisher.announce(&track.namespace).await.unwrap();

    // ---- 3. subscriber A：完整握手；subscriber B：完整握手后重连走 0-RTT ----
    let sub_ep = net::client_endpoint_pinned(pinned.clone()).unwrap();
    let (sub_a, info_a) = Subscriber::connect_gmpq(&sub_ep, addr, Arc::clone(&sub_id))
        .await
        .expect("subscriber A GM-PQ 握手");
    println!(
        "subscriber A: 握手模式 {} 耗时 {:?}",
        info_a.mode_label(),
        info_a.elapsed
    );
    let rx_a = sub_a
        .subscribe(1, &track, StartMode::LatestGroup, 0)
        .await
        .unwrap()
        .expect("A 订阅成功");

    // B 首次连接（完整握手，落票据）。演示中 B 复用 A 的身份密钥对
    //（实际部署各客户端独立密钥对，并在 relay 锚中逐一登记）。
    let sub_id_b = Arc::new(ClientIdentity::new(
        sub_sk_b.clone(),
        sub_pk.clone(),
        PinFileAnchor::from_keys([("relay", &*relay_pk)]),
    ));
    let (sub_b1, info_b1) = Subscriber::connect_gmpq(&sub_ep, addr, Arc::clone(&sub_id_b))
        .await
        .expect("subscriber B 首次 GM-PQ 握手");
    println!(
        "subscriber B(首次): 握手模式 {} 耗时 {:?}",
        info_b1.mode_label(),
        info_b1.elapsed
    );
    let rx_b = sub_b1
        .subscribe(1, &track, StartMode::LatestGroup, 0)
        .await
        .unwrap()
        .expect("B 订阅成功");

    // ---- 4. 推流 3 秒 ----
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pub_task = tokio::spawn({
        let track = track.clone();
        async move {
            let frame = Bytes::from(vec![0x5Au8; 16 * 1024]);
            for g in 0..GROUPS {
                let mut gw = publisher.begin_group(&track, g).await.unwrap();
                for i in 0..FRAMES_PER_GROUP {
                    let o =
                        Object::new(g, i, if i == 0 { 0 } else { 128 }, now_ms(), frame.clone());
                    gw.write_object(&o).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(1000 / 25)).await;
                }
                gw.finish();
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
            publisher.close().await;
        }
    });

    // ---- 5. 收流 + 延迟统计 ----
    let (ra, rb) = tokio::join!(collect_stats("A", rx_a), collect_stats("B", rx_b));
    pub_task.await.unwrap();
    for (name, lat) in [ra, rb] {
        println!("  {name}: {}", summarize(&lat));
    }

    // ---- 6. subscriber B 二次连接：0-RTT 恢复 ----
    let (_sub_b2, info_b2) = Subscriber::connect_gmpq(&sub_ep, addr, Arc::clone(&sub_id_b))
        .await
        .expect("subscriber B 0-RTT 恢复握手");
    println!(
        "\nsubscriber B(重连): 握手模式 {} 耗时 {:?} {}",
        info_b2.mode_label(),
        info_b2.elapsed,
        String::from_utf8_lossy(info_b2.early_data.as_deref().unwrap_or_default())
    );
    assert!(info_b2.resumed, "二次连接应走 0-RTT 恢复");

    // ---- 7. GOAWAY 优雅关闭 ----
    relay.shutdown().await;
    println!("\n== 演示完成：GM-PQ 会话层全链路（完整握手 + 0-RTT 恢复 + GOAWAY）==");
}

fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

/// 收流并统计端到端延迟。
async fn collect_stats(
    name: &str,
    mut rx: tokio::sync::mpsc::Receiver<Object>,
) -> (String, Vec<u64>) {
    let mut lat = Vec::new();
    let idle = Duration::from_millis(1500);
    while let Ok(Some(o)) = tokio::time::timeout(idle, rx.recv()).await {
        lat.push(now_ms().saturating_sub(o.timestamp_ms));
    }
    println!("subscriber {name}: 收到 {} 帧", lat.len());
    (name.to_string(), lat)
}

fn summarize(lat: &[u64]) -> String {
    if lat.is_empty() {
        return "无数据".to_string();
    }
    let mut sorted = lat.to_vec();
    sorted.sort_unstable();
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let p95 = sorted[((sorted.len() - 1) * 95) / 100];
    let avg = sorted.iter().sum::<u64>() / sorted.len() as u64;
    format!(
        "n={} min={}ms avg={}ms p95={}ms max={}ms",
        sorted.len(),
        min,
        avg,
        p95,
        max
    )
}

/// 自签名证书（QUIC TLS 钉扎用，与 GM-PQ 会话层正交）。
fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}
