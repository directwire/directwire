//! loopback 演示：1 个 publisher → relay → 3 个 subscriber 的实时“视频帧”流。
//!
//! 场景设计：
//! - publisher 以 25 fps 推送模拟视频帧（16 KB 伪数据），每 25 帧一个 group（1 秒 GOP），
//!   **每个 group 一条独立 QUIC 单向流**（stream-per-group）；
//!   group 首帧为“关键帧”（priority=0），其余为 P 帧（priority=128）；
//! - subscriber A / B 从头订阅；subscriber C 延迟 1.5s 加入，
//!   演示「断线重连/迟到订阅从最新 group 开头追赶」语义；
//! - 证书采用公钥钉扎（客户端钉扎 relay 自签名证书，不再 skip-verify）；
//! - 全部订阅端统计端到端延迟（帧头时间戳 vs 本地接收时刻），输出 min/avg/p95/max。
//!
//! 运行：cargo run --example live_demo

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moq_live::client::{Publisher, Subscriber, now_ms};
use moq_live::hub::Hub;
use moq_live::message::StartMode;
use moq_live::net;
use moq_live::relay::Relay;
use moq_live::track::{Object, TrackId};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const FPS: u64 = 25;
const FRAMES_PER_GROUP: u64 = 25; // 1 秒一个 GOP
const TOTAL_GROUPS: u64 = 3; // 共推 3 秒（75 帧）
const FRAME_SIZE: usize = 16 * 1024;

#[tokio::main]
async fn main() {
    // 全局兜底超时，防止演示挂死。
    tokio::time::timeout(Duration::from_secs(30), run())
        .await
        .expect("演示超时（30s）");
}

async fn run() {
    // ---- 1. 起 relay（loopback，随机端口；客户端钉扎其证书）----
    let (certs, key) = self_signed_cert();
    let pinned = certs[0].clone();
    let endpoint = net::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key)
        .expect("构建 relay endpoint");
    let addr: SocketAddr = endpoint.local_addr().expect("取监听地址");
    let relay = Arc::new(Relay::new(endpoint, Hub::new(2))); // 每条 track 缓存最近 2 个 group
    {
        let r = Arc::clone(&relay);
        tokio::spawn(async move { r.run().await });
    }
    println!("== relay 已启动 @ {addr}（每 track 缓存 2 个 group，证书钉扎）==\n");

    let track = TrackId::new("live/camera-01", "video");

    // ---- 2. publisher 先连接并 ANNOUNCE（subscriber 依赖命名空间已发布）----
    let pub_ep = net::client_endpoint_pinned(pinned.clone()).expect("publisher endpoint");
    let publisher = Publisher::connect(&pub_ep, addr)
        .await
        .expect("publisher 连接 relay");
    publisher
        .announce(&track.namespace)
        .await
        .expect("ANNOUNCE");
    println!("publisher: 已声明命名空间 {}", track.namespace);

    // ---- 3. 起 3 个 subscriber ----
    let stats = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut subs = tokio::task::JoinSet::new();
    for (name, delay) in [("A", 0u64), ("B", 0), ("C", 1500)] {
        let stats = Arc::clone(&stats);
        let track = track.clone();
        let pinned = pinned.clone();
        subs.spawn(async move {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let lat = run_subscriber(name, pinned, addr, track).await;
            stats.lock().await.push((name.to_string(), lat));
        });
    }

    // ---- 4. 推流 ----
    tokio::time::sleep(Duration::from_millis(300)).await; // 等 A/B 订阅就绪
    run_publisher(publisher, track).await.expect("publisher 失败");

    // ---- 5. 等订阅端收尾并汇总 ----
    while subs.join_next().await.is_some() {}
    let stats = stats.lock().await;
    println!("\n== 端到端延迟统计（publisher 帧头时间戳 → subscriber 收到时刻）==");
    let mut all = Vec::new();
    for (name, lat) in stats.iter() {
        all.extend(lat.iter().copied());
        println!("  subscriber {name}: {}", summarize(lat));
    }
    println!("  总体: {}", summarize(&all));

    // ---- 6. 演示 GOAWAY 优雅关闭 ----
    println!("\n== relay 发送 GOAWAY 优雅关闭 ==");
    relay.shutdown().await;
}

/// 模拟编码器：推送 TOTAL_GROUPS * FRAMES_PER_GROUP 帧，每 group 一条单向流。
async fn run_publisher(publisher: Publisher, track: TrackId) -> std::io::Result<()> {
    println!("publisher: 开始推流 {track} @ {FPS} fps，帧大小 {FRAME_SIZE} B");
    let frame = Bytes::from(vec![0xABu8; FRAME_SIZE]); // 模拟编码输出
    let frame_interval = Duration::from_millis(1000 / FPS);
    for group in 0..TOTAL_GROUPS {
        let mut gw = publisher.begin_group(&track, group).await?;
        let alias_used = publisher.alias_of(&track).await.is_some();
        for object_id in 0..FRAMES_PER_GROUP {
            let obj = Object::new(
                group,
                object_id,
                if object_id == 0 { 0 } else { 128 },
                now_ms(),
                frame.clone(),
            );
            gw.write_object(&obj).await?;
            tokio::time::sleep(frame_interval).await;
        }
        gw.finish();
        println!("publisher: group {group} 推完（帧头: {}）", if alias_used { "alias" } else { "full track" });
    }
    // 留出尾帧投递窗口再关闭连接。
    tokio::time::sleep(Duration::from_millis(500)).await;
    publisher.close().await;
    Ok(())
}

/// 单个订阅端：收流、算延迟。
async fn run_subscriber(
    name: &str,
    pinned: CertificateDer<'static>,
    addr: SocketAddr,
    track: TrackId,
) -> Vec<u64> {
    let endpoint = net::client_endpoint_pinned(pinned).expect("client endpoint");
    let sub = Subscriber::connect(&endpoint, addr)
        .await
        .expect("连接 relay");
    let mut rx = sub
        .subscribe(1, &track, StartMode::LatestGroup, 0)
        .await
        .expect("订阅请求")
        .expect("订阅应成功");

    let mut latencies = Vec::new();
    let mut first_group = None;
    let expect = (TOTAL_GROUPS * FRAMES_PER_GROUP) as usize;
    // 晚加入者收到的帧数更少；以「连续 1.5s 无新帧」判定推流结束。
    let idle = Duration::from_millis(1500);
    loop {
        if latencies.len() >= expect {
            break;
        }
        match tokio::time::timeout(idle, rx.recv()).await {
            Ok(Some(obj)) => {
                first_group.get_or_insert(obj.group_id);
                latencies.push(now_ms().saturating_sub(obj.timestamp_ms));
            }
            Ok(None) | Err(_) => break,
        }
    }
    println!(
        "subscriber {name}: 收到 {} 帧，首帧 group = {:?}{}",
        latencies.len(),
        first_group,
        if first_group.unwrap_or(0) > 0 {
            "（迟到加入 → 从最新 group 开头追赶切入，跳过陈旧内容）"
        } else {
            ""
        }
    );
    latencies
}

/// 延迟摘要：min/avg/p95/max（毫秒）。
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

/// 生成自签名证书（演示部署：客户端钉扎该证书）。
fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("生成自签名证书");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}
