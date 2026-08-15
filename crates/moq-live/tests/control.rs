//! 控制面测试：SUBSCRIBE_ERROR / UNSUBSCRIBE / GOAWAY（loopback，真实 QUIC）。

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moq_live::client::{ControlEvent, Publisher, Subscriber, now_ms};
use moq_live::hub::Hub;
use moq_live::message::StartMode;
use moq_live::net;
use moq_live::relay::Relay;
use moq_live::track::{Object, TrackId};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}

async fn start_relay() -> (Arc<Relay>, std::net::SocketAddr, CertificateDer<'static>) {
    let (certs, key) = self_signed_cert();
    let pinned = certs[0].clone();
    let endpoint = net::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let relay = Arc::new(Relay::new(endpoint, Hub::new(3)));
    {
        let r = Arc::clone(&relay);
        tokio::spawn(async move { r.run().await });
    }
    (relay, addr, pinned)
}

/// 订阅未发布的命名空间 → SUBSCRIBE_ERROR。
#[tokio::test]
async fn subscribe_unknown_namespace_gets_error() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (_relay, addr, pinned) = start_relay().await;
        let ep = net::client_endpoint_pinned(pinned).unwrap();
        let sub = Subscriber::connect(&ep, addr).await.unwrap();
        let track = TrackId::new("no/such-ns", "video");
        let result = sub.subscribe(1, &track, StartMode::LatestGroup, 0).await.unwrap();
        let reason = result.expect_err("应收到 SUBSCRIBE_ERROR");
        println!("SUBSCRIBE_ERROR: {reason}");
        assert!(reason.contains("未发布"));
    })
    .await
    .expect("测试超时");
}

/// UNSUBSCRIBE 后不再收到新 object。
#[tokio::test]
async fn unsubscribe_stops_forwarding() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (_relay, addr, pinned) = start_relay().await;
        let track = TrackId::new("test/unsub", "video");

        let pub_ep = net::client_endpoint_pinned(pinned.clone()).unwrap();
        let publisher = Publisher::connect(&pub_ep, addr).await.unwrap();
        publisher.announce(&track.namespace).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let sub_ep = net::client_endpoint_pinned(pinned).unwrap();
        let sub = Subscriber::connect(&sub_ep, addr).await.unwrap();
        let mut rx = sub
            .subscribe(1, &track, StartMode::NextObject, 0)
            .await
            .unwrap()
            .expect("订阅应成功");

        // 推 group 0：确认能收到。
        let mut gw = publisher.begin_group(&track, 0).await.unwrap();
        for i in 0..3u64 {
            gw.write_object(&Object::new(0, i, 128, now_ms(), Bytes::from_static(b"x")))
                .await
                .unwrap();
        }
        gw.finish();
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("应收到 group 0 的 object");
        }

        // UNSUBSCRIBE → 推 group 1：不应再收到。
        sub.unsubscribe(1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await; // 等 relay 处理
        let mut gw = publisher.begin_group(&track, 1).await.unwrap();
        for i in 0..3u64 {
            gw.write_object(&Object::new(1, i, 128, now_ms(), Bytes::from_static(b"x")))
                .await
                .unwrap();
        }
        gw.finish();
        // 不再收到新 object：通道被关闭（None）或超时（Err）均为正确行为。
        let got = tokio::time::timeout(Duration::from_millis(800), rx.recv()).await;
        assert!(
            !matches!(got, Ok(Some(_))),
            "UNSUBSCRIBE 后不应再收到 object，实际: {got:?}"
        );
    })
    .await
    .expect("测试超时");
}

/// relay 优雅关闭：订阅端收到 GOAWAY 事件。
#[tokio::test]
async fn goaway_on_relay_shutdown() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (relay, addr, pinned) = start_relay().await;
        let ep = net::client_endpoint_pinned(pinned).unwrap();
        let mut sub = Subscriber::connect(&ep, addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await; // 等 relay 注册连接

        relay.shutdown().await;
        let event = tokio::time::timeout(Duration::from_secs(3), sub.events().recv())
            .await
            .expect("应收到 GOAWAY 事件")
            .expect("事件通道不应提前关闭");
        match event {
            ControlEvent::Goaway { reason } => println!("收到 GOAWAY: {reason}"),
        }
    })
    .await
    .expect("测试超时");
}
