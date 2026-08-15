//! 证书钉扎测试：正确钉扎可连接，错误钉扎必须在 TLS 握手阶段失败。

use std::time::Duration;

use moq_live::client::Publisher;
use moq_live::hub::Hub;
use moq_live::net;
use moq_live::relay::Relay;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// 自签名证书（仅测试用）。
fn self_signed_cert(cn: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![cn.to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}

#[tokio::test]
async fn pinned_cert_connects_and_wrong_pin_fails() {
    tokio::time::timeout(Duration::from_secs(15), scenario())
        .await
        .expect("钉扎测试超时（15s）");
}

async fn scenario() {
    let (certs, key) = self_signed_cert("localhost");
    let pinned = certs[0].clone();
    let endpoint = net::server_endpoint("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let relay = Relay::new(endpoint, Hub::new(2));
    tokio::spawn(async move { relay.run().await });

    // 1. 钉扎正确证书 → 握手 + SETUP 成功。
    let ep_ok = net::client_endpoint_pinned(pinned.clone()).unwrap();
    Publisher::connect(&ep_ok, addr)
        .await
        .expect("钉扎正确证书应连接成功");

    // 2. 钉扎另一张证书 → TLS 握手必须失败（不能静默放行）。
    let (wrong_certs, _) = self_signed_cert("localhost");
    let ep_bad = net::client_endpoint_pinned(wrong_certs[0].clone()).unwrap();
    let result = Publisher::connect(&ep_bad, addr).await;
    assert!(result.is_err(), "钉扎错误证书必须连接失败");
    match result {
        Err(e) => println!("错误钉扎按预期失败: {e}"),
        Ok(_) => unreachable!(),
    }
}
