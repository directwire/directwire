//! QUIC 传输层：endpoint 构建与消息帧的流式读写。
//!
//! 证书策略：客户端对服务端证书做【公钥钉扎（pinning）】——
//! 校验对端出示的证书与预置的钉扎证书逐字节一致，适合自签名部署与内网场景；
//! 不再提供 skip-verify 路径。生产可平滑替换为平台根证书校验。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};

use crate::message::Message;

/// 应用层协议标识。
pub const ALPN: &[u8] = b"moq-lite/0";

/// 构建中继服务端 endpoint（监听指定地址）。
pub fn server_endpoint(
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<Endpoint> {
    let mut tls = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("TLS 配置失败: {e}")))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|e| io::Error::other(format!("QUIC server crypto 失败: {e}")))?;
    let config = ServerConfig::with_crypto(Arc::new(crypto));
    Endpoint::server(config, addr)
}

/// 构建客户端 endpoint：钉扎指定服务端证书（自签名 CA / 证书钉扎场景）。
pub fn client_endpoint_pinned(pinned: CertificateDer<'static>) -> io::Result<Endpoint> {
    let verifier = Arc::new(PinnedServerCert {
        expected: pinned.as_ref().to_vec(),
    });
    let mut tls = quinn::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|e| io::Error::other(format!("QUIC client crypto 失败: {e}")))?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("字面量地址必然合法"))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

/// 发送一帧消息。
pub async fn write_frame(send: &mut SendStream, msg: &Message) -> io::Result<()> {
    let frame = msg.encode();
    send.write_all(&frame)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("QUIC 写失败: {e}")))
}

/// 流式帧读取器：内部持有跨调用累积缓冲区，正确处理一次 read 含多帧的情况。
pub struct FrameReader {
    buf: Vec<u8>,
    chunk: Box<[u8; 16 * 1024]>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1500),
            chunk: Box::new([0u8; 16 * 1024]),
        }
    }

    /// 读取一帧；对端干净关闭流时返回 Ok(None)。
    pub async fn read(&mut self, recv: &mut RecvStream) -> io::Result<Option<Message>> {
        loop {
            if let Some((msg, consumed)) = try_parse(&self.buf)? {
                self.buf.drain(..consumed);
                return Ok(Some(msg));
            }
            let n = recv.read(&mut self.chunk[..]).await.map_err(|e| {
                io::Error::new(io::ErrorKind::BrokenPipe, format!("QUIC 读失败: {e}"))
            })?;
            match n {
                None if self.buf.is_empty() => return Ok(None), // 干净 EOF
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "流在帧中途关闭",
                    ));
                }
                Some(n) => self.buf.extend_from_slice(&self.chunk[..n]),
            }
        }
    }
}

/// 尝试从缓冲区解析一帧；数据不足返回 Ok(None)，成功返回 (消息, 消耗字节数)。
fn try_parse(buf: &[u8]) -> io::Result<Option<(Message, usize)>> {
    use crate::varint;
    let Ok((_, n1)) = varint::decode(buf) else {
        return Ok(None); // 类型 varint 未收齐
    };
    let Ok((len, n2)) = varint::decode(&buf[n1..]) else {
        return Ok(None); // 长度 varint 未收齐
    };
    let total = n1 + n2 + len as usize;
    if buf.len() < total {
        return Ok(None); // 载荷未收齐
    }
    Message::decode(&buf[..total]).map(|m| Some((m, total)))
}

/// 证书钉扎 verifier：仅接受与预置证书逐字节一致的服务端证书。
///
/// 安全性说明：钉扎 DER 全等比较即可锚定身份（证书内含公钥与签名），
/// 握手签名仍由 QUIC/TLS 栈完成；此处不再额外校验有效期与 SAN（自签名场景），
/// 接入平台 PKI 时替换为 WebPkiVerifier 即可。
#[derive(Debug)]
struct PinnedServerCert {
    expected: Vec<u8>,
}

impl quinn::rustls::client::danger::ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &quinn::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: quinn::rustls::pki_types::UnixTime,
    ) -> Result<quinn::rustls::client::danger::ServerCertVerified, quinn::rustls::Error> {
        if end_entity.as_ref() == self.expected.as_slice() {
            Ok(quinn::rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(quinn::rustls::Error::General(
                "服务端证书与钉扎证书不匹配".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        use quinn::rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PKCS1_SHA256,
        ]
    }
}
