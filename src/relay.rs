//! 内嵌 iroh-relay 服务器:有公网能力的 vigil 节点一条配置即可兼任 relay。

use std::net::{Ipv4Addr, SocketAddr};

use iroh::RelayUrl;
use iroh_relay::server::{
    AccessConfig, CertConfig, QuicConfig, RelayConfig as ServerRelayConfig, Server, ServerConfig,
    SpawnError as RelaySpawnError, SupervisorError, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// 内嵌 relay 的绑定方式。
pub enum RelayBind {
    /// 生产:HTTPS + 可选 QUIC 地址发现,证书由调用方提供。
    Tls {
        bind_addr: SocketAddr,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    },
    /// 仅本机开发:明文 HTTP,URL 为 `http://`。
    Http { bind_addr: SocketAddr },
    /// 测试:127.0.0.1 随机端口 + localhost/127.0.0.1/::1 SAN 自签证书。
    #[cfg(feature = "test-utils")]
    SelfSignedTest,
}

/// 内嵌 relay 启动错误。
#[derive(Debug, Error)]
pub enum SpawnError {
    /// iroh-relay 服务器启动失败。
    #[error(transparent)]
    Relay(#[from] RelaySpawnError),
    /// 提供的 TLS 证书/私钥无法组装为 rustls 配置。
    #[error("invalid tls cert/key")]
    Tls(#[from] rustls::Error),
    /// 明文 HTTP 模式不支持 QUIC 地址发现。
    #[error("quic requires tls bind")]
    QuicNeedsTls,
}

/// 一个运行中的内嵌 relay 服务器。
pub struct EmbeddedRelay {
    server: Server,
    url: RelayUrl,
}

impl EmbeddedRelay {
    /// 启动内嵌 relay。`quic` 控制是否同时提供 QUIC 地址发现(需要 TLS)。
    pub async fn spawn(bind: RelayBind, quic: bool) -> Result<Self, SpawnError> {
        let (http_bind_addr, tls, quic_opt) = match bind {
            RelayBind::Tls { bind_addr, certs, key } => {
                let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(rustls::Error::from)?
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key)?;
                let quic_opt = quic.then(|| QuicConfig {
                    bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
                    server_config: server_config.clone(),
                });
                (
                    (Ipv4Addr::LOCALHOST, 0).into(),
                    Some(TlsConfig {
                        https_bind_addr: bind_addr,
                        quic_bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
                        cert: CertConfig::<(), ()>::Manual { certs },
                        server_config,
                    }),
                    quic_opt,
                )
            }
            RelayBind::Http { bind_addr } => {
                if quic {
                    return Err(SpawnError::QuicNeedsTls);
                }
                (bind_addr, None, None)
            }
            #[cfg(feature = "test-utils")]
            RelayBind::SelfSignedTest => {
                let tls_config = iroh_relay::server::testing::tls_config();
                let quic_opt = quic.then(|| QuicConfig {
                    bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
                    server_config: tls_config.server_config.clone(),
                });
                (
                    (Ipv4Addr::LOCALHOST, 0).into(),
                    Some(tls_config),
                    quic_opt,
                )
            }
        };

        let server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(ServerRelayConfig {
                http_bind_addr,
                tls,
                limits: Default::default(),
                key_cache_capacity: Some(1024),
                access: AccessConfig::Everyone,
            }),
            quic: quic_opt,
            metrics_addr: None,
        })
        .await?;

        // `Server::https_url` 仅 test-utils 暴露,这里按同一规则从 https_addr 拼 URL。
        let url: RelayUrl = if let Some(addr) = server.https_addr() {
            format!("https://{addr}").parse().expect("addr renders valid url")
        } else {
            let addr = server.http_addr().expect("http bound");
            format!("http://{addr}").parse().expect("addr renders valid url")
        };
        Ok(Self { server, url })
    }

    /// 本 relay 的客户端可拨地址。
    pub fn relay_url(&self) -> &RelayUrl {
        &self.url
    }

    /// QUIC 地址发现端口,未启用为 `None`。
    pub fn quic_port(&self) -> Option<u16> {
        self.server.quic_addr().map(|addr| addr.port())
    }

    /// 手工配置的证书链(Manual TLS),供客户端信任装配。
    pub fn certificates(&self) -> Option<Vec<CertificateDer<'static>>> {
        self.server.certificates()
    }

    /// 停止服务器。
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        self.server.shutdown().await
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use iroh::endpoint::presets::Minimal;
    use iroh::tls::CaRootsConfig;
    use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode};
    use std::time::Duration;

    #[tokio::test]
    async fn embedded_relay_serves_clients() {
        let relay = EmbeddedRelay::spawn(RelayBind::SelfSignedTest, true)
            .await
            .expect("relay spawns");
        let url = relay.relay_url().clone();
        let quic = relay.quic_port().map(iroh_relay::RelayQuicConfig::new);

        let map = RelayMap::from_iter([RelayConfig::new(url.clone(), quic)]);
        let endpoint = Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Custom(map))
            .ca_roots_config(CaRootsConfig::insecure_skip_verify())
            .bind()
            .await
            .expect("endpoint binds");
        tokio::time::timeout(Duration::from_secs(10), endpoint.online())
            .await
            .expect("online within 10s");

        relay.shutdown().await.expect("clean shutdown");
    }
}
