//! VigilNode:组装 endpoint + 内嵌 relay + gossip Router + RelayPool。

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::presets::Minimal;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_gossip::api::{Event as GossipEvent, GossipSender};
use iroh_gossip::{Gossip, TopicId};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::interval;

use crate::announce::RelayAnnouncement;
use crate::pool::{RelayPool, RelayPoolConfig, RelayPoolEvent};
use crate::relay::{EmbeddedRelay, RelayBind};

/// 公告 gossip topic 的标签,`TopicId = blake3(label)`。
pub const POOL_TOPIC_LABEL: &[u8] = b"iroh-vigil/relay-pool/v1";

/// 自广播周期(spec 值)。
const REBROADCAST_PERIOD: Duration = Duration::from_secs(10 * 60);
/// NeighborUp 重播上限(spec 值)。
const REPLAY_LIMIT: usize = 32;

fn pool_topic() -> TopicId {
    TopicId::from_bytes(*blake3::hash(POOL_TOPIC_LABEL).as_bytes())
}

pub(crate) fn system_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// VigilNode 组装/启动错误。
#[derive(Debug, thiserror::Error)]
pub enum VigilError {
    /// endpoint 绑定失败。
    #[error("endpoint bind failed")]
    Bind(#[from] iroh::endpoint::BindError),
    /// 内嵌 relay 启动失败。
    #[error("embedded relay failed")]
    Relay(#[from] crate::relay::SpawnError),
    /// 地址服务(DHT/pkarr)构建失败。
    #[error("address lookup build failed")]
    AddressLookup(#[from] iroh::address_lookup::AddressLookupBuilderError),
    /// 加入 pool topic 失败。
    #[error("gossip subscribe failed")]
    Subscribe(#[from] iroh_gossip::api::ApiError),
    /// router 关闭出错。
    #[error("router shutdown failed")]
    Router(#[from] tokio::task::JoinError),
    /// gossip 关闭出错。
    #[error("gossip shutdown failed")]
    Gossip(#[from] iroh_gossip::net::Error),
    /// 内嵌 relay 关闭出错。
    #[error("relay shutdown failed")]
    RelayShutdown(#[from] iroh_relay::server::SupervisorError),
}

/// [`Builder`] 的缺省 DHT 状态:开(`dht` feature)。
#[cfg(feature = "dht")]
const DEFAULT_DHT: bool = true;
#[cfg(not(feature = "dht"))]
const DEFAULT_DHT: bool = false;

/// VigilNode 构造器。
#[derive(Debug, Default)]
pub struct Builder {
    secret_key: Option<SecretKey>,
    seed_relays: Vec<RelayUrl>,
    seed_nodes: Vec<EndpointAddr>,
    embedded_relay: Option<RelayBind>,
    #[cfg(feature = "dht")]
    dht: bool,
    pkarr_n0: bool,
    #[cfg(feature = "mdns")]
    mdns: bool,
    trust: Option<crate::pool::Trust>,
    pool_config: Option<RelayPoolConfig>,
    #[cfg(feature = "test-utils")]
    insecure_skip_cert_verify: bool,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "dht")]
            dht: DEFAULT_DHT,
            ..Default::default()
        }
    }

    /// 指定节点密钥(缺省随机生成)。
    pub fn secret_key(&mut self, sk: SecretKey) -> &mut Self {
        self.secret_key = Some(sk);
        self
    }

    /// 冷启动 seed relay:作为本节点的传输/驻留锚点(home relay 候选)。
    ///
    /// 注意(iroh 0.98 语义):共享同一个 relay **不构成**成员发现路径——
    /// 仅配 seed relay 的节点不会因此加入 pool topic 的 swarm。
    /// swarm 形成需要至少一个 [`Builder::seed_node`](已知节点地址,可经其 relay
    /// 传输层拨号),或可经 DHT 解析的节点 id。
    pub fn seed_relay(&mut self, url: RelayUrl) -> &mut Self {
        self.seed_relays.push(url);
        self
    }

    /// 冷启动 seed 节点(地址进 MemoryLookup,供 gossip 拨号解析)。
    pub fn seed_node(&mut self, addr: EndpointAddr) -> &mut Self {
        self.seed_nodes.push(addr);
        self
    }

    /// 内嵌一个 relay 服务器并广播其公告。
    pub fn with_embedded_relay(&mut self, bind: RelayBind) -> &mut Self {
        self.embedded_relay = Some(bind);
        self
    }

    /// Mainline DHT 地址发布/解析(feature `dht`,默认开)。
    #[cfg(feature = "dht")]
    pub fn discovery_dht(&mut self, on: bool) -> &mut Self {
        self.dht = on;
        self
    }

    /// n0 公共 pkarr DNS 发布(默认关)。
    pub fn discovery_pkarr_n0(&mut self, on: bool) -> &mut Self {
        self.pkarr_n0 = on;
        self
    }

    /// mDNS 局域网发现(feature `mdns`,默认关)。
    #[cfg(feature = "mdns")]
    pub fn discovery_mdns(&mut self, on: bool) -> &mut Self {
        self.mdns = on;
        self
    }

    /// 公告者信任策略。
    pub fn trust(&mut self, trust: crate::pool::Trust) -> &mut Self {
        self.trust = Some(trust);
        self
    }

    /// 池配置。
    pub fn pool_config(&mut self, cfg: RelayPoolConfig) -> &mut Self {
        self.pool_config = Some(cfg);
        self
    }

    /// 测试:跳过 relay 证书校验。
    #[cfg(feature = "test-utils")]
    pub fn insecure_skip_cert_verify(&mut self) -> &mut Self {
        self.insecure_skip_cert_verify = true;
        self
    }

    /// 组装并启动。顺序固定:内嵌 relay → endpoint → gossip/router → pool topic → 后台任务。
    pub async fn spawn(&mut self) -> Result<VigilNode, VigilError> {
        let secret_key = self.secret_key.take().unwrap_or_else(SecretKey::generate);

        // 1. 内嵌 relay 先起,拿到自己的公告 URL。
        let embedded = match self.embedded_relay.take() {
            Some(bind) => Some(EmbeddedRelay::spawn(bind, true).await?),
            None => None,
        };

        // 2. RelayMap 组装。
        //
        // iroh 只对 home relay 维持常连,其余 relay 按需连接。因此内嵌 relay 的节点
        // 初始 map 只挂自己的 relay——保证 home = own,公告的 URL 才可达;
        // seed relays 在 online 后再动态补挂(仅出站按需使用,home 粘住 own)。
        // seed 节点地址中的 Relay 传输层也进 map(如 D 仅凭 A 的 relay 入网的场景),
        // 否则该节点 relay 被禁用,无法经 relay 传输层拨号。
        let own_relay_config = embedded.as_ref().map(|relay| {
            RelayConfig::new(
                relay.relay_url().clone(),
                relay.quic_port().map(iroh_relay::RelayQuicConfig::new),
            )
        });
        let mut extra_relays: Vec<RelayConfig> = Vec::new();
        for url in &self.seed_relays {
            extra_relays.push(RelayConfig::new(url.clone(), None));
        }
        for addr in &self.seed_nodes {
            for transport in &addr.addrs {
                if let iroh::TransportAddr::Relay(url) = transport {
                    extra_relays.push(RelayConfig::new(url.clone(), None));
                }
            }
        }
        let initial_map: Vec<RelayConfig> = match &own_relay_config {
            Some(own) => vec![own.clone()],
            None => extra_relays.clone(),
        };
        let has_relays = !initial_map.is_empty();

        // 3. seed 节点地址进 MemoryLookup。
        let memory_lookup = MemoryLookup::new();
        for addr in &self.seed_nodes {
            memory_lookup.add_endpoint_info(addr.clone());
        }

        // 4. endpoint。
        let mut builder = Endpoint::builder(Minimal).secret_key(secret_key.clone());
        builder = if has_relays {
            builder.relay_mode(RelayMode::Custom(RelayMap::from_iter(initial_map)))
        } else {
            builder.relay_mode(RelayMode::Disabled)
        };
        builder = builder.address_lookup(memory_lookup);
        #[cfg(feature = "dht")]
        if self.dht {
            builder = builder.address_lookup(iroh::address_lookup::DhtAddressLookup::builder());
        }
        if self.pkarr_n0 {
            builder = builder.address_lookup(iroh::address_lookup::PkarrPublisher::n0_dns());
        }
        #[cfg(feature = "mdns")]
        if self.mdns {
            builder = builder
                .address_lookup(iroh::address_lookup::MdnsAddressLookup::builder());
        }
        #[cfg(feature = "test-utils")]
        if self.insecure_skip_cert_verify {
            builder = builder.ca_roots_config(iroh::tls::CaRootsConfig::insecure_skip_verify());
        }
        let endpoint = builder.bind().await?;

        // 5. 有 relay 则等在线。
        if has_relays {
            endpoint.online().await;
        }
        // 内嵌 relay 节点在 home 确定为自己的 relay 后,补挂其余 relay。
        if own_relay_config.is_some() {
            for config in &extra_relays {
                endpoint
                    .insert_relay(config.url.clone(), std::sync::Arc::new(config.clone()))
                    .await;
            }
        }

        // 6. gossip + router。
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        // 7. pool topic。
        let bootstrap: Vec<EndpointId> =
            self.seed_nodes.iter().map(|a| a.id).collect();
        let topic = gossip.subscribe(pool_topic(), bootstrap).await?.split();
        let (pool_sender, pool_receiver) = topic;

        // 8. pool + 事件。
        let mut pool_config = self.pool_config.clone().unwrap_or_default();
        if let Some(trust) = self.trust.clone() {
            pool_config.trust = trust;
        }
        let ttl = pool_config.ttl;
        let (pool, relay_events) = RelayPool::new(endpoint.clone(), pool_config);

        // 9. 后台任务。
        let mut tasks = JoinSet::new();
        let neighbors: Arc<RwLock<HashSet<EndpointId>>> = Arc::new(RwLock::new(HashSet::new()));

        // (a) pool topic 事件循环。
        {
            let pool = pool.clone();
            let neighbors = neighbors.clone();
            let sender = pool_sender.clone();
            let mut receiver = pool_receiver;
            tasks.spawn(async move {
                while let Some(ev) = receiver.next().await {
                    match ev {
                        Ok(GossipEvent::NeighborUp(_id)) => {
                            neighbors.write().expect("neighbors lock").insert(_id);
                            // 向新邻居重播已知公告(含自己的——已入自己的池)。
                            let replay = pool.replay_set();
                            for wire in replay.into_iter().take(REPLAY_LIMIT) {
                                let _ = sender.broadcast(wire).await;
                            }
                        }
                        Ok(GossipEvent::NeighborDown(id)) => {
                            neighbors.write().expect("neighbors lock").remove(&id);
                        }
                        Ok(GossipEvent::Received(msg)) => {
                            let _ = pool.handle_wire(&msg.content, system_now_unix()).await;
                        }
                        Ok(GossipEvent::Lagged) | Err(_) => {}
                    }
                }
            });
        }

        // (b) 自己的公告:立即入自己的池并广播(gossip 在入群前排队),
        // 之后每 10 分钟 seq+1 重发。
        if let Some(relay) = &embedded {
            let url = relay.relay_url().clone();
            let quic_port = relay.quic_port();
            let sk = secret_key.clone();
            let sender = pool_sender.clone();
            let pool = pool.clone();
            tasks.spawn(async move {
                // seq 以墙钟为底:重启(同 key)后 seq 仍单调递增,
                // 否则会被对端按回放拒到旧 seq 追平为止。
                let mut seq: u64 = system_now_unix();
                let mut tick = interval(REBROADCAST_PERIOD);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    seq += 1;
                    let ann =
                        RelayAnnouncement::new(sk.public(), url.clone(), quic_port, seq, system_now_unix());
                    let wire = ann.sign(&sk);
                    // 先入自己的池:replay_set 才会包含自己,晚加入的邻居也能学到。
                    let _ = pool.handle_wire(&wire, system_now_unix()).await;
                    let _ = sender.broadcast(wire).await;
                    tick.tick().await;
                }
            });
        }

        // (c) 每 ttl/2 清扫。
        {
            let pool = pool.clone();
            tasks.spawn(async move {
                let period = ttl.max(Duration::from_secs(2)) / 2;
                let mut tick = interval(period);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    pool.sweep(system_now_unix()).await;
                }
            });
        }

        Ok(VigilNode {
            endpoint,
            gossip,
            router,
            pool_sender,
            neighbors,
            relay_events: Some(relay_events),
            embedded,
            tasks,
        })
    }
}

/// 一个运行中的 vigil 节点。
pub struct VigilNode {
    endpoint: Endpoint,
    gossip: Gossip,
    router: Router,
    #[allow(dead_code)] // shutdown 时经 drop 终止广播
    pool_sender: GossipSender,
    neighbors: Arc<RwLock<HashSet<EndpointId>>>,
    relay_events: Option<mpsc::Receiver<RelayPoolEvent>>,
    embedded: Option<EmbeddedRelay>,
    tasks: JoinSet<()>,
}

impl VigilNode {
    /// 本节点 id。
    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// 底层 endpoint。
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// gossip API(`Deref` 到 `GossipApi`:subscribe/broadcast 任意应用 topic)。
    pub fn gossip(&self) -> &Gossip {
        &self.gossip
    }

    /// pool topic 当前邻居(应用 topic 引导用)。
    pub fn bootstrap_ids(&self) -> Vec<EndpointId> {
        self.neighbors
            .read()
            .expect("neighbors lock")
            .iter()
            .copied()
            .collect()
    }

    /// 取走池事件流(只能取一次)。
    pub fn take_relay_events(&mut self) -> mpsc::Receiver<RelayPoolEvent> {
        self.relay_events.take().expect("relay events taken once")
    }

    /// 内嵌 relay 的 URL,未内嵌为 `None`。
    pub fn embedded_relay_url(&self) -> Option<&RelayUrl> {
        self.embedded.as_ref().map(|r| r.relay_url())
    }

    /// 停止节点:后台任务、gossip(优雅离群)、router、内嵌 relay。
    pub async fn shutdown(mut self) -> Result<(), VigilError> {
        self.tasks.abort_all();
        // gossip 先停:发 Disconnect 优雅离群;router 随后的 handler shutdown
        // 会再调一次 gossip.shutdown(),其内部仅 warn,不传染错误。
        self.gossip.shutdown().await?;
        self.router.shutdown().await?;
        if let Some(relay) = self.embedded {
            relay.shutdown().await?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::StreamExt;
    use iroh::EndpointAddr;
    use iroh::test_utils::run_relay_server;
    use iroh_gossip::TopicId;
    use std::time::Duration;

    // 测试环境可能无外网,关闭 DHT 保持封闭。
    fn builder() -> Builder {
        let mut b = Builder::new();
        #[cfg(feature = "dht")]
        b.discovery_dht(false);
        b
    }

    #[tokio::test]
    async fn node_spawns_without_relays() {
        let node = builder().spawn().await.expect("spawn without relays");
        assert!(node.embedded_relay_url().is_none());
        let _ = node.node_id();
        let _ = node.endpoint();
        node.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn node_joins_seed_and_broadcasts_app_topic() {
        let (_seed_map, seed_url, _seed_guard) = run_relay_server().await.expect("seed relay");

        let a = builder()
            .seed_relay(seed_url.clone())
            .insecure_skip_cert_verify()
            .spawn()
            .await
            .expect("node a spawns");
        let b = builder()
            .seed_relay(seed_url.clone())
            .seed_node(EndpointAddr::new(a.node_id()).with_relay_url(seed_url.clone()))
            .insecure_skip_cert_verify()
            .spawn()
            .await
            .expect("node b spawns");

        let app_topic = TopicId::from_bytes([7u8; 32]);
        let sub_a = a.gossip().subscribe(app_topic, vec![]).await.expect("a subscribes");
        let (sink_a, _stream_a) = sub_a.split();
        let sub_b = b.gossip().subscribe(app_topic, vec![a.node_id()]).await.expect("b subscribes");
        let (_sink_b, mut recv_b) = sub_b.split();
        tokio::time::timeout(Duration::from_secs(10), recv_b.joined())
            .await
            .expect("b joins within 10s")
            .expect("join ok");

        sink_a.broadcast(Bytes::from_static(b"ping")).await.expect("broadcast");
        let mut got = false;
        let deadline = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(ev) = recv_b.next().await {
                if let iroh_gossip::api::Event::Received(msg) = ev.expect("stream ok")
                    && msg.content.as_ref() == b"ping"
                {
                    got = true;
                    break;
                }
            }
        })
        .await;
        deadline.expect("events within 10s");
        assert!(got, "b must receive a's app broadcast");

        a.shutdown().await.expect("a shutdown");
        b.shutdown().await.expect("b shutdown");
    }
}
