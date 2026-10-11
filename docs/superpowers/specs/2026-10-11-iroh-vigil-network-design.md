# iroh-vigil 网络层设计:relay 下沉进 gossip 网

日期: 2026-10-11
状态: 已由用户口头批准方向("把 iroh-gossip 普通节点和 iroh-relay 结合,减少 relay 的公网 IP 依赖,全局开启 DHT"),本文档是该方向的具体化。

## 意图与背景

运营商对公网 IPv4 的收紧(CGNAT、端口封锁)使"自建固定公网 relay"成为 P2P 网络的中心化软肋。iroh-vigil 要把 relay 这个角色**下沉进 gossip 网络**:网络里有公网能力的节点内嵌 iroh-relay 并通过 gossip 广播自己的 relay 公告,客户端通过 gossip 学到 relay 池并动态挂载;发现层用 Mainline DHT(pkarr)全局兜底。

**硬约束(设计必须诚实面对)**: NAT 后的普通节点无法被陌生节点入站连接,所以不能互为 relay;冷启动第一次入群仍需至少一个可达锚点(seed relay / seed 节点 / 公共 DHT)。本设计的目标是把这些锚点做小、做散、可替换,而不是消除。

## 术语

- **锚点**: 网络中公网可达的实体,承担"首次握手兜底 + 少量打洞失败流量"。
- **vigil 节点**: 运行本库的 iroh endpoint,内嵌 gossip;有公网能力时可内嵌 relay。
- **relay 公告**: 一个带签名的消息,声明"NodeId N 在 RelayUrl U 提供 relay 服务"。

## 目标

1. 节点只靠少量 seed(甚至一个)即可入群,入群后所有后续发现都是 P2P 的。
2. relay 池来自 gossip 公告,单个 relay 失效不致命,网络自愈。
3. 有公网能力的节点一条配置即可兼任 relay,不依赖专门运维的服务器。
4. 全局 DHT 发现(pkarr over Mainline),无自有基础设施时也能解析节点地址。
5. 应用层拿到一个简单的 gossip API(广播/订阅任意 topic)。

## 非目标(v1)

- relay 信誉/评分系统(v1 只做新鲜度 + 轮换;延迟评分留 v2)。
- 基于 gossip 的节点地址 lookup(实现 `AddressLookup` trait 的 gossip 后端留 v2;v1 地址解析靠 DHT + DNS + seed)。
- 恶意公告的 Sybil 防御(签名验证有,v1 允许 builder 限制信任的公告者)。
- NAT 内节点的自定义打洞协调器(iroh 自带打洞已够)。

## 架构

crate: `iroh-vigil`(Rust, edition 2024)。依赖: `iroh` 0.98、`iroh-gossip` 0.98、`iroh-relay` 0.98、`tokio`。feature: `dht`(启用 `iroh/address-lookup-pkarr-dht`,默认开)、`mdns`(可选)。

### 模块

```
src/
  lib.rs        // 导出 VigilNode, Builder, RelayPoolEvent, RelayAnnouncement, GossipApi 转发
  announce.rs   // RelayAnnouncement: 签名/验签/序列化/过期
  relay.rs      // EmbeddedRelay: spawn iroh_relay::server::Server, 暴露 RelayUrl/RelayMap entry
  pool.rs       // RelayPool: 收集公告 → 验签 → 评分 → endpoint.insert_relay/remove_relay
  node.rs       // VigilNode + Builder: 组装 endpoint+relay+gossip+pool, 提供 gossip 应用 API
  seed.rs       // seed 解析: NodeAddr 列表 / 已知 relay URL(冷启动用)
```

### VigilNode 组装(iroh 0.98.2 API,已核对源码)

1. `iroh_relay::server::Server::spawn(ServerConfig)` — 仅当配置了 `with_embedded_relay`。生产用 TLS(Manual 证书或 Let'sEncrypt),开发/测试用自签(`iroh_relay::server::testing::self_signed_tls_certs_and_config`)+ 客户端 `Builder::ca_roots_config` 定制信任。
2. `Endpoint::builder()`
   - `.relay_mode(RelayMode::Custom(map))`,map 含 seed relay + 自己内嵌 relay(`iroh::RelayConfig::new(url, Option<RelayQuicConfig>)`)。
   - `.address_lookup(DhtAddressLookup::builder().build()?)`(feature `dht`,发布+解析 Mainline DHT,`AddrFilter::relay_only`)。
   - `.address_lookup(PkarrPublisher::n0_dns()...)` 可选;`.address_lookup(MdnsAddressLookup...)` 可选(feature `mdns`)。
   - 测试/开发再加 `.ca_roots_config(...)`。
   - `.bind()` 后 `endpoint.online().await`。
3. `iroh_gossip::net::Gossip::builder().spawn(endpoint.clone())` + `iroh::protocol::Router::builder(endpoint).accept(iroh_gossip::ALPN, gossip_handle).spawn()`。
4. 加入控制 topic: `topic_pool = TopicId::from(hash("iroh-vigil/relay-pool/v1"))`,`gossip.subscribe(topic_pool, bootstrap_ids)`,bootstrap 取 seed 节点 id。
5. 应用 topic 由调用方随时 `node.gossip().subscribe(topic, bootstrap)`。

### relay 公告(announce.rs)

```rust
struct RelayAnnouncement {
    node_id: EndpointId,     // 公告者(= relay 运营者)
    relay_url: RelayUrl,
    quic_port: Option<u16>,
    seq: u64,                // 单调递增,防回放
    timestamp: u64,          // unix 秒,过期用
}
// 序列化后由公告者 SecretKey 签名,消息 = rmp/len 前缀 + sig(64B) + payload
```

- 验签: `node_id.verify(payload, sig)`(iroh-base Signature)。
- 过期: `timestamp + TTL(默认 30 分钟)`;旧公告重发由每个节点周期性(默认 10 分钟)重播**自己**的公告;对新邻居(NeighborUp 事件)重播**已知的最新**公告集合(上限 32 条,防放大)。
- 防回放: 同 node_id 只接受 seq 更大的。

### RelayPool(pool.rs)

- 状态: `HashMap<RelayUrl, PoolEntry{announcement, first_seen, last_seen}>`。
- 事件: `RelayPoolEvent::Added(RelayAnnouncement)` / `Removed(RelayUrl)` / `Current(Vec<RelayAnnouncement>)`(mpsc 广播给调用方)。
- 挂载策略 v1: 收到 Added → `endpoint.insert_relay(url, Arc(RelayConfig::new(url, quic)))`;过期/失效 → `remove_relay`。自身 home relay 不切换(iroh 自动多 relay);v2 再做延迟测量选优。
- 信任策略 v1: builder 可设 `trust = Everyone | Only(Vec<EndpointId>)`(默认 Everyone,文档标注风险)。

### EmbeddedRelay(relay.rs)

- `EmbeddedRelay::spawn(bind: RelayBindConfig) -> (RelayUrl, RelayMap, Server)`。
- 生产: `RelayBindConfig::Tls { https_bind_addr, certs }`(Manual 证书);也支持 `Http`(仅本地开发,URL 为 http://)。
- QUIC 地址发现(QuicConfig)与 relay HTTP 同证书,默认开。
- 内嵌 relay 的节点同时是 gossip 成员,广播自己的公告 —— 即"relay 下沉进 gossip 网"。

### 冷启动(seed.rs)

`Builder::seed_relay(RelayUrl)`(1 个即可)与/或 `Builder::seed_node(NodeAddr)`。首节点可以是 `with_embedded_relay` 自举。DHT 发布使后续节点可通过 NodeId 直接解析地址,不依赖 seed 常驻。

## 测试计划(参考 iroh 官方测试模式: 进程内 relay + 多 endpoint)

feature `test-utils` 启用 `iroh::test_utils::run_relay_server()` 与 `CaRootsConfig::insecure_skip_verify`。

1. `announce_sign_verify_roundtrip` — 公告签名/验签/篡改拒绝/seq 回放拒绝/过期。
2. `embedded_relay_serves_clients` — spawn embedded relay → 客户端 endpoint 挂其 RelayMap → `endpoint.online()` 成功。
3. `relay_pool_gossip_discovery` — 1 seed relay + 1 vigil 节点带 embedded relay + 2 普通节点:普通节点通过 gossip 学到 embedded relay 并 `insert_relay` 成功(RelayPoolEvent::Added)。
4. `network_survives_seed_relay_death` — 同上拓扑,shutdown seed relay 后,新节点入群 + 全员互通(走 embedded relay)。
5. `gossip_app_topic_broadcast` — 4 节点订阅应用 topic,广播消息全员收到 Event::Broadcast。
6. `dht_publish_resolve`(#[ignore],需真实网络)— 两个 endpoint 用 DhtAddressLookup,按 NodeId 直连。

## 留给实现者的决定

- 公告序列化格式(建议 rmp 或 postcard,保持向后兼容字段顺序)。
- Pool 内部并发结构(tokio::sync::RwLock + watch/mpsc)。
- 重播定时器的实现细节。
- 错误类型组织(thiserror)。
