# iroh-vigil 设计文档

对应实现:v0.1.1。

## 背景与意图

运营商对公网 IPv4 的收紧(CGNAT、端口封锁)使"自建固定公网 relay"成为 P2P 网络的中心化软肋。iroh-vigil 把 relay 这个角色**下沉进 gossip 网络**:网络里有公网能力的节点内嵌 iroh-relay 并通过 gossip 广播自己的 relay 公告,客户端通过 gossip 学到 relay 池并动态挂载;发现层用 Mainline DHT(pkarr)全局兜底。

**硬约束(设计必须诚实面对)**:NAT 后的普通节点无法被陌生节点入站连接,所以不能互为 relay;冷启动第一次入群仍需至少一个可达锚点(seed relay / seed 节点 / 公共 DHT)。本设计的目标是把这些锚点做小、做散、可替换,而不是消除。

## 术语

- **锚点**:网络中公网可达的实体,承担"首次握手兜底 + 少量打洞失败流量"。
- **vigil 节点**:运行本库的 iroh endpoint,内嵌 gossip;有公网能力时可内嵌 relay。
- **relay 公告**:一个带签名的消息,声明"EndpointId N 在 RelayUrl U 提供 relay 服务"。

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

```
src/
  lib.rs        // 导出 VigilNode, Builder, RelayPoolEvent, RelayAnnouncement 等
  announce.rs   // RelayAnnouncement: 签名/验签/序列化/过期
  relay.rs      // EmbeddedRelay: spawn iroh_relay::server::Server, 暴露 RelayUrl/证书
  pool.rs       // RelayPool: 收集公告 → 验签 → 信任/回放/新鲜度 → insert_relay/remove_relay
  node.rs       // VigilNode + Builder: 组装 endpoint+relay+gossip+pool, 提供 gossip 应用 API
```

### VigilNode 组装(spawn 流程)

1. `iroh_relay::server::Server::spawn(ServerConfig)`,仅当配置了 `with_embedded_relay`。生产用 TLS(Manual 证书),开发/测试用自签 + 客户端 `ca_roots_config` 定制信任。
2. `Endpoint::builder(presets::Minimal)`:
   - 内嵌 relay 节点的初始 `RelayMap` **只含自己的 relay**——iroh 0.98 仅对 home relay 维持常连,home 必须是自己的 relay,公告的 URL 才可达;`online()` 后再动态补挂 seed relays。
   - 无内嵌 relay 时,map = seed relays + seed 节点地址中的 Relay 传输层;为空则 `RelayMode::Disabled`。
   - `address_lookup`:每节点私有 `MemoryLookup`(承载 seed 节点地址,供 gossip 裸 id 拨号)+ 可选 `DhtAddressLookup`(feature `dht`,默认开)/ `PkarrPublisher::n0_dns()` / `MdnsAddressLookup`(feature `mdns`)。
   - 有 relay 则 `online().await`(默认 30s 超时,`Builder::online_timeout` 可调)。
3. `iroh_gossip::net::Gossip::builder().spawn(endpoint)` + `Router::builder(endpoint).accept(iroh_gossip::ALPN, gossip).spawn()`。
4. 加入控制 topic:`TopicId::from(blake3("iroh-vigil/relay-pool/v1"))`,bootstrap 取 seed 节点 id。
5. 后台任务:公告事件循环(`Received` → 入池;`NeighborUp` → `broadcast_neighbors` 重播已知公告 ≤32 条)、自有公告立即入自己池并广播 + 每 10 分钟 seq+1 重发、每 `ttl/2` 清扫。

### relay 公告(announce.rs)

```rust
struct RelayAnnouncement {
    node_id: EndpointId,     // 公告者(= relay 运营者)
    relay_url: RelayUrl,     // 默认必须 https
    quic_port: Option<u16>,
    seq: u64,                // 单调递增,防回放
    timestamp: u64,          // unix 秒,过期用
}
```

- 线上格式:`[0x01][64B ed25519 签名][postcard 载荷]`,签名覆盖载荷字节。
- 新鲜度:`timestamp + TTL`(默认 30 分钟)过期;时间戳落在当前时刻 5 分钟之外的"未来"同样拒绝,防止未来时间戳永久绕过新鲜度。
- 防回放:同 node_id 只接受更大 seq;seq 以墙钟为底,重启不回退。
- 信任:信任过滤先于验签(`Trust::Only` 拒绝不信任者不消耗 ed25519);验签是接受的唯一门槛。

### RelayPool(pool.rs)

- 状态:`HashMap<RelayUrl, PoolEntry{announcement, wire, first_seen, last_seen}>` + 每公告者最高 seq。
- 入池流水线:解析 → 信任过滤 → 验签 → TTL/未来时间戳 → https-only(可显式放开)→ seq 回放 → 容量(默认 64,超容淘汰最旧 `last_seen`)→ `endpoint.insert_relay` → `Added` 事件。
- 清扫(每 `ttl/2`):过期条目移出池并 `remove_relay`,`Removed` 事件;同时清掉无存活条目者的 seq 记录。
- 并发安全:决策与记账各自在单次写锁内原子完成,锁不跨 await。
- 事件:`mpsc(64)`,满则丢弃不阻塞;当前快照可用 `known()` 查询。

### 冷启动

`Builder::seed_relay(RelayUrl)` 与/或 `Builder::seed_node(EndpointAddr)`。首节点可以 `with_embedded_relay` 自举。DHT 发布使后续节点可通过 EndpointId 直接解析地址,不依赖 seed 常驻。

注意(iroh 0.98 语义):共享同一个 relay **不构成**成员发现路径(无 relay 端点枚举,地址解析仅 DHT/DNS/mdns/内存表)。swarm 形成需要至少一个 `seed_node`(其地址可经对方 home relay 拨号)或可经 DHT 解析的节点 id;seed relay 的角色是传输/驻留锚点与 home 候选。gossip 化的 `AddressLookup` 留给 v2。

## 测试策略

不 mock 协议:单进程内起真实的 iroh-relay 服务器(自签证书)与多个 endpoint,全部走 loopback。单元测试覆盖签名/篡改/过期/未来时间戳/回放/信任/容量/清扫;集成测试覆盖三个核心场景:gossip 学到内嵌 relay、seed relay 死亡后网络自愈(新节点仅凭已知地址入群)、多节点 app topic 全员互通。DHT 用例需要真实外网,标记 `#[ignore]`。

## 已知限制与 v2 方向

- `Trust::Everyone`(默认)有 Sybil 风险,生产建议 `Trust::Only`;信誉/延迟评分留 v2。
- home relay 的粘性选择在真实延迟差异下的行为(localhost 测试中所有延迟近似为 0)需生产观察。
- v2 候选:gossip 化 `AddressLookup`、relay 评分与择优、`RelayPoolEvent::Current` 快照事件。
