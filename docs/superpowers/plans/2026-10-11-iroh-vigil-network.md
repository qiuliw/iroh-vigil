# iroh-vigil 网络层(relay 下沉进 gossip 网)实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 iroh-gossip 普通节点与内嵌 iroh-relay 结合:有公网能力的节点内嵌 relay 并经 gossip 广播,其他节点动态挂载,配全局 DHT 发现,减少对固定公网 relay 的依赖。

**Architecture:** `VigilNode` 组装 endpoint + 内嵌 relay + gossip Router + RelayPool;relay 公告(签名+TTL+seq)在专用 gossip topic(`iroh-vigil/relay-pool/v1`)内传播;`Endpoint::insert_relay/remove_relay` 动态挂载;`DhtAddressLookup`(Mainline DHT)做全局地址发布/解析。

**Tech Stack:** Rust 2024,iroh 0.98.2 / iroh-gossip 0.98.0 / iroh-relay 0.98.0,tokio,postcard,blake3,thiserror,futures。

**Spec:** `docs/superpowers/specs/2026-10-11-iroh-vigil-network-design.md`

## Global Constraints

- 依赖版本锁定:`iroh = 0.98.2`、`iroh-gossip = 0.98.0`、`iroh-relay = 0.98`(features: iroh-relay 必须含 `server`)。
- 新增依赖仅限:`tokio`(full)、`postcard`、`blake3`、`thiserror`、`futures`、`serde`(derive)。
- crate features:`default = ["dht"]`;`dht = ["iroh/address-lookup-pkarr-dht"]`;`mdns = ["iroh/address-lookup-mdns"]`;`test-utils = ["iroh/test-utils", "iroh-gossip/test-utils", "iroh-relay/test-utils"]`。
- 公告 TTL 默认 30 分钟,自广播周期 10 分钟,NeighborUp 重播上限 32 条(spec 值)。
- 池默认上限 64 条(spec 值)。
- 所有公开 async API 的 future `Send`;`#![forbid(unsafe_code)]`。
- 测试遵循 iroh 官方模式:进程内 relay server(`iroh::test_utils::run_relay_server`)+ 多 endpoint + 自签证书信任(`CaRootsConfig::insecure_skip_verify`,仅 `cfg(feature = "test-utils")` 暴露的 builder 项)。

## Review Focus

1. **伪造/篡改公告**(签名不匹配):必须被静默拒绝,不进池、不 `insert_relay` — Task 2 篡改测试 + Task 4 `handle_bytes` 拒绝路径测试。
2. **过期公告**:decode 直接拒绝;已入池的由 sweep 移除并 `remove_relay` — Task 2 过期测试 + Task 4 sweep 测试。
3. **seq 回放**(重放旧公告):同公告者低 seq 被忽略 — Task 4 回放测试。
4. **不受信任的公告者**(`Trust::Only`):被忽略 — Task 4 trust 测试。
5. **垃圾字节/超长消息喂进 gossip topic**:decode 出错不 panic、不污染池 — Task 2 garbage-in 测试 + Task 4 garbage 路径。

---

### Task 1: crate 脚手架(features + 依赖 + 空模块)

**Files:**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`

**Interfaces:**
- Produces: 模块声明 `mod announce; mod relay; mod pool; mod node;` 与 `#![forbid(unsafe_code)]`;后续任务往这些文件填内容。

- [ ] **Step 1: 改写 `Cargo.toml`**

deps:`iroh`(0.98.2, features `["test-utils"]` 移到 dev)、`iroh-gossip`(0.98, test-utils 移到 dev)、`iroh-relay`(0.98, features `["server"]`)、`tokio`(full)、`serde`(derive)、`postcard`、`blake3`、`thiserror`、`futures`。dev-deps:本 crate 自身 `test-utils` feature(`iroh = { path = ".", features=["test-utils"] }` 不适用于自身——用 `[dev-dependencies]` 中重复依赖开启不同 feature 不行,正确做法:`[features] test-utils = [...]` + 测试命令带 `--features test-utils`)。features 按全局约束。

- [ ] **Step 2: 写 `src/lib.rs`**

`#![forbid(unsafe_code)]` + `mod announce; mod node; mod pool; mod relay;` + 各模块先放占位 `pub struct Placeholder;`(后续任务删除),`src/main.rs` 保留 hello。

- [ ] **Step 3: 验证编译**

Run: `cargo check && cargo check --features test-utils && cargo check --no-default-features`
Expected: 三者均 0 error(warning 可有)。

- [ ] **Step 4: Commit** `chore: scaffold crate with features and deps`

### Task 2: RelayAnnouncement(announce.rs)

**Files:**
- Create: `src/announce.rs`
- Test: `src/announce.rs` 内 `#[cfg(test)] mod tests`(纯单元测试,无网络)

**Interfaces:**
- Produces(Task 4/5 依赖,精确签名):

```rust
pub const DEFAULT_TTL: core::time::Duration; // 30 min
pub struct RelayAnnouncement { pub node_id: EndpointId, pub relay_url: RelayUrl,
    pub quic_port: Option<u16>, pub seq: u64, pub timestamp: u64 }  // timestamp = unix 秒
impl RelayAnnouncement {
    pub fn new(node_id: EndpointId, relay_url: RelayUrl, quic_port: Option<u16>, seq: u64, timestamp: u64) -> Self;
    pub fn sign(&self, secret_key: &SecretKey) -> bytes::Bytes;   // 线上格式: [0x01][sig 64B][postcard(self)]
    pub fn decode(bytes: &[u8], now_unix: u64) -> Result<Self, AnnounceError>; // 验签+TTL(DEFAULT_TTL)
    pub fn is_expired(&self, now_unix: u64) -> bool;
    pub fn verify_signature(bytes: &[u8]) -> Result<Self, AnnounceError>;       // 只验签不过期(pool 重验用)
}
pub enum AnnounceError { BadFormat, BadSignature, Expired }  // thiserror
```

- [ ] **Step 1: 写失败测试**(5 个)`roundtrip_sign_decode` / `tampered_payload_rejected`(改 payload 一字节)/ `wrong_key_rejected`(另一把 key 验)/ `expired_rejected`(timestamp = now - 3600)/ `garbage_rejected`(随机短字节)。
- [ ] **Step 2: `cargo test --lib announce` 确认编译失败(类型不存在)**
- [ ] **Step 3: 实现** — serde derive 于结构体(`EndpointId`、`RelayUrl` 均已实现 Serialize);签名用 `SecretKey::sign(&self, msg)` / `PublicKey::verify(&self, msg, &Signature)`(iroh-base 0.98 已核对);wire 帧如上;`Signature::to_bytes()/from_bytes(&[u8;64])`。
- [ ] **Step 4: `cargo test --lib announce` PASS**
- [ ] **Step 5: Commit** `feat: signed relay announcements with TTL`

### Task 3: EmbeddedRelay(relay.rs)

**Files:**
- Create: `src/relay.rs`
- Test: `src/relay.rs` 内 `#[cfg(test)] mod tests`(feature `test-utils`)

**Interfaces:**
- Produces(Task 5 依赖):

```rust
pub enum RelayBind {
    Tls { bind_addr: SocketAddr, certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static> },
    Http { bind_addr: SocketAddr },                     // 仅本机开发
    #[cfg(feature = "test-utils")] SelfSignedTest,      // 127.0.0.1:0 自签(localhost/127.0.0.1 SAN)
}
pub struct EmbeddedRelay { /* server + url + quic_port */ }
impl EmbeddedRelay {
    pub async fn spawn(bind: RelayBind, quic: bool) -> Result<Self, SpawnError>; // 包装 iroh_relay::server::SpawnError
    pub fn relay_url(&self) -> &RelayUrl;
    pub fn quic_port(&self) -> Option<u16>;
    pub fn certificates(&self) -> Option<Vec<CertificateDer<'static>>>;  // Server::certificates()
    pub async fn shutdown(self) -> Result<(), SupervisorError>;
}
```

- [ ] **Step 1: 写失败测试** `embedded_relay_serves_clients`:spawn `SelfSignedTest` → 客户端 `Endpoint::builder(presets::Minimal).relay_mode(Custom(RelayMap::from_iter([RelayConfig::new(url, quic)])))` + `.ca_roots_config(CaRootsConfig::insecure_skip_verify())` → `endpoint.online()` 在 10s 内返回。
- [ ] **Step 2: 跑测确认失败**
- [ ] **Step 3: 实现** — 组装 `ServerConfig { relay: Some(RelayConfig { http_bind_addr, tls: Some(TlsConfig{https_bind_addr, quic_bind_addr, cert: CertConfig::Manual{certs}, server_config}), limits: Default, key_cache_capacity: Some(1024), access: AccessConfig::Everyone }), quic, metrics_addr: None }`,`Server::spawn` 后 `https_url()`。`SelfSignedTest` 走 `iroh_relay::server::testing::tls_config()`;`Tls` 手工构造 `rustls::ServerConfig`(ring provider + `with_single_cert`)。
- [ ] **Step 4: `cargo test --features test-utils --lib relay` PASS**
- [ ] **Step 5: Commit** `feat: embedded relay server wrapper`

### Task 4: RelayPool(pool.rs)

**Files:**
- Create: `src/pool.rs`
- Test: `src/pool.rs` 内 `#[cfg(test)] mod tests`(feature `test-utils`;`insert_relay` 不需要真实网络)

**Interfaces:**
- Consumes: `RelayAnnouncement::{sign, decode, verify_signature}`(Task 2)。
- Produces(Task 5 依赖):

```rust
pub enum RelayPoolEvent { Added(RelayAnnouncement), Removed(RelayUrl) }
pub enum Trust { Everyone, Only(Vec<EndpointId>) }   // Default = Everyone
pub struct RelayPoolConfig { pub ttl: Duration /*30m*/, pub max_entries: usize /*64*/, pub trust: Trust }
pub struct RelayPool { /* Arc<Inner> */ }
impl RelayPool {
    pub fn new(endpoint: Endpoint, config: RelayPoolConfig) -> (Self, mpsc::Receiver<RelayPoolEvent>);
    pub async fn handle_wire(&self, bytes: &[u8], now_unix: u64) -> Result<Option<RelayAnnouncement>, PoolError>;
        // decode → trust 检查 → seq 回放检查 → 容量淘汰(最旧 last_seen)→ endpoint.insert_relay → 事件
    pub fn known(&self) -> Vec<RelayAnnouncement>;
    pub async fn sweep(&self, now_unix: u64);   // 过期 → endpoint.remove_relay → Removed 事件
    pub fn replay_set(&self) -> Vec<bytes::Bytes>;  // 最新 ≤32 条公告的原始 wire(NeighborUp 重播)
}
pub enum PoolError { Announce(AnnounceError), Untrusted, Stale, CapacityEvicted /*…*/ }
```

- [ ] **Step 1: 写失败测试**(用真 `Endpoint`,feature test-utils,RelayMode::Disabled 即可:`Endpoint::builder(presets::Minimal).relay_mode(Disabled).bind()`):
  `adds_valid_announcement_and_emits_event` / `rejects_stale_seq`(同公告者先 seq=5 再 seq=3 → 第二次 Err 且 known 不变)/ `rejects_untrusted_announcer`(Trust::Only([other]))/ `sweep_removes_expired`(now 前推)/ `garbage_wire_rejected`。
- [ ] **Step 2: 跑测确认失败**
- [ ] **Step 3: 实现** — 内部 `RwLock<HashMap<RelayUrl, PoolEntry>>` + `HashMap<EndpointId, u64>`(每公告者最高 seq);`insert_relay(url, Arc::new(iroh::RelayConfig::new(url, quic_port.map(RelayQuicConfig::new))))`;事件走 `mpsc::channel(64)`,满则丢事件不阻塞。
- [ ] **Step 4: `cargo test --features test-utils --lib pool` PASS**
- [ ] **Step 5: Commit** `feat: relay pool with dynamic insert/remove`

### Task 5: VigilNode + Builder(node.rs, lib.rs 导出)

**Files:**
- Create: `src/node.rs`
- Modify: `src/lib.rs`(导出公共类型,删占位)

**Interfaces:**
- Consumes: Task 2/3/4 全部;`Gossip::builder().spawn(endpoint)`、`Router::builder(endpoint).accept(iroh_gossip::ALPN, gossip.clone()).spawn()`、`gossip.subscribe(topic, bootstrap).await?.split()`、`GossipReceiver: Stream`(futures `StreamExt::next`)。
- Produces(应用层 API):

```rust
pub const POOL_TOPIC_LABEL: &[u8] = b"iroh-vigil/relay-pool/v1";
pub struct Builder { /* 如下 builder 方法 */ }
impl Builder {
    pub fn secret_key(&mut self, sk: SecretKey) -> &mut Self;
    pub fn seed_relay(&mut self, url: RelayUrl) -> &mut Self;
    pub fn seed_node(&mut self, addr: EndpointAddr) -> &mut Self;
    pub fn with_embedded_relay(&mut self, bind: RelayBind) -> &mut Self;
    #[cfg(feature = "dht")] pub fn discovery_dht(&mut self, on: bool) -> &mut Self;   // 默认 true
    pub fn discovery_pkarr_n0(&mut self, on: bool) -> &mut Self;                       // 默认 false
    #[cfg(feature = "mdns")] pub fn discovery_mdns(&mut self, on: bool) -> &mut Self;  // 默认 false
    pub fn trust(&mut self, trust: Trust) -> &mut Self;
    pub fn pool_config(&mut self, cfg: RelayPoolConfig) -> &mut Self;
    #[cfg(feature = "test-utils")] pub fn insecure_skip_cert_verify(&mut self) -> &mut Self;
    pub async fn spawn(&mut self) -> Result<VigilNode, VigilError>;
}
pub struct VigilNode { /* … */ }
impl VigilNode {
    pub fn node_id(&self) -> EndpointId;
    pub fn endpoint(&self) -> &Endpoint;
    pub fn gossip(&self) -> &iroh_gossip::Gossip;        // Deref 到 GossipApi: subscribe/broadcast
    pub fn bootstrap_ids(&self) -> Vec<EndpointId>;       // pool topic 当前邻居(应用 topic 引导用)
    pub fn take_relay_events(&mut self) -> mpsc::Receiver<RelayPoolEvent>;
    pub fn embedded_relay_url(&self) -> Option<&RelayUrl>;
    pub async fn shutdown(self) -> Result<(), VigilError>; // router.shutdown、gossip.shutdown、relay.shutdown
}
pub enum VigilError { /* Bind/Spawn/Join 等 thiserror 包装 */ }
```

spawn 流程(顺序固定):secret_key 默认 `SecretKey::generate()` → 内嵌 relay 先起(拿到自己的公告 URL)→ RelayMap = seed relays + 自己内嵌 relay(`RelayMap::from_iter`),为空则 `RelayMode::Disabled` 且跳过 `online()` → `Endpoint::builder(presets::Minimal)` + relay_mode + address_lookup(dht:`DhtAddressLookup::builder()`;pkarr:`PkarrPublisher::n0_dns()`;mdns 同理)+ 测试的 ca_roots → `bind()` → 有 relay 则 `online().await` → gossip + Router → pool topic `TopicId::from(blake3::hash(POOL_TOPIC_LABEL).as_bytes() 拷贝成 [u8;32])`,bootstrap = seed_node ids → RelayPool::new → JoinSet 任务:(a) pool topic 事件循环(`Received` → `pool.handle_wire`(now=系统钟);`NeighborUp` → `sender.broadcast` 逐条重播 `pool.replay_set()`;`Lagged` → 忽略)、(b) 自己的公告入群后立即广播一次 + 每 10 分钟重发(seq 单调递增)、(c) 每 `ttl/2` `pool.sweep(now)`。

- [ ] **Step 1: 写失败测试**(feature test-utils):
  `node_spawns_without_relays`(无 seed、无内嵌 → spawn 成功,RelayMode Disabled 不挂死,shutdown 干净);
  `node_joins_seed_and_broadcasts_app_topic`(用 `iroh::test_utils::run_relay_server()` 作 seed;两节点 `insecure_skip_cert_verify`;app topic = `TopicId::from([7u8;32])`;A broadcast "ping" → B 收到)。
- [ ] **Step 2: 跑测确认失败**
- [ ] **Step 3: 实现 node.rs + lib.rs 导出**(删除 Task 1 占位)。
- [ ] **Step 4: `cargo test --features test-utils --lib node` PASS**
- [ ] **Step 5: Commit** `feat: VigilNode assembling endpoint+relay+gossip+pool`

### Task 6: 集成测试(tests/network.rs,核心场景)

**Files:**
- Create: `tests/network.rs`(均 `#![cfg(feature = "test-utils")]`)

**Interfaces:**
- Consumes: `VigilNode`/`Builder`/`RelayBind::SelfSignedTest`/`RelayPoolEvent`/`iroh::test_utils::run_relay_server`。

- [ ] **Step 1: 写 `relay_pool_gossip_discovery`**(spec 测试 3)— 1 seed relay(`run_relay_server`)+ A(内嵌 SelfSignedTest relay,seed=seed_url)+ B、C(纯节点,seed=seed_url);轮询 B 的 `take_relay_events()` ≤20s 收到 `Added(ann)` 且 `ann.relay_url == A.embedded_relay_url()`;C 同样收到。
- [ ] **Step 2: 写 `network_survives_seed_relay_death`**(spec 测试 4)— 同拓扑;先确认 B、C 学到 A 的 relay → `seed_server.shutdown().await` → app topic 上 A broadcast → B、C 仍收到(走 A 的内嵌 relay);再起新节点 D:**无 seed relay**,仅 `seed_node(EndpointAddr { id: A.node_id(), addrs: BTreeSet::from([TransportAddr::Relay(A_relay_url)]) })` → D 加入 pool topic、学到公告、收到 app broadcast。
- [ ] **Step 3: 写 `gossip_app_topic_broadcast`**(spec 测试 5)— 4 节点同一 seed;每节点广播 1 条 → 断言每节点收到其它 3 条(按 content 前缀区分)。
- [ ] **Step 4: 写 `dht_publish_resolve`**(spec 测试 6,`#[ignore = "needs real internet"]`)— 两个 endpoint 仅 `discovery_dht(true)` + `RelayMode::Disabled`,A spawn 后 sleep 2s(等待 DHT publish),B `connect(A.node_id(), alpn)` 成功(走 DHT 解析)。
- [ ] **Step 5: `cargo test --features test-utils --test network` PASS(dht 用例显示 ignored)**
- [ ] **Step 6: Commit** `test: end-to-end gossip relay pool scenarios`

### Task 7: 全量验证

- [ ] **Step 1:** `cargo test --features test-utils`(全绿,ignored=1)+ `cargo test`(默认 feature,全绿)+ `cargo clippy --all-features -- -D warnings` 0 error。
- [ ] **Step 2:** 手动 `cargo run` 冒烟(打印 node_id、无 panic、Ctrl-C 退出)。
- [ ] **Step 3:** Commit `chore: final verification` + 打 tag `v0.1.0`。
