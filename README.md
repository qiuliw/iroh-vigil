# iroh-vigil

> 把 relay 下沉进 gossip 网络:有公网能力的节点兼任 relay 并在群内广播,其余节点动态挂载,减少对固定公网 relay 的依赖。

Rust 库,基于 `iroh` 0.98 / `iroh-gossip` / `iroh-relay`。完整设计见 [docs/design.md](docs/design.md)。

## 为什么

网络里的节点两两本就要保持连接。当 a、b、c 互联而 a 与 c 之间打洞失败时,兜底流量需要走 relay——问题是,这个 relay 凭什么必须是第三方公网服务器?如果 b 有公网能力,让 b 兼任这个角色,a、c 的兜底流量就走 b,不走出这张网。

再进一步:把"与 relay 的连接"这件事本身内嵌进 gossip 网络。relay 公告(签名 + TTL + 序号)在专用 topic 里传播,节点学到就挂载、过期就卸载。即使运营商屏蔽公网 IP 段、固定 relay 连不上,网内可达的 relay 依然在服务——内网可以先于外网自愈。

最后,全局开启 DHT(Mainline/pkarr):节点地址的发布与解析不依赖任何自有基础设施,冷启动之后连 seed 都不再需要常驻。

![设计动机草图:从依赖公网 relay 到 relay 下沉进 gossip 网](docs/assets/design-sketch.png)

诚实的前提:NAT 后的普通节点无法被陌生节点入站连接,所以不能人人互为 relay;冷启动第一次入群仍需至少一个可达锚点(seed relay / seed 节点 / 公共 DHT)。iroh-vigil 把这些锚点做小、做散、可替换,而不是消灭它们。

## 工作原理

| 模块 | 职责 |
|---|---|
| `announce` | `RelayAnnouncement`:`node_id + relay_url + quic_port + seq + timestamp`,ed25519 签名,默认 30 分钟 TTL,线上格式 `[0x01][64B 签名][postcard 载荷]` |
| `relay` | `EmbeddedRelay`:包装 `iroh-relay` 服务器,`RelayBind::Tls`(生产)/ `Http`(本机开发)/ `SelfSignedTest`(测试) |
| `pool` | `RelayPool`:信任过滤 → 验签 → 新鲜度(TTL/未来时间戳)→ seq 回放 → 容量淘汰 → `insert_relay`/`remove_relay`;事件流通知调用方 |
| `node` | `VigilNode` + `Builder`:组装 endpoint + 内嵌 relay + gossip Router + RelayPool 与三个后台任务 |

公告在专用 gossip topic(`iroh-vigil/relay-pool/v1` 的 blake3 哈希)内传播;对新邻居只向直连邻居重播已知公告(≤32 条,防放大);内嵌 relay 节点每 10 分钟以递增 seq 重发自己的公告;池每 `ttl/2` 清扫过期条目。

## 快速开始

普通节点——配 seed 入群,之后一切发现都是 P2P 的:

```rust
use iroh_vigil::Builder;

let mut node = Builder::new()               // DHT 发现默认开启
    .seed_relay(seed_relay_url)             // 传输/驻留锚点
    .seed_node(seed_endpoint_addr)          // swarm 引导:已知节点的 EndpointAddr
    .spawn()
    .await?;
```

有公网能力的节点——一条配置兼任 relay,公告自动广播:

```rust
let mut relay_node = Builder::new()
    .with_embedded_relay(RelayBind::Tls {
        bind_addr: "0.0.0.0:3340".parse()?,
        certs,  // Vec<CertificateDer<'static>>,你的证书链
        key,    // PrivateKeyDer<'static>
    })
    .spawn()
    .await?;
```

应用层拿到的是普通 gossip API,任意 topic 广播/订阅:

```rust
use futures::StreamExt;
use iroh_gossip::TopicId;

let topic = TopicId::from_bytes(*blake3::hash(b"my-app/v1").as_bytes());
let sub = node.gossip().subscribe(topic, node.bootstrap_ids()).await?;
let (sender, mut receiver) = sub.split();

sender.broadcast(b"hello".into()).await?;
while let Some(event) = receiver.next().await {
    // ...
}
```

关心 relay 池变化的调用方可以监听事件流:

```rust
let mut events = node.take_relay_events();
while let Some(event) = events.recv().await {
    match event {
        RelayPoolEvent::Added(ann) => println!("挂载了 {}", ann.relay_url),
        RelayPoolEvent::Removed(url) => println!("卸载了 {url}"),
    }
}
```

其他常用配置:`trust(Trust::Only(vec![...]))` 限制公告者、`pool_config(...)` 调 TTL/容量、`online_timeout(...)` 限定冷启动等待(默认 30s,锚点不可达时快速失败)。

## 特性开关

| feature | 默认 | 说明 |
|---|---|---|
| `dht` | 开 | Mainline DHT 地址发布/解析(`iroh/address-lookup-pkarr-dht`) |
| `mdns` | 关 | 局域网 mDNS 发现 |
| `test-utils` | 关 | 测试设施:自签 relay 绑定、跳过证书校验 |

## 测试

不 mock 协议:单进程内起真实的 iroh-relay 服务器与多个 endpoint,全部走 loopback,自签证书 + `insecure_skip_verify`。20 个单元测试 + 3 个端到端场景(gossip 学到内嵌 relay / seed relay 死亡后网络自愈、无 seed 的新节点凭已知地址入群 / 4 节点 app topic 全员互通);DHT 用例需要真实外网,标记 `#[ignore]`。

```sh
cargo test --features test-utils
```

## 限制与路线

当前 v0.1.1。诚实列出的限制:

- **信任模型是 v1 的**:`Trust::Everyone` 默认接受任何有效签名公告(有 Sybil 风险),生产建议 `trust(Trust::Only(vec![...]))`。
- **seed relay 本身不构成发现路径**(iroh 0.98 语义):swarm 形成需要至少一个 `seed_node`,或可经 DHT 解析的节点 id;seed relay 的角色是传输/驻留锚点。
- relay 信誉/延迟评分、基于 gossip 的节点地址 lookup,规划在 v2。
