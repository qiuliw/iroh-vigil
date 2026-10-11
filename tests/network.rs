//! 端到端场景测试(spec 测试 3-6)。

#![cfg(feature = "test-utils")]

use std::collections::BTreeSet;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use iroh::test_utils::run_relay_server;
use iroh::{EndpointAddr, TransportAddr};
use iroh_gossip::api::Event as GossipEvent;
use iroh_gossip::TopicId;
use iroh_vigil::{Builder, RelayBind, RelayPoolEvent, VigilNode};
use tokio::sync::mpsc;

const APP_TOPIC: TopicId = TopicId::from_bytes([7u8; 32]);
const WINDOW: Duration = Duration::from_secs(20);

// 测试环境可能无外网,关闭 DHT 保持封闭(dht_publish_resolve 单独开启且 #[ignore])。
fn builder() -> Builder {
    let mut b = Builder::new();
    #[cfg(feature = "dht")]
    b.discovery_dht(false);
    b
}

/// 轮询池事件,直到出现指向 `url` 的 `Added`(整体 ≤ `WINDOW`)。
async fn await_added(events: &mut mpsc::Receiver<RelayPoolEvent>, url: &iroh::RelayUrl) -> bool {
    let deadline = tokio::time::timeout(WINDOW, async {
        loop {
            match events.recv().await {
                Some(RelayPoolEvent::Added(ann)) if &ann.relay_url == url => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await;
    matches!(deadline, Ok(true))
}

/// 订阅 app topic,返回 (sender, receiver)。`joined()` 由调用方在全部订阅完成后按需等待
/// (空 bootstrap 的节点要等他人拨号,先等会死锁)。
async fn sub_app(
    node: &VigilNode,
    bootstrap: Vec<iroh::EndpointId>,
) -> (
    iroh_gossip::api::GossipSender,
    iroh_gossip::api::GossipReceiver,
) {
    let sub = node
        .gossip()
        .subscribe(APP_TOPIC, bootstrap)
        .await
        .expect("subscribe app topic");
    sub.split()
}

/// 后台排空接收端(避免通道背压阻塞对端广播)。
fn drain(mut receiver: iroh_gossip::api::GossipReceiver) {
    tokio::spawn(async move {
        while receiver.next().await.is_some() {}
    });
}

/// 收 `content`,忽略其它事件,`WINDOW` 内。
async fn recv_broadcast(
    receiver: &mut iroh_gossip::api::GossipReceiver,
    content: &[u8],
) -> bool {
    let deadline = tokio::time::timeout(WINDOW, async {
        while let Some(ev) = receiver.next().await {
            if let Ok(GossipEvent::Received(msg)) = ev
                && msg.content.as_ref() == content
            {
                return true;
            }
        }
        false
    })
    .await;
    matches!(deadline, Ok(true))
}

/// spec 测试 3:普通节点通过 gossip 学到 A 的内嵌 relay 并产生 `Added` 事件。
#[tokio::test]
async fn relay_pool_gossip_discovery() {
    let (_seed_map, seed_url, seed_server) = run_relay_server().await.expect("seed relay");

    let a = builder()
        .seed_relay(seed_url.clone())
        .with_embedded_relay(RelayBind::SelfSignedTest)
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("a spawns");
    let a_relay = a.embedded_relay_url().expect("a embeds relay").clone();

    // B、C 为纯节点:以 A 的 relay 传输层定位 A(公告的挂载/事件仍走 gossip 传播)。
    // iroh 只对 home relay 常连,A 的 home 是自己的内嵌 relay,经 seed relay 无法到达 A。
    let mut b = builder()
        .seed_relay(seed_url.clone())
        .seed_node(EndpointAddr::new(a.node_id()).with_relay_url(a_relay.clone()))
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("b spawns");
    let mut c = builder()
        .seed_relay(seed_url.clone())
        .seed_node(EndpointAddr::new(a.node_id()).with_relay_url(a_relay.clone()))
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("c spawns");

    let mut b_events = b.take_relay_events();
    let mut c_events = c.take_relay_events();
    assert!(
        await_added(&mut b_events, &a_relay).await,
        "b must learn a's relay via gossip"
    );
    assert!(
        await_added(&mut c_events, &a_relay).await,
        "c must learn a's relay via gossip"
    );

    a.shutdown().await.expect("a shutdown");
    b.shutdown().await.expect("b shutdown");
    c.shutdown().await.expect("c shutdown");
    seed_server.shutdown().await.expect("seed shutdown");
}

/// spec 测试 4:seed relay 死亡后网络自愈,新节点 D 仅凭 A 的地址入群。
#[tokio::test]
async fn network_survives_seed_relay_death() {
    let (_seed_map, seed_url, seed_server) = run_relay_server().await.expect("seed relay");

    let a = builder()
        .seed_relay(seed_url.clone())
        .with_embedded_relay(RelayBind::SelfSignedTest)
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("a spawns");
    let a_relay = a.embedded_relay_url().expect("a embeds relay").clone();

    let mut b = builder()
        .seed_relay(seed_url.clone())
        .seed_node(EndpointAddr::new(a.node_id()).with_relay_url(a_relay.clone()))
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("b spawns");
    let mut c = builder()
        .seed_relay(seed_url.clone())
        .seed_node(EndpointAddr::new(a.node_id()).with_relay_url(a_relay.clone()))
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("c spawns");

    let mut b_events = b.take_relay_events();
    let mut c_events = c.take_relay_events();
    assert!(await_added(&mut b_events, &a_relay).await, "b learned a's relay");
    assert!(await_added(&mut c_events, &a_relay).await, "c learned a's relay");

    // app topic 三方互通(全部订阅后再等 join,首节点靠他人拨号)。
    let (a_sink, a_recv) = sub_app(&a, vec![]).await;
    drain(a_recv);
    let (_b_sink, mut b_recv) = sub_app(&b, vec![a.node_id()]).await;
    let (_c_sink, mut c_recv) = sub_app(&c, vec![a.node_id()]).await;
    for recv in [&mut b_recv, &mut c_recv] {
        tokio::time::timeout(WINDOW, recv.joined())
            .await
            .expect("join app topic within window")
            .expect("join ok");
    }

    // seed relay 死亡。
    seed_server.shutdown().await.expect("seed dies");

    // A 广播,B、C 仍收到(可走 A 的内嵌 relay / 直连)。
    a_sink
        .broadcast(Bytes::from_static(b"after-death"))
        .await
        .expect("broadcast after seed death");
    assert!(
        recv_broadcast(&mut b_recv, b"after-death").await,
        "b receives after seed death"
    );
    assert!(
        recv_broadcast(&mut c_recv, b"after-death").await,
        "c receives after seed death"
    );
    drain(b_recv);
    drain(c_recv);

    // D:无 seed relay,仅凭 A 的 EndpointAddr(A 的内嵌 relay 传输层)入群。
    let mut d = builder()
        .seed_node(EndpointAddr {
            id: a.node_id(),
            addrs: BTreeSet::from([TransportAddr::Relay(a_relay.clone())]),
        })
        .insecure_skip_cert_verify()
        .spawn()
        .await
        .expect("d spawns");
    let mut d_events = d.take_relay_events();
    assert!(
        await_added(&mut d_events, &a_relay).await,
        "d learns a's relay via gossip"
    );
    let (_d_sink, mut d_recv) = sub_app(&d, vec![a.node_id()]).await;
    tokio::time::timeout(WINDOW, d_recv.joined())
        .await
        .expect("d joins app topic within window")
        .expect("join ok");
    a_sink
        .broadcast(Bytes::from_static(b"for-d"))
        .await
        .expect("broadcast for d");
    assert!(
        recv_broadcast(&mut d_recv, b"for-d").await,
        "d receives app broadcast"
    );
    drain(d_recv);

    a.shutdown().await.expect("a shutdown");
    b.shutdown().await.expect("b shutdown");
    c.shutdown().await.expect("c shutdown");
    d.shutdown().await.expect("d shutdown");
}

/// spec 测试 5:4 节点 app topic 全员互通。
#[tokio::test]
async fn gossip_app_topic_broadcast() {
    let (_seed_map, seed_url, seed_server) = run_relay_server().await.expect("seed relay");

    let mut nodes: Vec<VigilNode> = Vec::new();
    for i in 0..4 {
        let mut b = builder();
        b.seed_relay(seed_url.clone()).insecure_skip_cert_verify();
        if i > 0 {
            // 首节点作锚点,其余经 seed relay 传输层定位它;swarm 由 gossip 自行交织。
            b.seed_node(EndpointAddr::new(nodes[0].node_id()).with_relay_url(seed_url.clone()));
        }
        let node = b.spawn().await.expect("node spawns");
        nodes.push(node);
    }

    // 全员加入 app topic(后三个以首节点为 bootstrap;全部订阅完成后再等 join)。
    let mut subs = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let bootstrap = if i == 0 {
            vec![]
        } else {
            vec![nodes[0].node_id()]
        };
        subs.push(sub_app(node, bootstrap).await);
    }
    for (i, (_sink, recv)) in subs.iter_mut().enumerate() {
        if i > 0 {
            tokio::time::timeout(WINDOW, recv.joined())
                .await
                .expect("join app topic within window")
                .expect("join ok");
        }
    }

    // 每节点广播 1 条,断言每节点收到其它 3 条。
    for (i, (sink, _recv)) in subs.iter().enumerate() {
        let msg = Bytes::from(format!("msg-{i}"));
        sink.broadcast(msg).await.expect("broadcast");
    }
    for (i, (_sink, mut recv)) in subs.into_iter().enumerate() {
        let mut want: Vec<String> = (0..4).filter(|j| *j != i).map(|j| format!("msg-{j}")).collect();
        let got_all = tokio::time::timeout(WINDOW, async {
            while !want.is_empty() {
                if let Some(Ok(GossipEvent::Received(msg))) = recv.next().await
                    && let Ok(s) = std::str::from_utf8(&msg.content)
                {
                    want.retain(|w| w != s);
                }
            }
        })
        .await
        .is_ok();
        assert!(got_all, "node {i} must receive the other three messages");
    }

    for node in nodes {
        node.shutdown().await.expect("node shutdown");
    }
    seed_server.shutdown().await.expect("seed shutdown");
}

/// spec 测试 6:DHT 发布/解析(需真实外网)。
///
/// 两节点共享一个 seed relay:`DhtAddressLookup` 默认 `AddrFilter::relay_only`,
/// RelayMode::Disabled 的节点没有可发布的传输地址,裸 id 永远解析不出对端。
/// 共享 relay 不构成发现路径,`connect(A.node_id())` 的地址解析只能来自 DHT。
#[cfg(feature = "dht")]
#[ignore = "needs real internet"]
#[tokio::test]
async fn dht_publish_resolve() {
    let (_seed_map, seed_url, seed_server) = run_relay_server().await.expect("seed relay");

    let a = builder()
        .seed_relay(seed_url.clone())
        .spawn()
        .await
        .expect("a spawns (dht on)");
    tokio::time::sleep(Duration::from_secs(5)).await; // 等 DHT publish
    let b = builder()
        .seed_relay(seed_url.clone())
        .spawn()
        .await
        .expect("b spawns (dht on)");

    let conn = tokio::time::timeout(WINDOW, async {
        b.endpoint()
            .connect(a.node_id(), iroh_gossip::ALPN)
            .await
            .is_ok()
    })
    .await
    .expect("dht resolve within window");
    assert!(conn, "b must resolve and connect to a via dht");

    a.shutdown().await.expect("a shutdown");
    b.shutdown().await.expect("b shutdown");
    seed_server.shutdown().await.expect("seed shutdown");
}
