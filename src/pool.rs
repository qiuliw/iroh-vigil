//! Relay 公告池:收集 gossip 公告,验签防回放,动态挂载/卸载 endpoint 的 relay。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use iroh::{Endpoint, EndpointId, RelayConfig, RelayUrl};
use iroh_relay::RelayQuicConfig;
use tokio::sync::mpsc;

use crate::announce::{AnnounceError, RelayAnnouncement, DEFAULT_TTL};

/// 池对外事件。
pub enum RelayPoolEvent {
    /// 一条新公告入池并已挂载到 endpoint。
    Added(RelayAnnouncement),
    /// 一条公告被移除(过期/淘汰)并已从 endpoint 卸载。
    Removed(RelayUrl),
}

/// 公告者信任策略。
#[derive(Debug, Clone, Default)]
pub enum Trust {
    /// 接受任何人(默认;有 Sybil 风险,v1 允许,生产建议 `Only`)。
    #[default]
    Everyone,
    /// 只接受指定 endpoint 的公告。
    Only(Vec<EndpointId>),
}

/// 池配置。
#[derive(Debug, Clone)]
pub struct RelayPoolConfig {
    /// 公告有效期(池统一裁决,覆盖 [`crate::announce::DEFAULT_TTL`])。
    pub ttl: Duration,
    /// 池容量上限,超出淘汰最旧 `last_seen`。
    pub max_entries: usize,
    /// 信任策略。
    pub trust: Trust,
}

impl Default for RelayPoolConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            max_entries: 64,
            trust: Trust::default(),
        }
    }
}

/// 池操作错误。
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// 公告本身无效(格式/签名)。
    #[error(transparent)]
    Announce(#[from] AnnounceError),
    /// 公告者不在信任列表。
    #[error("announcer not trusted")]
    Untrusted,
    /// seq 不大于已记录值,判定为回放。
    #[error("stale seq, replay suspected")]
    Stale,
    /// 池容量为 0,无法容纳任何公告。
    #[error("pool at zero capacity")]
    CapacityEvicted,
}

struct PoolEntry {
    ann: RelayAnnouncement,
    wire: Bytes,
    #[allow(dead_code)] // spec 的 PoolEntry 字段,v2 信誉评分用
    first_seen: u64,
    last_seen: u64,
}

struct Inner {
    endpoint: Endpoint,
    config: RelayPoolConfig,
    events: mpsc::Sender<RelayPoolEvent>,
    /// 以 RelayUrl 为主键的当前池内容。
    entries: HashMap<RelayUrl, PoolEntry>,
    /// 每个公告者已被接受的最大 seq。
    max_seq: HashMap<EndpointId, u64>,
}

/// Relay 公告池。`Clone` 共享同一份状态。
///
/// 内部用 `std::sync::RwLock`,临界区内不做任何 `.await`,
/// 公开 async 方法的 future 保持 `Send`。
#[derive(Clone)]
pub struct RelayPool {
    inner: Arc<RwLock<Inner>>,
}

impl RelayPool {
    /// 创建池,返回事件接收端(`mpsc(64)`,满则丢事件不阻塞)。
    pub fn new(
        endpoint: Endpoint,
        config: RelayPoolConfig,
    ) -> (Self, mpsc::Receiver<RelayPoolEvent>) {
        let (events, receiver) = mpsc::channel(64);
        (
            Self {
                inner: Arc::new(RwLock::new(Inner {
                    endpoint,
                    config,
                    events,
                    entries: HashMap::new(),
                    max_seq: HashMap::new(),
                })),
            },
            receiver,
        )
    }

    /// 处理一条公告 wire:验签 → 信任 → 回放 → 容量 → 挂载。
    ///
    /// 返回 `Ok(Some(ann))` 表示新入池;`Ok(None)` 表示 gossip 重复投递(仅刷新 last_seen)。
    ///
    /// 并发安全:决策(trust/ttl/seq)与记账(容量复查+淘汰+插入)各自在单次锁内
    /// 原子完成,锁 guard 不跨 await;锁外只做 endpoint 调用与事件发送。
    /// 容量的权威裁决在记账段——两个并发 handle_wire 不可能同时挤占最后一个槽位。
    pub async fn handle_wire(
        &self,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<Option<RelayAnnouncement>, PoolError> {
        let ann = RelayAnnouncement::verify_signature(bytes)?;

        // 决策段:锁内同步判断;重复/拒绝路径在此提前返回。
        {
            let mut inner = self.inner.write().expect("pool lock");
            // 入池即检查池自己的 TTL(过期/超前的未来时间戳都拒,防止挂载死 relay)。
            if ann.is_expired_with_ttl(now_unix, inner.config.ttl) {
                return Err(PoolError::Announce(AnnounceError::Expired));
            }
            match inner.config.trust {
                Trust::Everyone => {}
                Trust::Only(ref ids) if ids.contains(&ann.node_id) => {}
                Trust::Only(_) => return Err(PoolError::Untrusted),
            }
            if let Some(&seq) = inner.max_seq.get(&ann.node_id) {
                if ann.seq < seq {
                    return Err(PoolError::Stale);
                }
                if ann.seq == seq {
                    if let Some(entry) = inner.entries.get_mut(&ann.relay_url)
                        && entry.ann.seq == ann.seq
                    {
                        entry.last_seen = now_unix;
                        return Ok(None);
                    }
                    return Err(PoolError::Stale);
                }
            }
            if inner.config.max_entries == 0 {
                return Err(PoolError::CapacityEvicted);
            }
        }

        // 记账段:容量复查 + 淘汰 + 插入,单次写锁内原子完成。
        let url = ann.relay_url.clone();
        let evicted: Option<RelayUrl> = {
            let mut inner = self.inner.write().expect("pool lock");
            let evicted = if !inner.entries.contains_key(&url)
                && inner.entries.len() >= inner.config.max_entries
            {
                let victim = inner
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.last_seen)
                    .map(|(victim_url, _)| victim_url.clone())
                    .expect("non-empty");
                inner.entries.remove(&victim);
                Some(victim)
            } else {
                None
            };
            inner.max_seq.insert(ann.node_id, ann.seq);
            inner.entries.insert(
                url.clone(),
                PoolEntry {
                    ann: ann.clone(),
                    wire: Bytes::copy_from_slice(bytes),
                    first_seen: now_unix,
                    last_seen: now_unix,
                },
            );
            evicted
        };

        // 锁外段:endpoint 调用与事件。
        if let Some(evicted) = &evicted {
            self.endpoint().remove_relay(evicted).await;
            self.emit(RelayPoolEvent::Removed(evicted.clone()));
        }
        self.endpoint()
            .insert_relay(
                url.clone(),
                Arc::new(RelayConfig::new(
                    url.clone(),
                    ann.quic_port.map(RelayQuicConfig::new),
                )),
            )
            .await;
        self.emit(RelayPoolEvent::Added(ann.clone()));
        Ok(Some(ann))
    }

    /// 锁外可 `await` 的 endpoint 克隆。
    fn endpoint(&self) -> Endpoint {
        self.inner.read().expect("pool lock").endpoint.clone()
    }

    /// 发一条事件(通道满则丢弃)。
    fn emit(&self, event: RelayPoolEvent) {
        let _ = self
            .inner
            .read()
            .expect("pool lock")
            .events
            .try_send(event);
    }

    /// 当前池内全部公告。
    pub fn known(&self) -> Vec<RelayAnnouncement> {        self.inner
            .read()
            .expect("pool lock")
            .entries
            .values()
            .map(|e| e.ann.clone())
            .collect()
    }

    /// 清扫过期公告并卸载。
    ///
    /// 同时清掉已无存活条目的公告者的 `max_seq` 记录:
    /// 否则重启后 seq 从 1 重新计数的公告者会被旧记录当回放拒掉,
    /// 且 `Trust::Everyone` 下该表可被无界撑大。
    ///
    /// 收集与移表在单次写锁内原子完成;锁外卸载前复查条目是否已被
    /// 并发 handle_wire 换新换回——是则跳过卸载与 Removed 事件。
    pub async fn sweep(&self, now_unix: u64) {
        let expired: Vec<RelayUrl> = {
            let mut inner = self.inner.write().expect("pool lock");
            let ttl = inner.config.ttl;
            let expired: Vec<RelayUrl> = inner
                .entries
                .iter()
                .filter(|(_, e)| e.ann.is_expired_with_ttl(now_unix, ttl))
                .map(|(url, _)| url.clone())
                .collect();
            for url in &expired {
                inner.entries.remove(url);
            }
            let live: HashSet<EndpointId> =
                inner.entries.values().map(|e| e.ann.node_id).collect();
            inner.max_seq.retain(|id, _| live.contains(id));
            expired
        };
        if expired.is_empty() {
            return;
        }
        let endpoint = self.endpoint();
        for url in expired {
            let refreshed = self
                .inner
                .read()
                .expect("pool lock")
                .entries
                .contains_key(&url);
            if refreshed {
                continue;
            }
            endpoint.remove_relay(&url).await;
            self.emit(RelayPoolEvent::Removed(url));
        }
    }

    /// 最近 `last_seen` 的 ≤32 条公告原始 wire(NeighborUp 重播用)。
    ///
    /// 过期条目可能仍在其中(清扫是周期性的);接收端的入池 TTL 检查是权威防线。
    pub fn replay_set(&self) -> Vec<Bytes> {
        let inner = self.inner.read().expect("pool lock");
        let mut entries: Vec<&PoolEntry> = inner.entries.values().collect();
        entries.sort_by_key(|e| e.last_seen);
        entries
            .into_iter()
            .rev()
            .take(32)
            .map(|e| e.wire.clone())
            .collect()
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::announce::{AnnounceError, RelayAnnouncement};
    use bytes::Bytes;
    use iroh::endpoint::presets::Minimal;
    use iroh::{Endpoint, RelayMode, RelayUrl, SecretKey};
    use std::time::Duration;

    const NOW: u64 = 1_700_000_000;

    async fn endpoint() -> Endpoint {
        Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("endpoint binds")
    }

    fn sample(sk: &SecretKey, seq: u64) -> Bytes {
        let url: RelayUrl = "https://127.0.0.1:3340".parse().expect("valid url");
        RelayAnnouncement::new(sk.public(), url, Some(3340), seq, NOW).sign(sk)
    }

    #[tokio::test]
    async fn adds_valid_announcement_and_emits_event() {
        let ep = endpoint().await;
        let (pool, mut events) = RelayPool::new(ep, RelayPoolConfig::default());
        let sk = SecretKey::generate();

        let added = pool.handle_wire(&sample(&sk, 1), NOW).await.expect("valid wire");
        assert!(added.is_some(), "first sight must add");
        assert_eq!(pool.known().len(), 1);
        assert_eq!(
            pool.known()[0].node_id,
            sk.public(),
            "known() returns the decoded announcement"
        );
        assert!(matches!(events.try_recv(), Ok(RelayPoolEvent::Added(_))));
        assert_eq!(pool.replay_set().len(), 1, "replay set carries the wire");
    }

    #[tokio::test]
    async fn rejects_stale_seq() {
        let ep = endpoint().await;
        let (pool, _events) = RelayPool::new(ep, RelayPoolConfig::default());
        let sk = SecretKey::generate();

        pool.handle_wire(&sample(&sk, 5), NOW).await.expect("seq 5 adds");
        let res = pool.handle_wire(&sample(&sk, 3), NOW).await;
        assert!(matches!(res, Err(PoolError::Stale)));
        assert_eq!(pool.known().len(), 1, "known unchanged after stale seq");
        assert_eq!(pool.known()[0].seq, 5);
    }

    #[tokio::test]
    async fn rejects_untrusted_announcer() {
        let ep = endpoint().await;
        let other = SecretKey::generate();
        let (pool, _events) = RelayPool::new(
            ep,
            RelayPoolConfig {
                trust: Trust::Only(vec![other.public()]),
                ..Default::default()
            },
        );
        let sk = SecretKey::generate();

        let res = pool.handle_wire(&sample(&sk, 1), NOW).await;
        assert!(matches!(res, Err(PoolError::Untrusted)));
        assert!(pool.known().is_empty());
    }

    #[tokio::test]
    async fn sweep_removes_expired() {
        let ep = endpoint().await;
        let (pool, mut events) = RelayPool::new(
            ep,
            RelayPoolConfig {
                ttl: Duration::from_secs(60),
                ..Default::default()
            },
        );
        let sk = SecretKey::generate();
        pool.handle_wire(&sample(&sk, 1), NOW).await.expect("adds");
        assert!(matches!(events.try_recv(), Ok(RelayPoolEvent::Added(_))));

        pool.sweep(NOW + 61).await;
        assert!(pool.known().is_empty(), "expired entry swept");
        assert!(matches!(events.try_recv(), Ok(RelayPoolEvent::Removed(_))));
    }

    #[tokio::test]
    async fn expired_rejected_at_intake() {
        let ep = endpoint().await;
        let (pool, _events) = RelayPool::new(ep, RelayPoolConfig::default());
        let sk = SecretKey::generate();

        // 有效签名但早已过期(timestamp = NOW - 3600,默认 ttl 30 分钟)。
        let url: RelayUrl = "https://127.0.0.1:3340".parse().expect("valid url");
        let old = RelayAnnouncement::new(sk.public(), url, Some(3340), 1, NOW - 3600);
        let res = pool.handle_wire(&old.sign(&sk), NOW).await;
        assert!(
            matches!(res, Err(PoolError::Announce(AnnounceError::Expired))),
            "expired announcement must be rejected at intake"
        );
        assert!(pool.known().is_empty());
    }

    #[tokio::test]
    async fn sweep_prunes_stale_announcer_seq() {
        // 重启场景:公告者旧 seq 随条目过期被清掉,seq=1 的新一轮公告可被接受。
        let ep = endpoint().await;
        let (pool, _events) = RelayPool::new(
            ep,
            RelayPoolConfig { ttl: Duration::from_secs(60), ..Default::default() },
        );
        let sk = SecretKey::generate();

        pool.handle_wire(&sample(&sk, 5), NOW).await.expect("seq 5 adds");
        pool.sweep(NOW + 61).await;
        assert!(pool.known().is_empty());

        let url: RelayUrl = "https://127.0.0.1:3340".parse().expect("valid url");
        let fresh = RelayAnnouncement::new(sk.public(), url, Some(3340), 1, NOW + 61);
        let res = pool.handle_wire(&fresh.sign(&sk), NOW + 61).await;
        assert!(
            matches!(res, Ok(Some(_))),
            "fresh announcement after sweep must be accepted despite lower seq"
        );
    }

    #[tokio::test]
    async fn concurrent_handles_respect_capacity() {
        // current-thread runtime:两任务仅在 await 点交错,构造确定性竞态。
        let ep = endpoint().await;
        let (pool, mut events) = RelayPool::new(
            ep,
            RelayPoolConfig { max_entries: 1, ..Default::default() },
        );
        let sk_a = SecretKey::generate();
        let sk_b = SecretKey::generate();
        let url_a: RelayUrl = "https://127.0.0.1:3341".parse().expect("valid url");
        let url_b: RelayUrl = "https://127.0.0.1:3342".parse().expect("valid url");
        let wa = RelayAnnouncement::new(sk_a.public(), url_a, None, 1, NOW).sign(&sk_a);
        let wb = RelayAnnouncement::new(sk_b.public(), url_b, None, 1, NOW).sign(&sk_b);

        let (ra, rb) = tokio::join!(
            pool.handle_wire(&wa, NOW),
            pool.handle_wire(&wb, NOW),
        );
        assert!(ra.is_ok() && rb.is_ok(), "both wires are valid: {ra:?} {rb:?}");
        assert_eq!(
            pool.known().len(),
            1,
            "capacity must hold even under concurrent intake"
        );
        let mut removed = 0;
        let mut added = 0;
        while let Ok(ev) = events.try_recv() {
            match ev {
                RelayPoolEvent::Removed(_) => removed += 1,
                RelayPoolEvent::Added(_) => added += 1,
            }
        }
        assert_eq!(removed, 1, "exactly one eviction event");
        assert_eq!(added, 2, "both wires were accepted");
    }

    #[tokio::test]
    async fn sweep_keeps_refreshed_entry() {
        let ep = endpoint().await;
        let (pool, _events) = RelayPool::new(
            ep,
            RelayPoolConfig { ttl: Duration::from_secs(60), ..Default::default() },
        );
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let url1: RelayUrl = "https://127.0.0.1:3341".parse().expect("valid url");
        let url2: RelayUrl = "https://127.0.0.1:3342".parse().expect("valid url");
        pool.handle_wire(&RelayAnnouncement::new(sk1.public(), url1.clone(), None, 1, NOW).sign(&sk1), NOW).await.expect("url1 adds");
        pool.handle_wire(&RelayAnnouncement::new(sk2.public(), url2.clone(), None, 1, NOW).sign(&sk2), NOW).await.expect("url2 adds");

        // sweep 在第一个 remove_relay().await 处让出;此刻 URL-2 被换新(seq 2,新时间戳)。
        let sweep = tokio::spawn({
            let pool = pool.clone();
            async move { pool.sweep(NOW + 61).await }
        });
        tokio::task::yield_now().await;
        pool.handle_wire(
            &RelayAnnouncement::new(sk2.public(), url2.clone(), None, 2, NOW + 61).sign(&sk2),
            NOW + 61,
        )
        .await
        .expect("url2 refresh accepted");
        sweep.await.expect("sweep task");

        let known = pool.known();
        assert!(
            known.iter().any(|a| a.relay_url == url2 && a.seq == 2),
            "refreshed entry must survive a concurrent sweep, got {known:?}"
        );
    }

    #[tokio::test]
    async fn garbage_wire_rejected() {
        let ep = endpoint().await;
        let (pool, _events) = RelayPool::new(ep, RelayPoolConfig::default());

        let res = pool.handle_wire(b"\x00nonsense", NOW).await;
        assert!(matches!(
            res,
            Err(PoolError::Announce(AnnounceError::BadFormat))
        ));
        assert!(pool.known().is_empty());
    }
}
