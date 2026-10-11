# iroh-vigil v0.1.1 修复批次实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 落地最终评审的全部 deferred minors(池并发竞态 ×2、重播范围、双广播、信任检查次序、online 超时、https-only 校验),修正 DHT 测试的可过性,发布 v0.1.1 并推送。

**Architecture:** 全部改动限于 `src/pool.rs`、`src/node.rs`、`src/announce.rs`、`tests/network.rs`。池的容量/清扫逻辑重构为"锁内决策+改表、锁外 await endpoint 调用",使两个并发竞态结构性消失。

**Tech Stack:** 同主计划(iroh 0.98.2 / tokio / postcard)。

**Spec:** `docs/superpowers/specs/2026-10-11-iroh-vigil-network-design.md`(评审记录见 git history 的 review 提交与上一会话 ledger,已随 workspace 删除;各项以本计划任务描述为准)

## Global Constraints

- 每个行为修复走 TDD:先失败测试再实现;纯重构(无可观测行为变化)以现有套件保持绿验证。
- `tokio::test` 默认 current-thread runtime:任务只在 `.await` 点交错,竞态测试据此构造确定性交错。
- 公开 async API 的 future 保持 `Send`;`#![forbid(unsafe_code)]` 不变。
- 全量门禁:`cargo test --features test-utils`、`cargo test`、`cargo clippy --all-features --tests -- -D warnings` 全绿。

## Review Focus

1. **并发 handle_wire 超容量**:max_entries=1、两任务 join 不同 URL → 池必须恰好 1 条、恰好一次 Removed(Task 1 RED 测试)。
2. **sweep 与换新竞态**:sweep 在 remove_relay await 点让出时,同 URL 高 seq 新公告被错误删除 → 新条目必须存活(Task 1 RED 测试)。
3. **不可达 relay 挂死 spawn**:refused 端口 + 短 online_timeout → spawn 返回 `VigilError::OnlineTimeout` 而非挂起(Task 5 RED 测试)。
4. **明文公告入池**:http:// URL 默认拒绝、`allow_insecure_urls(true)` 放行(Task 6 RED 测试)。
5. **DHT 测试可过性**:RelayMode::Disabled + relay_only 不发布可拨地址 → 测试节点必须带 relay(Task 7,#[ignore],真实网络验证)。

---

### Task 1: 池并发安全(淘汰/清扫竞态)

**Files:** Modify `src/pool.rs`(handle_wire、sweep);Test 同文件 tests 模块

**Interfaces:**
- Produces: `handle_wire`/`sweep` 签名不变;内部结构改为:决策段(锁内:trust/ttl/seq)→ 记账段(锁内:容量复查+淘汰+插入,map 变更与决策原子)→ 锁外仅 `endpoint.remove_relay/insert_relay().await` 与事件发送。sweep:锁内一次性收集并从表移除全部过期项,锁外逐个 `remove_relay().await` + 事件。

- [ ] **Step 1: RED 测试** `concurrent_handles_respect_capacity`:config `max_entries=1`;`tokio::join!` 两个不同 URL 的 `handle_wire`(seq 同为 1、不同公告者);断言 `known().len() == 1` 且事件流中 Removed 恰好 1 条、Added 共 2 条。
- [ ] **Step 2: 跑测确认失败**(当前 len==2、Removed 0 条)
- [ ] **Step 3: RED 测试** `sweep_keeps_refreshed_entry`:两条 URL 均 seq=1、timestamp=NOW(对 ttl=60 在 NOW+61 同时过期);spawn `pool.sweep(NOW+61)`,`yield_now()` 让 sweep 走到第一个 `remove_relay().await`;对 URL-2 投递 seq=2、timestamp=NOW+61 的新公告;await sweep;断言 URL-2 仍在 `known()` 且 seq==2。
- [ ] **Step 4: 跑测确认失败**(当前 URL-2 被误删)
- [ ] **Step 5: 重构实现** — handle_wire:决策段仅 trust/ttl/seq;记账段锁内容量复查(超容则就地淘汰最旧 last_seen 并从表移除,记住待卸载 URL)后插入;锁外执行 `remove_relay(待卸载)`、`insert_relay(新)`、事件。sweep:锁内收集+移除;锁外卸载+事件。注意保持 handle_wire future `Send`(锁 guard 不跨 await)。
- [ ] **Step 6: `cargo test --features test-utils --lib pool` PASS(全部 7 测试)**
- [ ] **Step 7: Commit** `fix: pool races - atomic eviction/sweep under lock`

### Task 2: NeighborUp 重播改 neighbors 范围

**Files:** Modify `src/node.rs`(事件循环 NeighborUp 分支)

- [ ] **Step 1: 重构** — `sender.broadcast(wire)` → `sender.broadcast_neighbors(wire)`;删除冗余 `.take(REPLAY_LIMIT)`(`replay_set()` 已限 32);注释说明 spec"对新邻居重播、防放大"语义。
- [ ] **Step 2: `cargo test --features test-utils` 全绿**(4 节点全互通用例证明小 swarm 行为不回归;plumtree 邻居语义在 n≤4 全连接下与 swarm 广播不可区分,故为重构)
- [ ] **Step 3: Commit** `refactor: replay to new neighbors only`

### Task 3: 修复启动双广播

**Files:** Modify `src/node.rs`(公告刷新任务)

- [ ] **Step 1: 重构** — `interval(REBROADCAST_PERIOD)` → `interval_at(Instant::now() + REBROADCAST_PERIOD, REBROADCAST_PERIOD)`;循环改为 `tick.tick().await` 在前的标准形态(首轮立即广播的语义由循环体在首个 tick 前执行保留:先 announce 再 tick 改为 interval_at 后保持"立即一次+周期一次")。
- [ ] **Step 2: `cargo test --features test-utils --lib node` PASS**
- [ ] **Step 3: Commit** `fix: single immediate announce on startup`

### Task 4: 信任检查先于验签

**Files:** Modify `src/announce.rs`(新增 `pub(crate) fn parse_unverified(&[u8]) -> Result<Self, AnnounceError>`:解 wire 帧 + postcard,不验签);Modify `src/pool.rs`(handle_wire:先 `parse_unverified` 取 node_id 查 trust,再 `verify_signature` 验签)

- [ ] **Step 1: 重构** — 按上述拆分;`decode`/`verify_signature` 行为不变;现有 `rejects_untrusted_announcer` 必须保持绿(trust 拒绝先行,不消耗验签)。
- [ ] **Step 2: `cargo test --features test-utils --lib` PASS**
- [ ] **Step 3: Commit** `perf: trust check before signature verification`

### Task 5: online() 超时

**Files:** Modify `src/node.rs`(Builder 字段 `online_timeout: Option<Duration>`、方法 `pub fn online_timeout(&mut self, d: Duration) -> &mut Self`;spawn 的 `endpoint.online().await` 包 `tokio::time::timeout`,默认 30s;`VigilError::OnlineTimeout` 变体)

**Interfaces:**
- Produces: `Builder::online_timeout(Duration)`;`VigilError::OnlineTimeout { after: Duration }`(thiserror,Display 含时长)

- [ ] **Step 1: RED 测试** `spawn_times_out_when_relay_unreachable`:占用后释放一个本地端口(bind 后 drop)得 refused 地址;builder `.seed_relay(refused_url).online_timeout(Duration::from_millis(300))`;外层 `tokio::time::timeout(5s, spawn)`;断言返回 `Err(VigilError::OnlineTimeout { .. })`。当前实现挂死 → 外层超时触发 → RED。
- [ ] **Step 2: 跑测确认失败**
- [ ] **Step 3: 实现** 按 Interfaces。
- [ ] **Step 4: 跑测 PASS;全 lib 套件 PASS**
- [ ] **Step 5: Commit** `feat: bounded online wait with online_timeout`

### Task 6: https-only 入池校验

**Files:** Modify `src/pool.rs`(`RelayPoolConfig.allow_insecure_urls: bool = false`;`PoolError::InsecureUrl`;handle_wire 决策段:`!allow && url.scheme() != "https"` → `Err(InsecureUrl)`);Modify `src/node.rs`(内嵌 `RelayBind::Http` 时置 `allow_insecure_urls = true`)

- [ ] **Step 1: RED 测试** `rejects_plaintext_relay_urls`:http:// URL 公告 → `Err(PoolError::InsecureUrl)`、池空;`allow_insecure_urls(true)` 时 Ok。
- [ ] **Step 2: 跑测确认失败**
- [ ] **Step 3: 实现** 按上述。
- [ ] **Step 4: 跑测 PASS**
- [ ] **Step 5: Commit** `feat: https-only relay urls by default`

### Task 7: DHT 测试可过性修正

**Files:** Modify `tests/network.rs`(`dht_publish_resolve`)

- [ ] **Step 1: 重写** — 两节点均 `.seed_relay(seed_url)`(relay URL 进 map,`relay_only` 过滤器才有东西发布)+ `discovery_dht(true)`;B `connect(A.node_id(), ALPN)` 成功即 DHT 解析生效(共享 relay 不构成发现路径,解析只能来自 DHT)。保持 `#[ignore = "needs real internet"]`。
- [ ] **Step 2: `cargo test --features test-utils --test network` PASS(ignored=1)**
- [ ] **Step 3: 有外网则 `-- --ignored` 实跑一次,如实记录结果(超时/失败不改断言,报告即可)**
- [ ] **Step 4: Commit** `fix: dht test publishes dialable relay addr`

### Task 8: 发布 v0.1.1

- [ ] **Step 1:** 全量门禁三项全绿。
- [ ] **Step 2:** `Cargo.toml` version = "0.1.1";`cargo check` 刷新 Cargo.lock;Commit `chore: release v0.1.1`;tag `v0.1.1`。
- [ ] **Step 3:** `git push origin main --tags`。
