//! iroh-vigil: 把 iroh-relay 下沉进 iroh-gossip 网络。
//!
//! 有公网能力的节点内嵌 relay 并通过 gossip 广播,其他节点动态挂载,
//! 配合全局 DHT 发现,减少对固定公网 relay 的依赖。

#![forbid(unsafe_code)]

pub mod announce;
pub mod node;
pub mod pool;
pub mod relay;
