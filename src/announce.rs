//! 带签名的 relay 公告:公告者声明"我在这个 RelayUrl 提供 relay 服务"。
//!
//! 线上格式: `[0x01][64B 签名][postcard 载荷]`,签名覆盖载荷字节。

use std::time::Duration;

use bytes::Bytes;
use iroh::{EndpointId, RelayUrl, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 公告默认有效期。
pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 60);

/// 线上帧的版本字节。
const WIRE_VERSION: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAnnouncement {
    /// 公告者(= relay 运营者)。
    pub node_id: EndpointId,
    /// relay 服务的 HTTPS 地址。
    pub relay_url: RelayUrl,
    /// QUIC 地址发现端口,若提供。
    pub quic_port: Option<u16>,
    /// 单调递增序号,防回放。
    pub seq: u64,
    /// unix 秒,过期用。
    pub timestamp: u64,
}

#[derive(Debug, Error)]
pub enum AnnounceError {
    #[error("malformed announcement wire")]
    BadFormat,
    #[error("bad signature")]
    BadSignature,
    #[error("announcement expired")]
    Expired,
}

impl RelayAnnouncement {
    pub fn new(
        node_id: EndpointId,
        relay_url: RelayUrl,
        quic_port: Option<u16>,
        seq: u64,
        timestamp: u64,
    ) -> Self {
        Self { node_id, relay_url, quic_port, seq, timestamp }
    }

    /// 签名并编码为线上格式。
    pub fn sign(&self, secret_key: &SecretKey) -> Bytes {
        let payload = postcard::to_allocvec(self).expect("postcard encode");
        let signature = secret_key.sign(&payload);
        let mut wire = Vec::with_capacity(1 + 64 + payload.len());
        wire.push(WIRE_VERSION);
        wire.extend_from_slice(&signature.to_bytes());
        wire.extend_from_slice(&payload);
        Bytes::from(wire)
    }

    /// 解码并验证:验签 + TTL 检查(用 [`DEFAULT_TTL`])。
    pub fn decode(bytes: &[u8], now_unix: u64) -> Result<Self, AnnounceError> {
        let ann = Self::verify_signature(bytes)?;
        if ann.is_expired(now_unix) {
            return Err(AnnounceError::Expired);
        }
        Ok(ann)
    }

    /// 只验签解码,不做 TTL 检查(池用自己的 ttl 复查)。
    pub fn verify_signature(bytes: &[u8]) -> Result<Self, AnnounceError> {
        if bytes.len() < 1 + 64 || bytes[0] != WIRE_VERSION {
            return Err(AnnounceError::BadFormat);
        }
        let (sig_bytes, payload) = bytes[1..].split_at(64);
        let signature = Signature::from_bytes(sig_bytes.try_into().expect("length checked"));
        let ann: Self =
            postcard::from_bytes(payload).map_err(|_| AnnounceError::BadFormat)?;
        ann.node_id
            .verify(payload, &signature)
            .map_err(|_| AnnounceError::BadSignature)?;
        Ok(ann)
    }

    /// `timestamp + ttl` 是否已过。
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.is_expired_with_ttl(now_unix, DEFAULT_TTL)
    }

    /// 同 [`Self::is_expired`],显式指定 TTL。
    pub fn is_expired_with_ttl(&self, now_unix: u64, ttl: Duration) -> bool {
        now_unix.saturating_sub(self.timestamp) >= ttl.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{EndpointId, RelayUrl, SecretKey};

    const NOW: u64 = 1_700_000_000;

    fn announcer() -> SecretKey {
        SecretKey::generate()
    }

    fn sample(node_id: EndpointId) -> RelayAnnouncement {
        let url: RelayUrl = "https://127.0.0.1:3340".parse().expect("valid url");
        RelayAnnouncement::new(node_id, url, Some(3340), 1, NOW)
    }

    #[test]
    fn roundtrip_sign_decode() {
        let sk = announcer();
        let ann = sample(sk.public());
        let wire = ann.sign(&sk);
        let decoded = RelayAnnouncement::decode(&wire, NOW).expect("decode ok");
        assert_eq!(decoded.node_id, ann.node_id);
        assert_eq!(decoded.relay_url, ann.relay_url);
        assert_eq!(decoded.quic_port, ann.quic_port);
        assert_eq!(decoded.seq, ann.seq);
        assert_eq!(decoded.timestamp, ann.timestamp);
    }

    #[test]
    fn tampered_payload_rejected() {
        let sk = announcer();
        let mut wire = sample(sk.public()).sign(&sk).to_vec();
        // 翻转 node_id 区内的字节:postcard 仍可解码,签名校验必然失败。
        let in_node_id = 1 + 64 + 5;
        wire[in_node_id] ^= 0xff;
        assert!(matches!(
            RelayAnnouncement::decode(&wire, NOW),
            Err(AnnounceError::BadSignature)
        ));
        // 翻转末字节(timestamp varint 尾字节,置 continuation bit)在解码阶段即被拒。
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        assert!(RelayAnnouncement::decode(&wire, NOW).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let signer = SecretKey::generate();
        let claimed_id = SecretKey::generate().public(); // 公告者与签名者不一致
        let wire = sample(claimed_id).sign(&signer);
        assert!(matches!(
            RelayAnnouncement::decode(&wire, NOW),
            Err(AnnounceError::BadSignature)
        ));
    }

    #[test]
    fn expired_rejected() {
        let sk = announcer();
        let old = sample(sk.public()); // timestamp = NOW
        let wire = old.sign(&sk);
        let one_hour_later = NOW + 3600; // TTL 默认 30 分钟
        assert!(matches!(
            RelayAnnouncement::decode(&wire, one_hour_later),
            Err(AnnounceError::Expired)
        ));
        assert!(old.is_expired(one_hour_later));
        assert!(!old.is_expired(NOW));
    }

    #[test]
    fn garbage_rejected() {
        assert!(matches!(
            RelayAnnouncement::decode(b"\x00short", NOW),
            Err(AnnounceError::BadFormat)
        ));
        assert!(matches!(
            RelayAnnouncement::decode(&[], NOW),
            Err(AnnounceError::BadFormat)
        ));
    }
}
