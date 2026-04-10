//! P2P Connection Mode — Active / Backup 接続モデル分離
//!
//! # 設計原則
//!
//! ```text
//! Active Validator
//!   - 公開到達可能 (public_reachable = true)
//!   - ポート開放必須 (port_open = true)
//!   - inbound/outbound 両対応
//!   - コンセンサスの中核。他ノードから直接接続を受け付ける
//!
//! Backup Validator
//!   - outbound-only で参加可能
//!   - ポート開放不要 (port_open = not required)
//!   - NAT配下・ローカルPC・家庭回線でも参加可能
//!   - 昇格時にのみ Active モードへ切り替え
//! ```
//!
//! # 昇格時の要件
//!
//! Backup が Active に昇格するには、スコア条件に加えて
//! `can_switch_to_public_mode = true` であること。
//! ローカルPCのままでは昇格できない。

use serde::{Deserialize, Serialize};

// ─── NodeConnectionMode ────────────────────────────────────────────────────────

/// ノードの P2P 接続モード。
/// Active/Backup それぞれで必要な接続条件が異なる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeConnectionMode {
    /// 公開接続モード。
    /// - inbound/outbound 両対応
    /// - 外部から直接接続を受け付ける
    /// - Active Validator に必須
    Public,

    /// outbound-only モード。
    /// - 自分から接続先に接続する（inbound なし）
    /// - ポート開放不要
    /// - NAT 配下・ローカルPC で参加可能
    /// - Backup Validator として参加可能
    OutboundOnly,
}

impl NodeConnectionMode {
    /// Active Validator になれるモードか
    pub fn can_be_active(&self) -> bool {
        matches!(self, NodeConnectionMode::Public)
    }

    /// Backup Validator として参加可能か
    pub fn can_be_backup(&self) -> bool {
        true // 全モード Backup 参加可能
    }
}

impl std::fmt::Display for NodeConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::OutboundOnly => write!(f, "outbound_only"),
        }
    }
}

// ─── ActiveEndpointInfo ────────────────────────────────────────────────────────

/// Active Validator のエンドポイント情報。
/// コンセンサス参加に必要な公開接続情報を保持する。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveEndpointInfo {
    /// 外部から到達可能な IP アドレスまたは DNS ホスト名
    pub endpoint: String,
    /// コンセンサス P2P ポート番号
    pub port: u16,
    /// 登録済みエンドポイントが到達可能かの最終確認結果
    pub reachability_verified: bool,
    /// 最終到達確認タイムスタンプ (Unix ms)
    pub last_verified_ms: u64,
}

impl ActiveEndpointInfo {
    pub fn new(endpoint: impl Into<String>, port: u16) -> Self {
        Self {
            endpoint: endpoint.into(),
            port,
            reachability_verified: false,
            last_verified_ms: 0,
        }
    }

    /// エンドポイント文字列を返す (host:port 形式)
    pub fn address(&self) -> String {
        format!("{}:{}", self.endpoint, self.port)
    }
}

// ─── P2pConnectionRequirements ────────────────────────────────────────────────

/// Active / Backup それぞれの接続要件。
/// ノード昇格時の条件チェックに使用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConnectionRequirements {
    /// 外部から到達可能か (Active 必須、Backup 不要)
    pub public_reachable: bool,
    /// コンセンサス用ポートが開いているか (Active 必須、Backup 不要)
    pub port_open: bool,
    /// inbound コンセンサス接続を受け付けるか (Active 必須)
    pub inbound_consensus_connection: bool,
    /// 安定したエンドポイントが登録済みか (Active 必須)
    pub stable_endpoint_registered: bool,
}

impl P2pConnectionRequirements {
    /// Active Validator として参加するための要件を満たしているか
    ///
    /// ```text
    /// eligible_active =
    ///     public_reachable
    ///     AND port_open
    ///     AND inbound_consensus_connection
    ///     AND stable_endpoint_registered
    /// ```
    pub fn satisfies_active_requirements(&self) -> bool {
        self.public_reachable
            && self.port_open
            && self.inbound_consensus_connection
            && self.stable_endpoint_registered
    }

    /// Backup Validator として参加するための要件を満たしているか
    /// (全ての構成で Backup 参加は可能)
    pub fn satisfies_backup_requirements(&self) -> bool {
        true // outbound-only / NAT / ローカルPC すべて許可
    }

    /// Backup が Active に昇格できる接続状態にあるか
    ///
    /// ```text
    /// can_switch_to_public_mode =
    ///     public_reachable_ready
    ///     AND port_open_ready
    ///     AND active_endpoint_registered
    /// ```
    pub fn can_switch_to_public_mode(&self) -> bool {
        self.satisfies_active_requirements()
    }
}

// ─── ValidatorNetworkProfile ──────────────────────────────────────────────────

/// バリデータの現在のネットワークプロファイル。
/// `ValidatorRegistry` が各バリデータごとに保持する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorNetworkProfile {
    /// バリデータ ID (32 bytes, canonical SHA3-256)
    pub validator_id: [u8; 32],
    /// 現在の接続モード
    pub mode: NodeConnectionMode,
    /// Active エンドポイント情報 (Public モードの場合のみ Some)
    pub active_endpoint: Option<ActiveEndpointInfo>,
    /// 接続要件の現在の状態
    pub requirements: P2pConnectionRequirements,
}

impl ValidatorNetworkProfile {
    /// Backup (outbound-only) プロファイルを作成
    pub fn new_backup(validator_id: [u8; 32]) -> Self {
        Self {
            validator_id,
            mode: NodeConnectionMode::OutboundOnly,
            active_endpoint: None,
            requirements: P2pConnectionRequirements {
                public_reachable: false,
                port_open: false,
                inbound_consensus_connection: false,
                stable_endpoint_registered: false,
            },
        }
    }

    /// Public (Active-capable) プロファイルを作成
    pub fn new_public(validator_id: [u8; 32], endpoint: ActiveEndpointInfo) -> Self {
        let requirements = P2pConnectionRequirements {
            public_reachable: endpoint.reachability_verified,
            port_open: true,
            inbound_consensus_connection: true,
            stable_endpoint_registered: true,
        };
        Self {
            validator_id,
            mode: NodeConnectionMode::Public,
            active_endpoint: Some(endpoint),
            requirements,
        }
    }

    /// Active になれるか (接続モードと要件の両方を確認)
    pub fn eligible_for_active(&self) -> bool {
        self.mode.can_be_active() && self.requirements.satisfies_active_requirements()
    }

    /// Backup から Active への昇格が接続要件上可能か
    pub fn can_promote_to_active(&self) -> bool {
        self.requirements.can_switch_to_public_mode()
    }

    /// 到達可能性を更新 (P2P 到達確認後に呼ぶ)
    pub fn mark_reachable(&mut self, verified_ms: u64) {
        self.requirements.public_reachable = true;
        if let Some(ref mut ep) = self.active_endpoint {
            ep.reachability_verified = true;
            ep.last_verified_ms = verified_ms;
        }
    }
}

// ─── ReachabilityProbe ────────────────────────────────────────────────────────

/// 到達可能性チェックの結果。
/// Active への昇格前にプローブが成功していることを確認する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityProbeResult {
    pub validator_id: [u8; 32],
    pub endpoint: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub probed_at_ms: u64,
    pub error: Option<String>,
}

impl ReachabilityProbeResult {
    pub fn success(
        validator_id: [u8; 32],
        endpoint: String,
        latency_ms: u64,
        probed_at_ms: u64,
    ) -> Self {
        Self {
            validator_id,
            endpoint,
            success: true,
            latency_ms: Some(latency_ms),
            probed_at_ms,
            error: None,
        }
    }

    pub fn failure(
        validator_id: [u8; 32],
        endpoint: String,
        probed_at_ms: u64,
        error: impl Into<String>,
    ) -> Self {
        Self {
            validator_id,
            endpoint,
            success: false,
            latency_ms: None,
            probed_at_ms,
            error: Some(error.into()),
        }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn make_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn backup_profile_cannot_be_active() {
        let profile = ValidatorNetworkProfile::new_backup(make_id(1));
        assert!(!profile.eligible_for_active());
        assert!(!profile.can_promote_to_active());
    }

    #[test]
    fn public_profile_eligible_after_verification() {
        let mut ep = ActiveEndpointInfo::new("203.0.113.1", 6690);
        // 未確認の状態では不可
        let profile = ValidatorNetworkProfile::new_public(make_id(2), ep.clone());
        assert!(!profile.eligible_for_active()); // reachability_verified = false

        // 到達確認後は Active 可能
        ep.reachability_verified = true;
        ep.last_verified_ms = 1_700_000_000_000;
        let mut profile = ValidatorNetworkProfile::new_public(make_id(2), ep);
        profile.requirements.public_reachable = true;
        assert!(profile.eligible_for_active());
    }

    #[test]
    fn mode_display() {
        assert_eq!(NodeConnectionMode::Public.to_string(), "public");
        assert_eq!(
            NodeConnectionMode::OutboundOnly.to_string(),
            "outbound_only"
        );
    }

    #[test]
    fn active_requirements_all_must_be_true() {
        let req = P2pConnectionRequirements {
            public_reachable: true,
            port_open: true,
            inbound_consensus_connection: true,
            stable_endpoint_registered: true,
        };
        assert!(req.satisfies_active_requirements());

        // 一つでも false なら不合格
        let req2 = P2pConnectionRequirements {
            public_reachable: false,
            ..req.clone()
        };
        assert!(!req2.satisfies_active_requirements());
    }

    #[test]
    fn backup_requirements_always_satisfied() {
        let req = P2pConnectionRequirements {
            public_reachable: false,
            port_open: false,
            inbound_consensus_connection: false,
            stable_endpoint_registered: false,
        };
        assert!(req.satisfies_backup_requirements());
    }

    #[test]
    fn endpoint_address_format() {
        let ep = ActiveEndpointInfo::new("validator.example.com", 6690);
        assert_eq!(ep.address(), "validator.example.com:6690");
    }

    #[test]
    fn mark_reachable_updates_state() {
        let ep = ActiveEndpointInfo::new("10.0.0.1", 6690);
        let mut profile = ValidatorNetworkProfile::new_public(make_id(5), ep);
        assert!(!profile.requirements.public_reachable);
        profile.mark_reachable(1_700_000_000_000);
        assert!(profile.requirements.public_reachable);
        assert!(
            profile
                .active_endpoint
                .as_ref()
                .expect("ep")
                .reachability_verified
        );
    }
}
