use crate::types::PolicyEnvelope;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Human-readable service label for logs and metrics.
    pub service_name: String,
    /// Node or deployment identifier.
    pub node_id: String,
    /// Upper bound on request payload bytes accepted by the security layer.
    pub max_payload_bytes: usize,
    /// Maximum tolerated skew between a request timestamp and the local clock.
    pub max_clock_skew_secs: i64,
    /// Maximum number of parent hashes accepted in a request.
    pub max_parent_hashes: usize,
    /// Maximum number of distinct nonces retained in memory for replay defense.
    pub replay_cache_limit: usize,
    /// Maximum number of attestations accepted on a single envelope.
    pub max_attestations: usize,
    /// Enable append-only disk persistence for events and replay state.
    pub enable_persistence: bool,
    /// Optional path where the replay snapshot is stored.
    pub replay_store_path: Option<String>,
    /// Optional path where the event log is stored.
    pub event_store_path: Option<String>,
    /// Policy defaults that can be loaded into the engine.
    pub policy: PolicyEnvelope,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            service_name: "vector-security-layer".to_string(),
            node_id: "local-node".to_string(),
            max_payload_bytes: 16 * 1024,
            max_clock_skew_secs: 300,
            max_parent_hashes: 32,
            replay_cache_limit: 50_000,
            max_attestations: 16,
            enable_persistence: false,
            replay_store_path: None,
            event_store_path: None,
            policy: PolicyEnvelope::default(),
        }
    }
}
