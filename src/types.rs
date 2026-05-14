use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WalletId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RegionId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EventId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Nonce(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationKind {
    Create,
    Certify,
    Transfer,
    Drain,
    Project,
    Reconstruct,
    Move,
    Rotate,
    Scale,
    Normalize,
    Constrain,
    Query,
    Custom(String),
}

impl fmt::Display for OperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationKind::Create => write!(f, "CREATE"),
            OperationKind::Certify => write!(f, "CERTIFY"),
            OperationKind::Transfer => write!(f, "TRANSFER"),
            OperationKind::Drain => write!(f, "DRAIN"),
            OperationKind::Project => write!(f, "PROJECT"),
            OperationKind::Reconstruct => write!(f, "RECONSTRUCT"),
            OperationKind::Move => write!(f, "MOVE"),
            OperationKind::Rotate => write!(f, "ROTATE"),
            OperationKind::Scale => write!(f, "SCALE"),
            OperationKind::Normalize => write!(f, "NORMALIZE"),
            OperationKind::Constrain => write!(f, "CONSTRAIN"),
            OperationKind::Query => write!(f, "QUERY"),
            OperationKind::Custom(s) => write!(f, "CUSTOM:{s}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub wallet_id: WalletId,
    pub region_id: RegionId,
    pub verified_public_key: Vec<u8>,
    pub auth_ratio: f64,
    pub cert_threshold: f64,
    pub timestamp: i64,
}

impl SecurityContext {
    pub fn now(
        wallet_id: impl Into<String>,
        region_id: impl Into<String>,
        verified_public_key: Vec<u8>,
        auth_ratio: f64,
        cert_threshold: f64,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        Self {
            wallet_id: WalletId(wallet_id.into()),
            region_id: RegionId(region_id.into()),
            verified_public_key,
            auth_ratio,
            cert_threshold,
            timestamp: ts,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.wallet_id.0.trim().is_empty() {
            return Err("wallet_id is empty".into());
        }
        if self.region_id.0.trim().is_empty() {
            return Err("region_id is empty".into());
        }
        if self.verified_public_key.len() != 32 {
            return Err("verified_public_key must be 32 bytes".into());
        }
        if !(0.0..=1.0).contains(&self.auth_ratio) {
            return Err("auth_ratio must be within [0, 1]".into());
        }
        if !(0.0..=1.0).contains(&self.cert_threshold) {
            return Err("cert_threshold must be within [0, 1]".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequest {
    pub protocol_version: u32,
    pub nonce: Nonce,
    pub operation: OperationKind,
    pub region_id: RegionId,
    pub wallet_id: WalletId,
    pub target_wallet: Option<WalletId>,
    pub payload: Vec<u8>,
    pub parent_event_hashes: Vec<String>,
    pub signature: Vec<u8>,
    pub timestamp: i64,
}

impl SecurityRequest {
    pub fn validate_basic(&self) -> Result<(), String> {
        if self.protocol_version == 0 {
            return Err("protocol_version must be greater than zero".into());
        }
        if self.nonce.0.trim().is_empty() {
            return Err("nonce is empty".into());
        }
        if self.wallet_id.0.trim().is_empty() {
            return Err("wallet_id is empty".into());
        }
        if self.region_id.0.trim().is_empty() {
            return Err("region_id is empty".into());
        }
        if self.timestamp <= 0 {
            return Err("timestamp must be positive".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: EventId,
    pub protocol_version: u32,
    pub parent_hashes: Vec<String>,
    pub region_id: RegionId,
    pub entity_id: WalletId,
    pub operation: OperationKind,
    pub request_hash: String,
    pub payload_hash: String,
    pub auth_ratio: f64,
    pub attestation_score: f64,
    pub drain_applied: f64,
    pub certified: bool,
    pub actor_pk: Vec<u8>,
    pub nonce: Nonce,
    pub timestamp: i64,
    pub signature: Vec<u8>,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub accepted: bool,
    pub reason: Option<String>,
    pub event: Option<SecurityEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnvelope {
    pub allow_create: bool,
    pub allow_transfer: bool,
    pub allow_projection: bool,
    pub allow_cross_region: bool,
    pub allow_query: bool,
    pub allow_empty_payloads: bool,
    pub required_protocol_version: u32,
    pub min_auth_ratio: f64,
    pub min_attestation_score: f64,
    pub max_drain_rate: f64,
    pub max_payload_bytes: usize,
    pub max_parent_hashes: usize,
    pub max_nonce_len: usize,
    pub max_signature_bytes: usize,
    pub max_clock_skew_secs: i64,
}

impl Default for PolicyEnvelope {
    fn default() -> Self {
        Self {
            allow_create: true,
            allow_transfer: true,
            allow_projection: true,
            allow_cross_region: false,
            allow_query: true,
            allow_empty_payloads: true,
            required_protocol_version: 1,
            min_auth_ratio: 0.65,
            min_attestation_score: 0.50,
            max_drain_rate: 0.20,
            max_payload_bytes: 16 * 1024,
            max_parent_hashes: 32,
            max_nonce_len: 128,
            max_signature_bytes: 128,
            max_clock_skew_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub issuer: String,
    pub subject_wallet: WalletId,
    pub score: f64,
    pub note: String,
    pub issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEnvelope {
    pub request: SecurityRequest,
    pub context: SecurityContext,
    pub attestations: Vec<Attestation>,
}

#[derive(Debug, Clone)]
pub struct SecurityKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl SecurityKeyPair {
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }
}

pub fn signature_from_bytes(bytes: &[u8]) -> Result<Signature, String> {
    Signature::try_from(bytes).map_err(|e| e.to_string())
}
