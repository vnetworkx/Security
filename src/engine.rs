use crate::attestation::AttestationSet;
use crate::crypto::{domain_hash, hash_bytes, hash_event, hash_request, public_key_from_bytes, verify_request_signature};
use crate::errors::{SecurityError, SecurityResult};
use crate::policy::PolicyEngine;
use crate::storage::{EventStore, MemoryEventStore, MemoryReplayStore, ReplayStore};
use crate::audit::{AuditLog, AuditSink};
use crate::types::{EventId, SecurityContext, SecurityDecision, SecurityEnvelope, SecurityEvent, SecurityRequest};
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Clone)]
pub struct SecurityEngine {
    policy: PolicyEngine,
    replay: Arc<dyn ReplayStore>,
    audit: Arc<dyn AuditSink>,
    events: Arc<dyn EventStore>,
    attestation_threshold: f64,
    node_label: String,
}

impl core::fmt::Debug for SecurityEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityEngine")
            .field("policy", &self.policy)
            .field("attestation_threshold", &self.attestation_threshold)
            .field("node_label", &self.node_label)
            .finish_non_exhaustive()
    }
}

impl SecurityEngine {
    pub fn new(policy: PolicyEngine) -> Self {
        Self::builder(policy).build()
    }

    pub fn builder(policy: PolicyEngine) -> SecurityEngineBuilder {
        SecurityEngineBuilder::new(policy)
    }

    pub fn with_attestation_threshold(mut self, threshold: f64) -> Self {
        self.attestation_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn audit_log(&self) -> Vec<crate::types::SecurityEvent> {
        self.audit.list()
    }

    pub fn validate(&self, envelope: &SecurityEnvelope) -> SecurityResult<SecurityDecision> {
        let ctx = &envelope.context;
        let req = &envelope.request;

        self.policy.validate(ctx, req)?;
        self.validate_key_binding(ctx, req)?;
        self.validate_attestations(ctx, envelope)?;
        self.validate_replay(req)?;
        let verifying_key = public_key_from_bytes(&ctx.verified_public_key)?;
        verify_request_signature(&verifying_key, req)?;

        let request_hash = hash_request(req)?;
        let payload_hash = hash_bytes(&req.payload);
        let attestation_score = AttestationSet::new(envelope.attestations.clone()).total_score();
        let drain_applied = self.policy.drain_rate_for(&req.operation);
        let attestation_gate = envelope.attestations.is_empty()
            || attestation_score >= self.attestation_threshold.max(self.policy.envelope().min_attestation_score);
        let certified = ctx.auth_ratio >= ctx.cert_threshold && attestation_gate;

        if ctx.auth_ratio < ctx.cert_threshold {
            return Err(SecurityError::AuthBelowThreshold { got: ctx.auth_ratio, required: ctx.cert_threshold });
        }
        if !attestation_gate {
            return Err(SecurityError::AttestationBelowThreshold {
                got: attestation_score,
                required: self.attestation_threshold.max(self.policy.envelope().min_attestation_score),
            });
        }

        let mut event = self.build_event(ctx, req, request_hash, payload_hash, attestation_score, drain_applied, certified)?;
        let event_hash = hash_event(&event)?;
        event.event_hash = event_hash.clone();

        self.validate_replay_hash(&event_hash)?;
        self.events.append(&event)?;
        self.audit.append(event.clone());
        self.record_seen(req, &event_hash)?;

        info!(
            wallet = %ctx.wallet_id.0,
            region = %ctx.region_id.0,
            operation = %req.operation,
            accepted = true,
            certified = certified,
            node = %self.node_label,
            "security request accepted"
        );
        Ok(SecurityDecision { accepted: true, reason: None, event: Some(event) })
    }

    pub fn reject(&self, reason: impl Into<String>) -> SecurityDecision {
        SecurityDecision { accepted: false, reason: Some(reason.into()), event: None }
    }

    pub async fn validate_async(&self, envelope: SecurityEnvelope) -> SecurityResult<SecurityDecision> {
        tokio::task::yield_now().await;
        self.validate(&envelope)
    }

    fn validate_key_binding(&self, ctx: &SecurityContext, req: &SecurityRequest) -> SecurityResult<()> {
        let wallet = &req.wallet_id.0;
        let ctx_wallet = &ctx.wallet_id.0;
        if wallet != ctx_wallet {
            return Err(SecurityError::PolicyViolation(format!(
                "wallet mismatch: request={} context={}",
                wallet, ctx_wallet
            )));
        }
        if req.region_id != ctx.region_id && !self.policy.envelope().allow_cross_region {
            return Err(SecurityError::PolicyViolation(format!(
                "region mismatch: request={} context={}",
                req.region_id.0, ctx.region_id.0
            )));
        }
        Ok(())
    }

    fn validate_replay(&self, req: &SecurityRequest) -> SecurityResult<()> {
        if self.replay.seen_nonce(&req.nonce.0)? {
            return Err(SecurityError::ReplayDetected);
        }
        Ok(())
    }

    fn validate_replay_hash(&self, event_hash: &str) -> SecurityResult<()> {
        if self.replay.seen_event_hash(event_hash)? {
            return Err(SecurityError::ReplayDetected);
        }
        Ok(())
    }

    fn validate_attestations(&self, ctx: &SecurityContext, envelope: &SecurityEnvelope) -> SecurityResult<()> {
        let set = AttestationSet::new(envelope.attestations.clone());
        set.validate_subject(&ctx.wallet_id)?;
        let score = set.total_score();
        if !envelope.attestations.is_empty() && score < self.attestation_threshold {
            return Err(SecurityError::AttestationBelowThreshold {
                got: score,
                required: self.attestation_threshold,
            });
        }
        Ok(())
    }

    fn record_seen(&self, req: &SecurityRequest, event_hash: &str) -> SecurityResult<()> {
        self.replay.remember_nonce(&req.nonce.0)?;
        self.replay.remember_event_hash(event_hash)?;
        Ok(())
    }

    fn build_event(
        &self,
        ctx: &SecurityContext,
        req: &SecurityRequest,
        request_hash: String,
        payload_hash: String,
        attestation_score: f64,
        drain_applied: f64,
        certified: bool,
    ) -> SecurityResult<SecurityEvent> {
        let event_id = EventId(domain_hash(
            "vector-security-event-id",
            format!("{}:{}:{}:{}", req.nonce.0, ctx.wallet_id.0, ctx.region_id.0, req.timestamp).as_bytes(),
        ));

        let event = SecurityEvent {
            event_id,
            protocol_version: req.protocol_version,
            parent_hashes: req.parent_event_hashes.clone(),
            region_id: ctx.region_id.clone(),
            entity_id: ctx.wallet_id.clone(),
            operation: req.operation.clone(),
            request_hash,
            payload_hash,
            auth_ratio: ctx.auth_ratio,
            attestation_score,
            drain_applied,
            certified,
            actor_pk: ctx.verified_public_key.clone(),
            nonce: req.nonce.clone(),
            timestamp: req.timestamp,
            signature: req.signature.clone(),
            event_hash: String::new(),
        };

        debug!(
            wallet = %ctx.wallet_id.0,
            operation = %req.operation,
            certified = certified,
            parents = req.parent_event_hashes.len(),
            attestation_score = attestation_score,
            "built security event"
        );
        Ok(event)
    }
}

#[derive(Clone)]
pub struct SecurityEngineBuilder {
    policy: PolicyEngine,
    replay: Arc<dyn ReplayStore>,
    audit: Arc<dyn AuditSink>,
    events: Arc<dyn EventStore>,
    attestation_threshold: f64,
    node_label: String,
}

impl core::fmt::Debug for SecurityEngineBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityEngineBuilder")
            .field("policy", &self.policy)
            .field("attestation_threshold", &self.attestation_threshold)
            .field("node_label", &self.node_label)
            .finish_non_exhaustive()
    }
}

impl SecurityEngineBuilder {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            replay: Arc::new(MemoryReplayStore::default()),
            audit: Arc::new(AuditLog::new()),
            events: Arc::new(MemoryEventStore::default()),
            attestation_threshold: 0.50,
            node_label: "local-node".to_string(),
        }
    }

    pub fn attestation_threshold(mut self, threshold: f64) -> Self {
        self.attestation_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn node_label(mut self, label: impl Into<String>) -> Self {
        self.node_label = label.into();
        self
    }

    pub fn replay_store(mut self, replay: Arc<dyn ReplayStore>) -> Self {
        self.replay = replay;
        self
    }

    pub fn audit_sink(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = audit;
        self
    }

    pub fn event_store(mut self, events: Arc<dyn EventStore>) -> Self {
        self.events = events;
        self
    }

    pub fn build(self) -> SecurityEngine {
        SecurityEngine {
            policy: self.policy,
            replay: self.replay,
            audit: self.audit,
            events: self.events,
            attestation_threshold: self.attestation_threshold,
            node_label: self.node_label,
        }
    }
}
