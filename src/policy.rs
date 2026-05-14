use crate::errors::{SecurityError, SecurityResult};
use crate::types::{OperationKind, PolicyEnvelope, SecurityContext, SecurityRequest};

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub rules: PolicyRuleSet,
}

#[derive(Debug, Clone)]
pub struct PolicyRuleSet {
    pub envelope: PolicyEnvelope,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            rules: PolicyRuleSet {
                envelope: PolicyEnvelope::default(),
            },
        }
    }
}

impl PolicyEngine {
    pub fn with_envelope(envelope: PolicyEnvelope) -> Self {
        Self { rules: PolicyRuleSet { envelope } }
    }

    pub fn envelope(&self) -> &PolicyEnvelope {
        &self.rules.envelope
    }

    pub fn validate(&self, ctx: &SecurityContext, req: &SecurityRequest) -> SecurityResult<()> {
        let env = &self.rules.envelope;

        req.validate_basic().map_err(SecurityError::InvalidRequest)?;
        ctx.validate().map_err(SecurityError::InvalidRequest)?;

        if req.protocol_version != env.required_protocol_version {
            return Err(SecurityError::PolicyViolation(format!(
                "unsupported protocol version: {} != {}",
                req.protocol_version, env.required_protocol_version
            )));
        }

        if req.payload.len() > env.max_payload_bytes {
            return Err(SecurityError::PolicyViolation(format!(
                "payload too large: {} > {}",
                req.payload.len(), env.max_payload_bytes
            )));
        }

        if req.payload.is_empty() && !env.allow_empty_payloads {
            return Err(SecurityError::PolicyViolation("empty payloads are disabled".into()));
        }

        if req.parent_event_hashes.len() > env.max_parent_hashes {
            return Err(SecurityError::PolicyViolation(format!(
                "too many parent hashes: {} > {}",
                req.parent_event_hashes.len(), env.max_parent_hashes
            )));
        }

        if req.nonce.0.len() > env.max_nonce_len {
            return Err(SecurityError::PolicyViolation(format!(
                "nonce too long: {} > {}",
                req.nonce.0.len(), env.max_nonce_len
            )));
        }

        if req.signature.len() > env.max_signature_bytes {
            return Err(SecurityError::PolicyViolation(format!(
                "signature too long: {} > {}",
                req.signature.len(), env.max_signature_bytes
            )));
        }

        if ctx.auth_ratio < env.min_auth_ratio {
            return Err(SecurityError::AuthBelowThreshold { got: ctx.auth_ratio, required: env.min_auth_ratio });
        }

        if req.region_id != ctx.region_id && !env.allow_cross_region {
            return Err(SecurityError::PolicyViolation("cross-region operations disabled".into()));
        }

        let drift = (ctx.timestamp - req.timestamp).abs();
        if drift > env.max_clock_skew_secs {
            return Err(SecurityError::PolicyViolation(format!(
                "timestamp drift too large: {}s > {}s",
                drift, env.max_clock_skew_secs
            )));
        }

        if let OperationKind::Custom(kind) = &req.operation {
            if kind.trim().is_empty() {
                return Err(SecurityError::PolicyViolation("custom operation name is empty".into()));
            }
        }

        match &req.operation {
            OperationKind::Create if !env.allow_create => {
                return Err(SecurityError::PolicyViolation("CREATE is disabled".into()));
            }
            OperationKind::Transfer if !env.allow_transfer => {
                return Err(SecurityError::PolicyViolation("TRANSFER is disabled".into()));
            }
            OperationKind::Project if !env.allow_projection => {
                return Err(SecurityError::PolicyViolation("PROJECT is disabled".into()));
            }
            OperationKind::Query if !env.allow_query => {
                return Err(SecurityError::PolicyViolation("QUERY is disabled".into()));
            }
            _ => {}
        }

        Ok(())
    }

    pub fn drain_rate_for(&self, op: &OperationKind) -> f64 {
        match op {
            OperationKind::Transfer | OperationKind::Project => self.rules.envelope.max_drain_rate,
            OperationKind::Move | OperationKind::Rotate | OperationKind::Scale => 0.02,
            OperationKind::Create => 0.0,
            _ => 0.0,
        }
    }
}
