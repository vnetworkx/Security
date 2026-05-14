use crate::errors::{SecurityError, SecurityResult};
use crate::types::{Attestation, WalletId};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttestationScore {
    pub score: f64,
    pub threshold: f64,
}

impl AttestationScore {
    pub fn passed(&self) -> bool {
        self.score >= self.threshold
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttestationSummary {
    pub count: usize,
    pub mean_score: f64,
    pub min_score: f64,
    pub max_score: f64,
}

/// AttestationSet computes a compact trust summary from a list of attestations.
///
/// In production deployments, attestations may come from validator clusters,
/// compliance systems, hardware attestation services, or domain-specific policy
/// engines. The security layer does not assume any one attestation model; it
/// only reduces the envelope into a deterministic score that can be checked
/// before state mutation.
#[derive(Debug, Clone, Default)]
pub struct AttestationSet {
    items: Vec<Attestation>,
}

impl AttestationSet {
    pub fn new(items: Vec<Attestation>) -> Self {
        Self { items }
    }

    pub fn items(&self) -> &[Attestation] {
        &self.items
    }

    pub fn count(&self) -> usize {
        self.items.len()
    }

    pub fn total_score(&self) -> f64 {
        if self.items.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.items.iter().map(|a| a.score.clamp(0.0, 1.0)).sum();
        (sum / self.items.len() as f64).clamp(0.0, 1.0)
    }

    pub fn summary(&self) -> AttestationSummary {
        if self.items.is_empty() {
            return AttestationSummary { count: 0, mean_score: 0.0, min_score: 0.0, max_score: 0.0 };
        }
        let mut min_score = 1.0;
        let mut max_score = 0.0;
        let mut sum = 0.0;
        for item in &self.items {
            let score = item.score.clamp(0.0, 1.0);
            min_score = min_score.min(score);
            max_score = max_score.max(score);
            sum += score;
        }
        AttestationSummary {
            count: self.items.len(),
            mean_score: (sum / self.items.len() as f64).clamp(0.0, 1.0),
            min_score,
            max_score,
        }
    }

    pub fn validate_subject(&self, wallet_id: &WalletId) -> SecurityResult<()> {
        for att in &self.items {
            if &att.subject_wallet != wallet_id {
                return Err(SecurityError::PolicyViolation(format!(
                    "attestation subject mismatch: expected {}, saw {}",
                    wallet_id.0, att.subject_wallet.0
                )));
            }
        }
        Ok(())
    }

    pub fn require_min_score(&self, threshold: f64) -> SecurityResult<AttestationScore> {
        let score = self.total_score();
        if score < threshold {
            return Err(SecurityError::AttestationBelowThreshold { got: score, required: threshold });
        }
        Ok(AttestationScore { score, threshold })
    }
}
