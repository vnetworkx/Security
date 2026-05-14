use thiserror::Error;

pub type SecurityResult<T> = Result<T, SecurityError>;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("signature verification failed")]
    InvalidSignature,

    #[error("invalid request signature length")]
    InvalidSignatureLength,

    #[error("request replay detected")]
    ReplayDetected,

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("auth ratio below threshold: got {got}, required {required}")]
    AuthBelowThreshold { got: f64, required: f64 },

    #[error("attestation score below threshold: got {got}, required {required}")]
    AttestationBelowThreshold { got: f64, required: f64 },

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("internal error: {0}")]
    Internal(String),
}
