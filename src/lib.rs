#![forbid(unsafe_code)]

//! Vector Security Layer
//!
//! This crate provides the security-facing boundary for the Vector Network.
//! It validates identity binding, request integrity, replay safety, policy
//! compliance, and immutable audit emission before any state transition is
//! allowed to reach the kernel.
//!
//! The crate is intentionally split into small modules:
//! - `crypto`: canonical signing, verification, and hashing helpers
//! - `policy`: enforcement of request, region, and payload rules
//! - `replay`: fast in-memory replay guard
//! - `storage`: optional persistence helpers and reference stores
//! - `attestation`: deterministic attestation aggregation
//! - `audit`: append-only audit trail helpers
//! - `engine`: high-level validation pipeline
//!
//! The design goal is to keep the security layer deterministic, auditable,
//! and simple enough to sit in front of a protocol kernel without becoming
//! the source of truth itself.

pub mod audit;
pub mod attestation;
pub mod config;
pub mod crypto;
pub mod engine;
pub mod errors;
pub mod policy;
pub mod replay;
pub mod storage;
pub mod types;

pub use audit::{AuditLog, AuditSink};
pub use attestation::{AttestationScore, AttestationSet, AttestationSummary};
pub use config::SecurityConfig;
pub use crypto::{generate_signing_key, sign_request, verifying_key_bytes};
pub use engine::{SecurityEngine, SecurityEngineBuilder};
pub use errors::{SecurityError, SecurityResult};
pub use policy::{PolicyEngine, PolicyRuleSet};
pub use replay::ReplayGuard;
pub use storage::{EventStore, FileEventStore, FileReplayStore, MemoryEventStore, MemoryReplayStore, ReplayStore};
pub use types::*;
