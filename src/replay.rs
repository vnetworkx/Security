use crate::errors::{SecurityError, SecurityResult};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct ReplayGuard {
    seen_nonces: HashSet<String>,
    seen_event_hashes: HashSet<String>,
    nonce_order: VecDeque<String>,
    capacity: usize,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self {
            seen_nonces: HashSet::new(),
            seen_event_hashes: HashSet::new(),
            nonce_order: VecDeque::new(),
            capacity: 50_000,
        }
    }
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    pub fn check_nonce(&self, nonce: &str) -> SecurityResult<()> {
        if self.seen_nonces.contains(nonce) {
            Err(SecurityError::ReplayDetected)
        } else {
            Ok(())
        }
    }

    pub fn remember_nonce(&mut self, nonce: impl Into<String>) {
        let nonce = nonce.into();
        if self.seen_nonces.insert(nonce.clone()) {
            self.nonce_order.push_back(nonce);
            self.enforce_capacity();
        }
    }

    pub fn remember_event_hash(&mut self, event_hash: impl Into<String>) {
        self.seen_event_hashes.insert(event_hash.into());
    }

    pub fn check_event_hash(&self, event_hash: &str) -> SecurityResult<()> {
        if self.seen_event_hashes.contains(event_hash) {
            Err(SecurityError::ReplayDetected)
        } else {
            Ok(())
        }
    }

    pub fn seen_count(&self) -> usize {
        self.seen_nonces.len()
    }

    fn enforce_capacity(&mut self) {
        while self.seen_nonces.len() > self.capacity {
            if let Some(oldest) = self.nonce_order.pop_front() {
                self.seen_nonces.remove(&oldest);
            } else {
                break;
            }
        }
    }
}
