use crate::types::SecurityEvent;
use blake3::Hasher;
use std::sync::{Arc, Mutex};

pub trait AuditSink: Send + Sync + 'static {
    fn append(&self, event: SecurityEvent);
    fn list(&self) -> Vec<SecurityEvent>;
    fn len(&self) -> usize;
}

#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    inner: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn latest(&self) -> Option<SecurityEvent> {
        self.inner.lock().expect("audit log lock poisoned").last().cloned()
    }

    /// Computes a chain head over the event hashes to make the log easier to
    /// checkpoint and compare across nodes.
    pub fn chain_head(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(b"vector-security-audit-v1");
        for event in self.list() {
            hasher.update(event.event_hash.as_bytes());
            hasher.update(&[0]);
        }
        hasher.finalize().to_hex().to_string()
    }
}

impl AuditSink for AuditLog {
    fn append(&self, event: SecurityEvent) {
        let mut guard = self.inner.lock().expect("audit log lock poisoned");
        guard.push(event);
    }

    fn list(&self) -> Vec<SecurityEvent> {
        self.inner.lock().expect("audit log lock poisoned").clone()
    }

    fn len(&self) -> usize {
        self.inner.lock().expect("audit log lock poisoned").len()
    }
}
