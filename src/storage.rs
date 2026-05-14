use crate::errors::{SecurityError, SecurityResult};
use crate::types::SecurityEvent;
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub trait EventStore: Send + Sync + 'static {
    fn append(&self, event: &SecurityEvent) -> SecurityResult<()>;
    fn load_all(&self) -> SecurityResult<Vec<SecurityEvent>>;
}

pub trait ReplayStore: Send + Sync + 'static {
    fn remember_nonce(&self, nonce: &str) -> SecurityResult<()>;
    fn seen_nonce(&self, nonce: &str) -> SecurityResult<bool>;
    fn remember_event_hash(&self, event_hash: &str) -> SecurityResult<()>;
    fn seen_event_hash(&self, event_hash: &str) -> SecurityResult<bool>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryEventStore {
    inner: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl EventStore for MemoryEventStore {
    fn append(&self, event: &SecurityEvent) -> SecurityResult<()> {
        let mut guard = self.inner.lock().map_err(|_| SecurityError::Storage("event store lock poisoned".into()))?;
        guard.push(event.clone());
        Ok(())
    }

    fn load_all(&self) -> SecurityResult<Vec<SecurityEvent>> {
        let guard = self.inner.lock().map_err(|_| SecurityError::Storage("event store lock poisoned".into()))?;
        Ok(guard.clone())
    }
}

#[derive(Debug, Clone)]
pub struct FileEventStore {
    path: PathBuf,
}

impl FileEventStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn open_append(&self) -> SecurityResult<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SecurityError::Storage(e.to_string()))
    }
}

impl EventStore for FileEventStore {
    fn append(&self, event: &SecurityEvent) -> SecurityResult<()> {
        let line = to_string(event).map_err(|e| SecurityError::Serialization(e.to_string()))?;
        let mut file = self.open_append()?;
        writeln!(file, "{line}").map_err(|e| SecurityError::Storage(e.to_string()))
    }

    fn load_all(&self) -> SecurityResult<Vec<SecurityEvent>> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .open(&self.path)
            .map_err(|e| SecurityError::Storage(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| SecurityError::Storage(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let event: SecurityEvent = serde_json::from_str(&line)
                .map_err(|e| SecurityError::Serialization(e.to_string()))?;
            out.push(event);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct MemoryReplayStore {
    nonces: Arc<Mutex<VecDeque<String>>>,
    nonce_set: Arc<Mutex<HashSet<String>>>,
    event_hashes: Arc<Mutex<HashSet<String>>>,
    capacity: usize,
}

impl Default for MemoryReplayStore {
    fn default() -> Self {
        Self::new(50_000)
    }
}

impl MemoryReplayStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            nonces: Arc::new(Mutex::new(VecDeque::new())),
            nonce_set: Arc::new(Mutex::new(HashSet::new())),
            event_hashes: Arc::new(Mutex::new(HashSet::new())),
            capacity,
        }
    }

    fn trim(&self) -> SecurityResult<()> {
        let mut queue = self.nonces.lock().map_err(|_| SecurityError::Storage("replay queue lock poisoned".into()))?;
        let mut set = self.nonce_set.lock().map_err(|_| SecurityError::Storage("replay set lock poisoned".into()))?;
        while set.len() > self.capacity {
            if let Some(oldest) = queue.pop_front() {
                set.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(())
    }
}

impl ReplayStore for MemoryReplayStore {
    fn remember_nonce(&self, nonce: &str) -> SecurityResult<()> {
        let mut queue = self.nonces.lock().map_err(|_| SecurityError::Storage("replay queue lock poisoned".into()))?;
        let mut set = self.nonce_set.lock().map_err(|_| SecurityError::Storage("replay set lock poisoned".into()))?;
        if set.insert(nonce.to_string()) {
            queue.push_back(nonce.to_string());
        }
        drop(queue);
        drop(set);
        self.trim()
    }

    fn seen_nonce(&self, nonce: &str) -> SecurityResult<bool> {
        let set = self.nonce_set.lock().map_err(|_| SecurityError::Storage("replay set lock poisoned".into()))?;
        Ok(set.contains(nonce))
    }

    fn remember_event_hash(&self, event_hash: &str) -> SecurityResult<()> {
        let mut set = self.event_hashes.lock().map_err(|_| SecurityError::Storage("event hash lock poisoned".into()))?;
        set.insert(event_hash.to_string());
        Ok(())
    }

    fn seen_event_hash(&self, event_hash: &str) -> SecurityResult<bool> {
        let set = self.event_hashes.lock().map_err(|_| SecurityError::Storage("event hash lock poisoned".into()))?;
        Ok(set.contains(event_hash))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReplaySnapshot {
    nonces: Vec<String>,
    event_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FileReplayStore {
    path: PathBuf,
    inner: Arc<Mutex<ReplaySnapshot>>,
    capacity: usize,
}

impl FileReplayStore {
    pub fn new(path: impl Into<PathBuf>, capacity: usize) -> SecurityResult<Self> {
        let path = path.into();
        let snapshot = if path.exists() {
            let file = OpenOptions::new().read(true).open(&path).map_err(|e| SecurityError::Storage(e.to_string()))?;
            serde_json::from_reader::<_, ReplaySnapshot>(file).map_err(|e| SecurityError::Serialization(e.to_string()))?
        } else {
            ReplaySnapshot::default()
        };
        Ok(Self { path, inner: Arc::new(Mutex::new(snapshot)), capacity })
    }

    fn flush(&self) -> SecurityResult<()> {
        let snapshot = self.inner.lock().map_err(|_| SecurityError::Storage("replay snapshot lock poisoned".into()))?.clone();
        let file = OpenOptions::new().create(true).truncate(true).write(true).open(&self.path)
            .map_err(|e| SecurityError::Storage(e.to_string()))?;
        serde_json::to_writer_pretty(file, &snapshot).map_err(|e| SecurityError::Serialization(e.to_string()))
    }

    fn trim(snapshot: &mut ReplaySnapshot, capacity: usize) {
        if snapshot.nonces.len() > capacity {
            let drain = snapshot.nonces.len() - capacity;
            snapshot.nonces.drain(0..drain);
        }
        if snapshot.event_hashes.len() > capacity {
            let drain = snapshot.event_hashes.len() - capacity;
            snapshot.event_hashes.drain(0..drain);
        }
    }
}

impl ReplayStore for FileReplayStore {
    fn remember_nonce(&self, nonce: &str) -> SecurityResult<()> {
        {
            let mut snapshot = self.inner.lock().map_err(|_| SecurityError::Storage("replay snapshot lock poisoned".into()))?;
            if !snapshot.nonces.iter().any(|n| n == nonce) {
                snapshot.nonces.push(nonce.to_string());
            }
            Self::trim(&mut snapshot, self.capacity);
        }
        self.flush()
    }

    fn seen_nonce(&self, nonce: &str) -> SecurityResult<bool> {
        let snapshot = self.inner.lock().map_err(|_| SecurityError::Storage("replay snapshot lock poisoned".into()))?;
        Ok(snapshot.nonces.iter().any(|n| n == nonce))
    }

    fn remember_event_hash(&self, event_hash: &str) -> SecurityResult<()> {
        {
            let mut snapshot = self.inner.lock().map_err(|_| SecurityError::Storage("replay snapshot lock poisoned".into()))?;
            if !snapshot.event_hashes.iter().any(|h| h == event_hash) {
                snapshot.event_hashes.push(event_hash.to_string());
            }
            Self::trim(&mut snapshot, self.capacity);
        }
        self.flush()
    }

    fn seen_event_hash(&self, event_hash: &str) -> SecurityResult<bool> {
        let snapshot = self.inner.lock().map_err(|_| SecurityError::Storage("replay snapshot lock poisoned".into()))?;
        Ok(snapshot.event_hashes.iter().any(|h| h == event_hash))
    }
}
