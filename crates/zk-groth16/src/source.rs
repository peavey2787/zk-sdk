//! Where circuit artifacts (`<name>.r1cs`, `<name>.sym`) come from: a directory on disk, or bytes
//! handed over by the host (the browser fetches them). A source is untrusted; every artifact is
//! checked against its approved hash before use.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::{Groth16Error, Result};

/// Artifact bytes by file name.
pub trait Source: Send + Sync {
    fn read(&self, file: &str) -> Result<Arc<[u8]>>;
}

/// Artifacts in one directory.
pub struct Directory(PathBuf);

impl Directory {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
}

impl Source for Directory {
    fn read(&self, file: &str) -> Result<Arc<[u8]>> {
        std::fs::read(self.0.join(file))
            .map(Arc::from)
            .map_err(|e| Groth16Error::Missing(format!("{}: {e}", self.0.join(file).display())))
    }
}

/// Artifacts held in memory.
#[derive(Default)]
pub struct Memory(Mutex<HashMap<String, Arc<[u8]>>>);

impl Memory {
    pub fn insert(&self, file: &str, bytes: Vec<u8>) {
        self.map().insert(file.to_owned(), Arc::from(bytes));
    }

    pub fn contains(&self, file: &str) -> bool {
        self.map().contains_key(file)
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<[u8]>>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Source for Memory {
    fn read(&self, file: &str) -> Result<Arc<[u8]>> {
        self.map()
            .get(file)
            .cloned()
            .ok_or_else(|| Groth16Error::Missing(file.to_owned()))
    }
}
