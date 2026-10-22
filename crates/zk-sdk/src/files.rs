//! Native-only file adapters. Everything else in the SDK is byte-oriented and portable.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use serde::{de::DeserializeOwned, Serialize};
use zk_core::{decode_artifact, encode_artifact, Result, ZkError, MAX_ARTIFACT_BYTES};

/// Read a whole file, refusing anything above `max` bytes before allocating.
pub fn read_bounded(path: impl AsRef<Path>, max: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > max {
        return Err(ZkError::Format(format!("file exceeds {max} byte limit")));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Write via a sibling temporary file and rename, so readers never see a partial artifact.
pub fn write_atomic(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut temp = tempfile::NamedTempFile::new_in(parent.unwrap_or_else(|| Path::new(".")))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| ZkError::Io(e.error))?;
    Ok(())
}

pub fn save_artifact<T: Serialize>(path: impl AsRef<Path>, value: &T) -> Result<()> {
    write_atomic(path, &encode_artifact(value)?)
}

pub fn load_artifact<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    decode_artifact(&read_bounded(path, MAX_ARTIFACT_BYTES + 16)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.zk");
        save_artifact(&path, &vec![1u64, 2, 3]).unwrap();
        assert_eq!(load_artifact::<Vec<u64>>(&path).unwrap(), vec![1, 2, 3]);
        assert!(read_bounded(&path, 4).is_err());
        assert!(read_bounded(dir.path().join("missing"), 4).is_err());
    }

    #[test]
    fn tampered_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.zk");
        save_artifact(&path, &vec![1u64]).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        write_atomic(&path, &bytes).unwrap();
        assert!(load_artifact::<Vec<u64>>(&path).is_err());
    }
}
