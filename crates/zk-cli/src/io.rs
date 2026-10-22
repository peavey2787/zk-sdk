//! File and timing helpers shared by the CLI commands.

use std::time::Instant;

use zk_sdk::files::{read_bounded, write_atomic};

use crate::args::Flags;

/// Largest circuit, key, witness or proof file this tool will load.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub fn sdk(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub fn timed<T>(label: &str, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let start = Instant::now();
    let value = work()?;
    println!("timing {label}_ms={}", start.elapsed().as_millis());
    Ok(value)
}

pub fn read(flags: &Flags, name: &str) -> Result<Vec<u8>, String> {
    read_bounded(flags.required(name)?, MAX_FILE_BYTES).map_err(sdk)
}

pub fn read_text(flags: &Flags, name: &str) -> Result<String, String> {
    String::from_utf8(read(flags, name)?).map_err(|_| format!("--{name} file is not UTF-8"))
}

pub fn write(flags: &Flags, name: &str, bytes: &[u8]) -> Result<(), String> {
    write_atomic(flags.required(name)?, bytes).map_err(sdk)
}
