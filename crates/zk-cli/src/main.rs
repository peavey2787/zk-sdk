//! `zk`: file-based adapter over the SDK facade. Contains no cryptography of its own.
mod args;
mod commands;

use std::process::ExitCode;

/// Optimized builds (`scripts/build_optimized.py`) assume AVX2 and BMI2; refuse to run on a CPU
/// without them instead of crashing on an illegal instruction. Portable builds never check.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn cpu_supported() -> bool {
    is_x86_feature_detected!("avx2") && is_x86_feature_detected!("bmi2")
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
fn cpu_supported() -> bool {
    true
}

fn main() -> ExitCode {
    if !cpu_supported() {
        eprintln!("error: this build is the optimized build and needs a CPU with AVX2 and BMI2; use the default build");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match commands::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
