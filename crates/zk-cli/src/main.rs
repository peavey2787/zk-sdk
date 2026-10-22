//! `zk`: file-based adapter over the SDK facade. Contains no cryptography of its own.
mod args;
mod commands;

use std::process::ExitCode;

/// The build targets x86-64-v3 (see .cargo/config.toml); refuse to run elsewhere instead of
/// crashing on an illegal instruction.
#[cfg(target_arch = "x86_64")]
fn cpu_supported() -> bool {
    is_x86_feature_detected!("avx2") && is_x86_feature_detected!("bmi2")
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_supported() -> bool {
    true
}

fn main() -> ExitCode {
    if !cpu_supported() {
        eprintln!("error: this build requires a CPU with AVX2 and BMI2 (x86-64-v3)");
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
