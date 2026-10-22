use std::time::Instant;

use zk_sdk::{
    decode_artifact,
    files::{read_bounded, write_atomic},
    portable, PrivateInputs, ProvingKey, SecurityPolicy, Zk,
};

use crate::args::Flags;

const USAGE: &str = "usage:
  zk info
  zk setup   --r1cs F --pk F --vk F [--bits N] [--soundness unique|johnson|capacity]
  zk prove   --pk F --r1cs F --sym F --input F.json --proof F
  zk verify  --vk F --expected N,N,... --proof F
  zk inspect --proof F
  zk bench   --pk F --r1cs F --sym F --input F.json [--runs N]   (p50/p95/p99 per run)";

/// Largest circuit, key, witness or proof file this tool will load.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn sdk(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn timed<T>(label: &str, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let start = Instant::now();
    let value = work()?;
    println!("timing {label}_ms={}", start.elapsed().as_millis());
    Ok(value)
}

fn parse_policy(flags: &Flags) -> Result<SecurityPolicy, String> {
    let mut policy = SecurityPolicy::default();
    if let Some(bits) = flags.optional("bits") {
        policy.bits = bits.parse().map_err(|_| format!("bad --bits `{bits}`"))?;
    }
    if let Some(name) = flags.optional("soundness") {
        policy.soundness = name.parse().map_err(sdk)?;
    }
    Ok(policy)
}

fn parse_signals(list: &str) -> Result<Vec<u64>, String> {
    list.split(',')
        .map(|n| n.trim().parse().map_err(|_| format!("bad signal `{n}`")))
        .collect()
}

fn read(flags: &Flags, name: &str) -> Result<Vec<u8>, String> {
    read_bounded(flags.required(name)?, MAX_FILE_BYTES).map_err(sdk)
}

fn read_text(flags: &Flags, name: &str) -> Result<String, String> {
    String::from_utf8(read(flags, name)?).map_err(|_| format!("--{name} file is not UTF-8"))
}

fn write(flags: &Flags, name: &str, bytes: &[u8]) -> Result<(), String> {
    write_atomic(flags.required(name)?, bytes).map_err(sdk)
}

fn info() -> Result<(), String> {
    let caps = Zk::spartan_whir().capabilities();
    println!("backend {} ({})", caps.backend, caps.backend_version);
    println!("security bits {}..={}", caps.min_bits, caps.max_bits);
    println!("soundness {:?}", caps.soundness);
    println!("full zero knowledge {}", caps.full_zero_knowledge);
    println!("default policy {:?}", SecurityPolicy::default());
    Ok(())
}

fn setup(flags: &Flags) -> Result<(), String> {
    let zk = Zk::spartan_whir().with_policy(parse_policy(flags)?);
    let r1cs = read(flags, "r1cs")?;
    let keys = timed("setup", || portable::setup(&zk, r1cs).map_err(sdk))?;
    write(flags, "pk", &keys.proving)?;
    write(flags, "vk", &keys.verifying)
}

fn prove(flags: &Flags) -> Result<(), String> {
    let zk = Zk::spartan_whir();
    let (r1cs, sym, input) = (
        read(flags, "r1cs")?,
        read_text(flags, "sym")?,
        read_text(flags, "input")?,
    );
    let wtns = timed("witness", || {
        portable::witness(&zk, &r1cs, &sym, &input).map_err(sdk)
    })?;
    let pk = read(flags, "pk")?;
    let proof = timed("prove", || portable::prove(&zk, &pk, &wtns).map_err(sdk))?;
    write(flags, "proof", &proof)
}

/// The value at the given percentile (0-100) of an unsorted sample.
fn percentile(samples: &mut [u64], percent: usize) -> u64 {
    samples.sort_unstable();
    samples[(samples.len() - 1) * percent / 100]
}

fn bench(flags: &Flags) -> Result<(), String> {
    let runs: usize = flags
        .optional("runs")
        .unwrap_or("20")
        .parse()
        .map_err(|_| "bad --runs")?;
    if runs == 0 {
        return Err("--runs must be at least 1".into());
    }
    let zk = Zk::spartan_whir();
    let (r1cs, sym, input) = (
        read(flags, "r1cs")?,
        read_text(flags, "sym")?,
        read_text(flags, "input")?,
    );
    let wtns = portable::witness(&zk, &r1cs, &sym, &input).map_err(sdk)?;
    let key: ProvingKey = decode_artifact(&read(flags, "pk")?).map_err(sdk)?;
    let witness = PrivateInputs::from_wtns_bytes(wtns).map_err(sdk)?;
    let mut samples: Vec<Vec<u64>> = Vec::new();
    for _ in 0..runs {
        let output = zk.prove(&key, &witness).map_err(sdk)?;
        if samples.is_empty() {
            samples = output.phases.iter().map(|_| Vec::new()).collect();
        }
        for (column, phase) in samples.iter_mut().zip(&output.phases) {
            column.push(phase.micros);
        }
    }
    let names = zk.prove(&key, &witness).map_err(sdk)?.phases;
    let mut total: Vec<u64> = (0..runs)
        .map(|i| samples.iter().map(|c| c[i]).sum())
        .collect();
    for (phase, column) in names.iter().zip(&mut samples) {
        println!(
            "phase {:<20} median_us={} p95_us={}",
            phase.name,
            percentile(column, 50),
            percentile(column, 95)
        );
    }
    println!(
        "total runs={runs} p50_ms={} p95_ms={} p99_ms={}",
        percentile(&mut total, 50) / 1000,
        percentile(&mut total, 95) / 1000,
        percentile(&mut total, 99) / 1000
    );
    Ok(())
}

fn verify(flags: &Flags) -> Result<(), String> {
    let zk = Zk::spartan_whir();
    let expected = parse_signals(flags.required("expected")?)?;
    let (vk, proof) = (read(flags, "vk")?, read(flags, "proof")?);
    timed("verify", || {
        portable::verify(&zk, &vk, &expected, &proof).map_err(sdk)
    })?;
    println!("VALID");
    Ok(())
}

fn inspect(flags: &Flags) -> Result<(), String> {
    let metadata = portable::describe(&read(flags, "proof")?).map_err(sdk)?;
    println!("{metadata:?}");
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    let flags = |allowed: &[&str]| Flags::parse(rest, allowed);
    match command.as_str() {
        "info" => info(),
        "setup" => setup(&flags(&["r1cs", "pk", "vk", "bits", "soundness"])?),
        "prove" => prove(&flags(&["pk", "r1cs", "sym", "input", "proof"])?),
        "verify" => verify(&flags(&["vk", "expected", "proof"])?),
        "bench" => bench(&flags(&["pk", "r1cs", "sym", "input", "runs"])?),
        "inspect" => inspect(&flags(&["proof"])?),
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_parse_strictly() {
        assert_eq!(parse_signals("1, 18").unwrap(), vec![1, 18]);
        assert!(parse_signals("1,,2").is_err());
        assert!(parse_signals("-1").is_err());
        assert!(run(&[]).is_err());
        assert!(run(&["bogus".into()]).is_err());
    }
}
