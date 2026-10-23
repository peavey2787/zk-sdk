//! `zk predicate ...`: file adapter over `zk_sdk::predicate`. All proving and verification goes
//! through the same typed engine as the Rust API and the browser.

use std::fs;

use zk_sdk::predicate::{self, Predicates};

use crate::args::Flags;
use crate::io::{read, read_text, sdk, timed, write};

pub const USAGE: &str = "  zk predicate commit   --type u32|i32|u64|i64|u128|i128 --value N --commitment F --secret F
  zk predicate describe --claim F.json [--min-bits N]
  zk predicate prove    --claim F.json --secrets F[,F...] --proof F [--min-bits N]
  zk predicate verify   --claim F.json --proof F [--min-bits N]
--min-bits: authorize circuits that cannot reach the 116-bit default to run at the highest level
  they attain, but never below N (the larger arithmetic circuits attain 115); without it they fail
secrets: one file per committed value, in claim order (comma separated)
claim: {\"kind\":\"opens\"|\"compare\"|\"range\"|\"compare_committed\"|\"sum\"|\"arithmetic\"|\"divide\", ...};
see docs/PREDICATES.md";

fn commit(flags: &Flags) -> Result<(), String> {
    let made = predicate::commit(flags.required("type")?, flags.required("value")?).map_err(sdk)?;
    write(flags, "commitment", made.commitment.as_bytes())?;
    write(flags, "secret", made.secret.as_bytes())?;
    println!("{}", made.commitment);
    Ok(())
}

/// The default 116-bit engine, lowered only as far as `--min-bits` explicitly allows.
fn engine(flags: &Flags) -> Result<Predicates, String> {
    let engine = Predicates::new();
    match flags.optional("min-bits") {
        None => Ok(engine),
        Some(bits) => bits
            .parse()
            .map(|bits| engine.with_minimum_bits(bits))
            .map_err(|_| format!("--min-bits must be a number of bits, got {bits}")),
    }
}

fn prove(flags: &Flags) -> Result<(), String> {
    let secrets = flags
        .required("secrets")?
        .split(',')
        .map(|file| fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let claim = read_text(flags, "claim")?;
    let zk = engine(flags)?;
    let proof = timed("prove", || {
        predicate::prove(&zk, &claim, &secrets).map_err(sdk)
    })?;
    write(flags, "proof", &proof)
}

fn verify(flags: &Flags) -> Result<(), String> {
    let (claim, proof) = (read_text(flags, "claim")?, read(flags, "proof")?);
    let zk = engine(flags)?;
    timed("verify", || {
        predicate::verify(&zk, &claim, &proof).map_err(sdk)
    })?;
    println!("VALID");
    Ok(())
}

fn describe(flags: &Flags) -> Result<(), String> {
    println!(
        "{}",
        predicate::describe(&engine(flags)?, &read_text(flags, "claim")?).map_err(sdk)?
    );
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    let flags = |allowed: &[&str]| Flags::parse(rest, allowed);
    match command.as_str() {
        "commit" => commit(&flags(&["type", "value", "commitment", "secret"])?),
        "describe" => describe(&flags(&["claim", "min-bits"])?),
        "prove" => prove(&flags(&["claim", "secrets", "proof", "min-bits"])?),
        "verify" => verify(&flags(&["claim", "proof", "min-bits"])?),
        _ => Err(USAGE.into()),
    }
}
