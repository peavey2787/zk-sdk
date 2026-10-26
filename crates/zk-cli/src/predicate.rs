//! `zk predicate ...`: file adapter over `zk_sdk::predicate`. All proving and verification goes
//! through the same typed engine as the Rust API and the browser.

use std::fs;

use zk_sdk::files::write_atomic;
use zk_sdk::predicate::{self, Groth16Setup, Predicates};

use crate::args::Flags;
use crate::groth16::{ceremony, read_pack, trust};
use crate::io::{read, read_text, sdk, timed, write};

pub const USAGE: &str = "  zk predicate commit   --type u32|i32|u64|i64|u128|i128 --value N --commitment F --secret F
                        [--scheme spartan-whir|groth16]
  zk predicate set      --type T --values F.json --commitment F [--scheme S]
  zk predicate path     --type T --values F.json --value N --proves member|absent --path F [--scheme S]
  zk predicate transition --spec F.json --claim F.json --open F.json
  zk predicate issue    --type T --entries F.json --out F.json [--scheme S]
  zk predicate present  --credential F --now UNIX_SECONDS [--options F.json] --claim F.json --secrets-prefix P
  zk predicate describe --claim F.json [--min-bits N] [SETUP]
  zk predicate prove    --claim F.json --secrets F[,F...] --proof F [--min-bits N] [SETUP]
  zk predicate verify   --claim F.json --proof F [--min-bits N] [SETUP]
--scheme: the proof system a commitment, set or issuer is made for (default spartan-whir:
  transparent and post-quantum); groth16 gives 128-byte proofs but needs a trusted setup and is not
  post-quantum; see docs/GROTH16_SETUP.md. Sets and issuers only serve claims of their own scheme
SETUP (groth16): --groth16-keys PACK (a trusted setup from `zk groth16 new`/`contribute`, or
  imported), checked against phase 1 on first use of each circuit (--groth16-dir D, --ptau F: see
  `zk groth16`); verifying also needs --groth16-trust F, a file of setup or key ids the verifier
  accepts (`zk groth16 verify --trust-out F` writes one)
--min-bits: authorize circuits that cannot reach the 116-bit default to run at the highest level
  they attain, but never below N (the larger arithmetic circuits attain 115); without it they fail
secrets: one file per committed value, in claim order (comma separated); a member/absent claim
  takes its path file (from `path`) as the last one
entries: a JSON array of {\"attribute\",\"serial\",\"expiry\"} (decimal strings); `issue` writes
  {\"issuer\",\"credentials\":[...]}: publish the issuer, give each holder one credential (a secret)
present: writes the claim and its secrets to P0, P1, ... (pass them to `prove` in that order);
  --options {\"also\":[claims using \"$attribute\"], \"revoked\":[serials]} adds claims and a revocation check
values: a JSON array of decimal strings, e.g. [\"10\",\"20\"]
claim: {\"kind\":\"opens\"|\"compare\"|\"range\"|\"compare_committed\"|\"sum\"|\"arithmetic\"|\"divide\"|\"member\"|\"absent\"|\"in_any_range\"|\"distance\"|\"credential\"|\"all\", ...};
see docs/PREDICATES.md";

fn commit(flags: &Flags) -> Result<(), String> {
    let made = predicate::commit(
        scheme(flags),
        flags.required("type")?,
        flags.required("value")?,
    )
    .map_err(sdk)?;
    write(flags, "commitment", made.commitment.as_bytes())?;
    write(flags, "secret", made.secret.as_bytes())?;
    println!("{}", made.commitment);
    Ok(())
}

fn scheme(flags: &Flags) -> &str {
    flags.optional("scheme").unwrap_or("spartan-whir")
}

fn set(flags: &Flags) -> Result<(), String> {
    let values = read_text(flags, "values")?;
    let commitment =
        predicate::set_commitment(scheme(flags), flags.required("type")?, &values).map_err(sdk)?;
    write(flags, "commitment", commitment.as_bytes())?;
    println!("{commitment}");
    Ok(())
}

fn path(flags: &Flags) -> Result<(), String> {
    let values = read_text(flags, "values")?;
    let absent = match flags.required("proves")? {
        "member" => false,
        "absent" => true,
        other => return Err(format!("--proves must be member or absent, got {other}")),
    };
    let path = predicate::set_path(
        scheme(flags),
        flags.required("type")?,
        &values,
        flags.required("value")?,
        absent,
    )
    .map_err(sdk)?;
    write(flags, "path", path.as_bytes())
}

/// The default 116-bit engine with the Groth16 setup of `--groth16-keys`, if any, lowered only as
/// far as `--min-bits` explicitly allows.
fn engine(flags: &Flags) -> Result<Predicates, String> {
    let mut engine = Predicates::new();
    if flags.optional("groth16-keys").is_some() {
        let keys = read_pack(flags, "groth16-keys")?;
        let setup = Groth16Setup::new(ceremony(flags)?, keys, trust(flags)?).map_err(sdk)?;
        engine = engine.with_groth16(setup);
    }
    match flags.optional("min-bits") {
        None => Ok(engine),
        Some(bits) => bits
            .parse()
            .map(|bits| engine.with_minimum_bits(bits))
            .map_err(|_| format!("--min-bits must be a number of bits, got {bits}")),
    }
}

fn transition(flags: &Flags) -> Result<(), String> {
    let lowered = predicate::transition_claim(&read_text(flags, "spec")?).map_err(sdk)?;
    write(flags, "claim", lowered.claim.as_bytes())?;
    write(flags, "open", lowered.open_json().as_bytes())
}

fn issue(flags: &Flags) -> Result<(), String> {
    let entries = read_text(flags, "entries")?;
    let issued = predicate::credential_issue(scheme(flags), flags.required("type")?, &entries)
        .map_err(sdk)?;
    write(flags, "out", issued.as_bytes())
}

fn present(flags: &Flags) -> Result<(), String> {
    let options = match flags.optional("options") {
        Some(_) => read_text(flags, "options")?,
        None => "{}".to_owned(),
    };
    let presented = predicate::credential_present(
        &read_text(flags, "credential")?,
        flags.required("now")?,
        &options,
    )
    .map_err(sdk)?;
    write(flags, "claim", presented.claim().as_bytes())?;
    let prefix = flags.required("secrets-prefix")?;
    presented
        .secrets
        .iter()
        .enumerate()
        .try_for_each(|(i, secret)| {
            write_atomic(format!("{prefix}{i}"), secret.as_bytes()).map_err(sdk)
        })
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
        predicate::prove(&zk, &claim, secrets).map_err(sdk)
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

/// The flags every command that builds an engine takes.
const ENGINE_FLAGS: [&str; 5] = [
    "min-bits",
    "groth16-dir",
    "groth16-keys",
    "groth16-trust",
    "ptau",
];

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    let flags = |allowed: &[&str]| Flags::parse(rest, allowed);
    match command.as_str() {
        "commit" => commit(&flags(&[
            "type",
            "value",
            "commitment",
            "secret",
            "scheme",
        ])?),
        "set" => set(&flags(&["type", "values", "commitment", "scheme"])?),
        "path" => path(&flags(&[
            "type", "values", "value", "proves", "path", "scheme",
        ])?),
        "transition" => transition(&flags(&["spec", "claim", "open"])?),
        "issue" => issue(&flags(&["type", "entries", "out", "scheme"])?),
        "present" => present(&flags(&[
            "credential",
            "now",
            "options",
            "claim",
            "secrets-prefix",
        ])?),
        "describe" => describe(&flags(&[ENGINE_FLAGS.as_slice(), &["claim"]].concat())?),
        "prove" => prove(&flags(
            &[ENGINE_FLAGS.as_slice(), &["claim", "secrets", "proof"]].concat(),
        )?),
        "verify" => verify(&flags(
            &[ENGINE_FLAGS.as_slice(), &["claim", "proof"]].concat(),
        )?),
        _ => Err(USAGE.into()),
    }
}
