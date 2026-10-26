//! `zk groth16 ...`: trusted setups for the Groth16 predicate circuits. Starting keys are derived
//! from a published Powers of Tau file, contributions are sequential and recorded in snarkjs's
//! format, and every key can be re-verified by anyone (here or with `snarkjs zkey verify`).

use std::fs;
use std::path::{Path, PathBuf};

use zk_sdk::predicate::{
    self, Beacon, Ceremony, Contribution, KeyPack, KeyReport, SetupReport, Trust,
};

use crate::args::Flags;
use crate::io::{read, sdk, write};

pub const USAGE: &str = "  zk groth16 phase1     [SOURCE]
  zk groth16 new        --circuits all|C[,C...] --out PACK [CONTRIBUTION] [SOURCE]
  zk groth16 contribute --keys PACK --out PACK [CONTRIBUTION] [SOURCE]
  zk groth16 verify     --keys PACK [--trust-out F] [SOURCE]
  zk groth16 initial    --circuit C --out F.zkey [SOURCE]
  zk groth16 export     --keys PACK --dir D
  zk groth16 import     --dir D --circuits all|C[,C...] --out PACK
new: a new setup (each circuit's starting key plus your contribution); contribute: verifies a setup,
  then adds your contribution to every key; verify: checks every key against phase 1, prints the
  setup id and each contribution, and with --trust-out writes the setup id for --groth16-trust;
  initial: a circuit's starting key (byte-identical to `snarkjs zkey new`); export/import: one
  <circuit>.zkey per key, for snarkjs (an imported pack is checked when used)
CONTRIBUTION: [--name TEXT] [--beacon HEX --beacon-exponent N]: fresh entropy (discarded at once) by
  default, or a public beacon (2^N SHA-256 iterations, N from 10 to 28) anyone can recompute
SOURCE: --groth16-dir D (approved r1cs and sym; default $ZK_GROTH16_DIR, a groth16 directory beside
  zk, or testdata/groth16) --ptau F (a published Hermez powersOfTau28_hez_final_NN.ptau, NN >= 14;
  default $ZK_PTAU, a ptau directory beside zk, or target/ptau; fetch with
  `python scripts/groth16_setup.py --fetch`)";

const SOURCE: [&str; 2] = ["groth16-dir", "ptau"];
const CONTRIBUTION: [&str; 3] = ["name", "beacon", "beacon-exponent"];

fn path(flags: &Flags, name: &str) -> Option<PathBuf> {
    flags.optional(name).map(PathBuf::from)
}

/// The ceremony over `--groth16-dir` and `--ptau`.
pub fn ceremony(flags: &Flags) -> Result<Ceremony, String> {
    predicate::load_ceremony(path(flags, "groth16-dir"), path(flags, "ptau")).map_err(sdk)
}

pub fn read_pack(flags: &Flags, name: &str) -> Result<KeyPack, String> {
    KeyPack::from_bytes(&read(flags, name)?).map_err(sdk)
}

fn progress(verb: &'static str) -> impl FnMut(&str, usize, usize) {
    move |circuit, done, total| eprint!("\r{verb} {done}/{total} {circuit:<24}")
}

fn circuits(flags: &Flags) -> Result<Vec<String>, String> {
    match flags.required("circuits")? {
        "all" => Ok(predicate::groth16_circuits()),
        list => Ok(list.split(',').map(str::to_owned).collect()),
    }
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let bad = || format!("--beacon must be hex, got `{text}`");
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err(bad());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| bad()))
        .collect()
}

fn contribution(flags: &Flags) -> Result<Contribution, String> {
    let name = flags.optional("name").map(str::to_owned);
    let Some(value) = flags.optional("beacon") else {
        return Ok(Contribution::Random { name });
    };
    let exponent = flags.required("beacon-exponent")?;
    let exponent = exponent
        .parse()
        .map_err(|_| format!("--beacon-exponent must be a number, got {exponent}"))?;
    let beacon = Beacon::new(hex_bytes(value)?, exponent).map_err(sdk)?;
    Ok(Contribution::Beacon { name, beacon })
}

fn phase1(flags: &Flags) -> Result<(), String> {
    let ceremony = ceremony(flags)?;
    println!(
        "VALID: published Hermez Powers of Tau, power {}",
        ceremony.phase1().power()
    );
    Ok(())
}

fn create(flags: &Flags) -> Result<(), String> {
    let pack = ceremony(flags)?
        .create(
            &circuits(flags)?,
            &contribution(flags)?,
            &mut progress("created"),
        )
        .map_err(sdk)?;
    eprintln!();
    write(flags, "out", &pack.to_bytes())?;
    println!("setup {}", pack.setup_id().map_err(sdk)?);
    Ok(())
}

fn contribute(flags: &Flags) -> Result<(), String> {
    let pack = read_pack(flags, "keys")?;
    let pack = ceremony(flags)?
        .contribute(&pack, &contribution(flags)?, &mut progress("contributed"))
        .map_err(sdk)?;
    eprintln!();
    write(flags, "out", &pack.to_bytes())?;
    println!("setup {}", pack.setup_id().map_err(sdk)?);
    Ok(())
}

fn print_key(key: &KeyReport) {
    println!("{} key {}", key.circuit, key.key_id);
    println!("  circuit hash {}", key.circuit_hash);
    for (i, c) in key.contributions.iter().enumerate() {
        let name = c.name.as_deref().unwrap_or("(unnamed)");
        match &c.beacon {
            None => println!("  #{} {name} {}", i + 1, c.hash),
            Some(b) => {
                let value: String = b.value.iter().map(|x| format!("{x:02x}")).collect();
                println!(
                    "  #{} {name} beacon {value} 2^{} {}",
                    i + 1,
                    b.exponent,
                    c.hash
                );
            }
        }
    }
}

fn verify(flags: &Flags) -> Result<(), String> {
    let pack = read_pack(flags, "keys")?;
    let report: SetupReport = ceremony(flags)?
        .verify(&pack, &mut progress("verified"))
        .map_err(sdk)?;
    eprintln!();
    report.keys.iter().for_each(print_key);
    println!("VALID: setup {}", report.setup_id);
    if flags.optional("trust-out").is_some() {
        write(
            flags,
            "trust-out",
            format!("{}\n", report.setup_id).as_bytes(),
        )?;
    }
    Ok(())
}

fn initial(flags: &Flags) -> Result<(), String> {
    let key = ceremony(flags)?
        .initial_key(flags.required("circuit")?)
        .map_err(sdk)?;
    write(flags, "out", &key)
}

fn export(flags: &Flags) -> Result<(), String> {
    let dir = Path::new(flags.required("dir")?);
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    for (name, zkey) in read_pack(flags, "keys")?.iter() {
        let file = dir.join(format!("{name}.zkey"));
        zk_sdk::files::write_atomic(&file, zkey).map_err(sdk)?;
    }
    Ok(())
}

fn import(flags: &Flags) -> Result<(), String> {
    let dir = Path::new(flags.required("dir")?);
    let mut pack = KeyPack::default();
    for name in circuits(flags)? {
        let file = dir.join(format!("{name}.zkey"));
        let zkey = fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        pack.insert(&name, zkey).map_err(sdk)?;
    }
    write(flags, "out", &pack.to_bytes())
}

/// The trust list of `--groth16-trust` (empty without it: proofs then do not verify).
pub fn trust(flags: &Flags) -> Result<Trust, String> {
    match flags.optional("groth16-trust") {
        None => Ok(Trust::default()),
        Some(file) => {
            let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
            Trust::parse(&text).map_err(sdk)
        }
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    let flags = |own: &[&str], extra: &[&str]| Flags::parse(rest, &[own, extra].concat());
    let made = [CONTRIBUTION.as_slice(), &SOURCE].concat();
    match command.as_str() {
        "phase1" => phase1(&flags(&[], &SOURCE)?),
        "new" => create(&flags(&["circuits", "out"], &made)?),
        "contribute" => contribute(&flags(&["keys", "out"], &made)?),
        "verify" => verify(&flags(&["keys", "trust-out"], &SOURCE)?),
        "initial" => initial(&flags(&["circuit", "out"], &SOURCE)?),
        "export" => export(&flags(&["keys", "dir"], &[])?),
        "import" => import(&flags(&["dir", "circuits", "out"], &[])?),
        _ => Err(USAGE.into()),
    }
}
