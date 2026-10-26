//! Emits the generated circom hash libraries from the pinned parameter crates, so no constant is
//! ever retyped by hand.
//!
//! usage: circuitgen koalabear|bn254 <output.circom>

mod bn254;
mod emit;
mod koalabear;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let render = match args.first().map(String::as_str) {
        Some("koalabear") => koalabear::render,
        Some("bn254") => bn254::render,
        _ => usage(),
    };
    let Some(path) = args.get(1) else { usage() };
    // light-poseidon builds its parameter tables on the stack, which overflows the 1 MiB Windows
    // main thread in debug builds.
    let source = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(render)
        .expect("spawn renderer")
        .join()
        .expect("renderer panicked");
    if let Err(error) = std::fs::write(path, source) {
        eprintln!("error: {path}: {error}");
        std::process::exit(1);
    }
}

fn usage() -> ! {
    eprintln!("usage: circuitgen koalabear|bn254 <output.circom>");
    std::process::exit(2);
}
