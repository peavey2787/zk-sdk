//! Spartan-WHIR full-ZK backend linked as a library. No subprocess, no mock proofs, no local
//! reimplementation of proving or verification; the same code runs natively and on wasm32.
mod codec;
mod params;
mod spartan;

pub use spartan::SpartanWhir;
