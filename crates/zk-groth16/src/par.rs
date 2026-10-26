//! Data parallelism where threads exist: every core natively, and in wasm32 only when built with the
//! `parallel` feature.

#[cfg(any(feature = "parallel", not(target_arch = "wasm32")))]
pub(crate) fn map<T: Send>(count: usize, f: impl Fn(usize) -> T + Sync + Send) -> Vec<T> {
    use rayon::prelude::*;
    (0..count).into_par_iter().map(f).collect()
}

#[cfg(not(any(feature = "parallel", not(target_arch = "wasm32"))))]
pub(crate) fn map<T: Send>(count: usize, f: impl Fn(usize) -> T + Sync + Send) -> Vec<T> {
    (0..count).map(f).collect()
}
