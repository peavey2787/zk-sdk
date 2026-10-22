#!/usr/bin/env python3
"""Small offline structure/privacy checks; not a Rust compiler or security audit."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
required = [
    "Cargo.toml", "README.md", "run-all-linux.sh", "run-all-windows.cmd",
    "docs/ROADMAP.md", "docs/PROGRESS.md", "docs/SECURITY.md",
    "crates/zk-core/src/lib.rs", "crates/zk-spartan-whir/src/lib.rs",
    "crates/zk-sdk/src/lib.rs", "crates/zk-wasm/src/lib.rs", "web/index.html",
]
for name in required:
    assert (root / name).is_file(), f"missing {name}"

sdk = (root / "crates/zk-sdk/src/lib.rs").read_text()
for name in ["compile", "setup", "prove", "verify", "verify_batch", "inspect"]:
    assert re.search(rf"pub fn {name}\s*\(", sdk), f"missing facade API {name}"

SKIPPED = {".git", "target", "pkg", "circuits", "__pycache__"}
PRIVATE = {".zkk", ".zkp", ".pem", ".key"}
for file in root.rglob("*"):
    if file.is_file() and not SKIPPED & set(file.relative_to(root).parts[:-1]):
        assert file.suffix not in PRIVATE, f"private artifact in repo: {file}"

assert not list((root / "web" / "pkg").glob("*")) or (root / ".gitignore").read_text().count("/web/pkg/")
# Security downgrade guard: WHIR grinding/query parameters may only come from upstream's
# recommendation; no source may assign or clamp them (tests that read them are fine).
FORBIDDEN = re.compile(r"\.(pow_bits|folding_factor|starting_log_inv_rate)\s*(=[^=]|\.(min|max|saturating_sub))|MAX_POW_BITS")
for file in (root / "crates").rglob("*.rs"):
    text = file.read_text().split("#[cfg(test)]")[0]
    assert not FORBIDDEN.search(text), f"WHIR parameter modification in {file}; see docs/SECURITY.md"

print("PASS: project layout, six facade method names, no private artifacts")
