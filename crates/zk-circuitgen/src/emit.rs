//! Circom source helpers: constant tables are emitted as functions returning array literals.

use std::fmt::Write;

pub fn function(out: &mut String, name: &str, shape: &str, body: &str) {
    writeln!(
        out,
        "function {name}() {{\n    var v{shape} = {body};\n    return v;\n}}\n"
    )
    .unwrap();
}

pub fn row(values: &[String]) -> String {
    format!("[{}]", values.join(", "))
}

pub fn grid(rows: &[Vec<String>]) -> String {
    let lines: Vec<String> = rows.iter().map(|r| row(r)).collect();
    format!("[\n        {}\n    ]", lines.join(",\n        "))
}
