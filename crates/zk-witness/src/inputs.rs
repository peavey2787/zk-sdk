//! Circom-style input JSON: `{"name": "decimal" | number | [..nested..]}`.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{Result, WitnessError};

/// Flattened inputs: `x` for scalars, `x[0]`, `x[1]`, ... for arrays (nested arrays append
/// further indices).
pub type Inputs = BTreeMap<String, u64>;

fn scalar(name: &str, value: &Value) -> Result<u64> {
    let parsed = match value {
        Value::String(text) => text.parse::<u64>().ok(),
        Value::Number(number) => number.as_u64(),
        _ => None,
    };
    parsed.ok_or_else(|| WitnessError::Format(format!("input `{name}` is not an unsigned integer")))
}

fn flatten(name: String, value: &Value, out: &mut Inputs) -> Result<()> {
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .try_for_each(|(i, item)| flatten(format!("{name}[{i}]"), item, out)),
        other => {
            let parsed = scalar(&name, other)?;
            out.insert(name, parsed);
            Ok(())
        }
    }
}

pub fn parse_json(text: &str) -> Result<Inputs> {
    let root: Value =
        serde_json::from_str(text).map_err(|e| WitnessError::Format(e.to_string()))?;
    let Value::Object(map) = root else {
        return Err(WitnessError::Format("inputs must be a JSON object".into()));
    };
    let mut out = Inputs::new();
    for (name, value) in &map {
        flatten(name.clone(), value, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_scalars_and_arrays() {
        let inputs = parse_json(r#"{"a":"20","b":7,"c":[1,[2,3]]}"#).unwrap();
        let names: Vec<_> = inputs.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(
            names,
            vec![
                ("a", 20),
                ("b", 7),
                ("c[0]", 1),
                ("c[1][0]", 2),
                ("c[1][1]", 3)
            ]
        );
    }

    #[test]
    fn rejects_non_integers() {
        assert!(parse_json(r#"{"a":"-1"}"#).is_err());
        assert!(parse_json(r#"{"a":1.5}"#).is_err());
        assert!(parse_json(r#"[1]"#).is_err());
    }
}
