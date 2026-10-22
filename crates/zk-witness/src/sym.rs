//! Parser for circom `.sym` files: `label,wire,component,name` per line.

use std::collections::BTreeMap;

use crate::{Result, WitnessError};

/// Signal name (for example `main.age` or `main.x[1]`) to wire index. Optimised-away signals
/// (wire -1) are omitted.
pub type SignalMap = BTreeMap<String, u32>;

pub fn parse(text: &str) -> Result<SignalMap> {
    let mut signals = SignalMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut fields = line.splitn(4, ',');
        let (_label, wire, _component, name) =
            (fields.next(), fields.next(), fields.next(), fields.next());
        let (Some(wire), Some(name)) = (wire, name) else {
            return Err(WitnessError::Format(format!("bad sym line `{line}`")));
        };
        let wire: i64 = wire
            .trim()
            .parse()
            .map_err(|_| WitnessError::Format(format!("bad wire in sym line `{line}`")))?;
        if let Ok(wire) = u32::try_from(wire) {
            signals.insert(name.trim().to_owned(), wire);
        }
    }
    Ok(signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_skips_optimised_signals() {
        let map = parse("1,1,0,main.out\n2,-1,0,main.dead\n3,2,0,main.x[0]\n").unwrap();
        assert_eq!(map.get("main.out"), Some(&1));
        assert_eq!(map.get("main.x[0]"), Some(&2));
        assert!(!map.contains_key("main.dead"));
        assert!(parse("garbage").is_err());
        assert!(parse("1,notanumber,0,main.a").is_err());
    }
}
