//! Minimal `--flag value` parsing. Unknown or repeated flags are errors.

use std::collections::BTreeMap;

pub struct Flags(BTreeMap<String, String>);

impl Flags {
    pub fn parse(args: &[String], allowed: &[&str]) -> Result<Self, String> {
        let mut map = BTreeMap::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let name = flag.strip_prefix("--").filter(|n| allowed.contains(n));
            let name = name.ok_or_else(|| format!("unexpected argument `{flag}`"))?;
            let value = iter
                .next()
                .ok_or_else(|| format!("`{flag}` needs a value"))?;
            if map.insert(name.to_owned(), value.clone()).is_some() {
                return Err(format!("`{flag}` given twice"));
            }
        }
        Ok(Self(map))
    }

    pub fn required(&self, name: &str) -> Result<&str, String> {
        self.optional(name)
            .ok_or_else(|| format!("missing required `--{name}`"))
    }

    pub fn optional(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_and_rejects() {
        let flags = Flags::parse(&args(&["--a", "1"]), &["a", "b"]).unwrap();
        assert_eq!(flags.required("a"), Ok("1"));
        assert!(flags.required("b").is_err());
        assert!(Flags::parse(&args(&["--c", "1"]), &["a"]).is_err());
        assert!(Flags::parse(&args(&["--a"]), &["a"]).is_err());
        assert!(Flags::parse(&args(&["--a", "1", "--a", "2"]), &["a"]).is_err());
        assert!(Flags::parse(&args(&["a"]), &["a"]).is_err());
    }
}
