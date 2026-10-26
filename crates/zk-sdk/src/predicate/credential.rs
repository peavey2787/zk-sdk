//! Issuer-backed credentials: an attribute with a serial and an expiry that an issuer published
//! under a Merkle root, presentable without revealing which credential it is.
//!
//! The issuer builds a [`CredentialIssuer`] from its entries, publishes the [`IssuerCommitment`]
//! and hands each holder a [`Credential`] (a bearer secret: whoever holds it can present it). A
//! holder calls [`Credential::present`] with the verifier's current time to get a [`Presentation`]:
//! fresh commitments to the attribute, serial and expiry (so two presentations share nothing) and
//! the claim `Predicate::Credential` that they are those of a credential under the issuer's root
//! and not expired. Revocation is a separate, composable claim: the serial is not in the issuer's
//! revocation set, tied to the credential by the shared serial commitment
//! ([`Presentation::all`]).
//!
//! This is deliberately a different claim, circuit and hash domain from `opens` (knowledge of a
//! committed secret) and from set membership: possessing a secret proves nothing about an issuer.
//!
//! An issuer is built for one [`Scheme`]; its credentials are presented with that scheme's
//! commitments.
//!
//! Trust: the issuer's root is only as honest as the issuer; whoever controls the tree can mint a
//! credential for anyone. That is what an issuer is.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::claim::Predicate;
use super::commit::{Commitment, Opening};
use super::compose::{Conjunction, ConjunctionWitness};
use super::engine::Witness;
use super::hash::{Node, CREDENTIAL_DOMAIN};
use super::int::{IntType, Number};
use super::scheme::Scheme;
use super::set::{
    fit_depth, levels, siblings_of, top, zero_hashes, PathText, SetPath, SetTree, SET_DEPTHS,
};
use super::statement::{digest, elements, limbs, same_scheme, signed, PathShape, Slot, Statement};
use crate::{Result, ZkError};

const SERIAL_TYPE: IntType = IntType::U64;

fn error(message: impl Into<String>) -> ZkError {
    ZkError::Predicate(message.into())
}

fn leaf(scheme: Scheme, ty: IntType, attribute: u128, serial: u64, expiry: u64) -> Node {
    let attribute = ty.limbs(attribute);
    let mut message = vec![u32::from(ty.signed), attribute.len() as u32];
    message.extend(attribute.iter().map(|l| *l as u32));
    for field in [serial, expiry] {
        message.extend(
            SERIAL_TYPE
                .limbs(u128::from(field))
                .iter()
                .map(|l| *l as u32),
        );
    }
    Node::leaf(scheme, CREDENTIAL_DOMAIN, &message)
}

fn time(number: Number, what: &str) -> Result<u64> {
    let encoded = SERIAL_TYPE
        .encode(number)
        .map_err(|_| error(format!("{what} must be a u64")))?;
    Ok(encoded as u64)
}

/// The public handle of an issuer's credentials: attribute type, tree depth and Merkle root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IssuerCommitment {
    ty: IntType,
    depth: usize,
    root: Node,
}

impl IssuerCommitment {
    pub fn ty(&self) -> IntType {
        self.ty
    }

    pub fn scheme(&self) -> Scheme {
        self.root.scheme()
    }

    /// Canonical text form `[groth16:]issuer:<type>:<depth>:<64 hex digits>`.
    pub fn to_text(&self) -> String {
        let prefix = self.scheme().text_prefix();
        format!(
            "{prefix}issuer:{}:{}:{}",
            self.ty,
            self.depth,
            self.root.to_hex()
        )
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let invalid = || ZkError::Format(format!("`{text}` is not an issuer commitment"));
        let (scheme, rest) = Scheme::split_text(text);
        let mut parts = rest.splitn(4, ':');
        let (Some("issuer"), Some(ty), Some(depth), Some(hex)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        let depth: usize = depth.parse().map_err(|_| invalid())?;
        if !SET_DEPTHS.contains(&depth) {
            return Err(invalid());
        }
        Ok(Self {
            ty: ty.parse().map_err(|_| invalid())?,
            depth,
            root: Node::from_hex(scheme, hex).ok_or_else(invalid)?,
        })
    }
}

impl fmt::Display for IssuerCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl Serialize for IssuerCommitment {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_text())
    }
}

impl<'de> Deserialize<'de> for IssuerCommitment {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_text(&text).map_err(serde::de::Error::custom)
    }
}

/// What an issuer records for one credential: the attribute value, a serial that is unique among
/// the issuer's credentials (it is what revocation names) and an expiry in Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialEntry {
    pub attribute: Number,
    pub serial: u64,
    pub expiry: u64,
}

/// An issuer's credentials with the Merkle tree materialised.
pub struct CredentialIssuer {
    commitment: IssuerCommitment,
    entries: Vec<CredentialEntry>,
    levels: Vec<Vec<Node>>,
}

impl CredentialIssuer {
    /// Build the Spartan-WHIR tree for `entries` of attribute type `ty`. Fails when an attribute
    /// does not fit `ty`, two entries share a serial, or there are too many entries for the
    /// largest depth.
    pub fn new(ty: IntType, entries: impl IntoIterator<Item = CredentialEntry>) -> Result<Self> {
        Self::new_in(Scheme::SpartanWhir, ty, entries)
    }

    /// Build the tree in `scheme`, whose commitments the credentials are then presented with.
    pub fn new_in(
        scheme: Scheme,
        ty: IntType,
        entries: impl IntoIterator<Item = CredentialEntry>,
    ) -> Result<Self> {
        let entries: Vec<CredentialEntry> = entries.into_iter().collect();
        let mut serials: Vec<u64> = entries.iter().map(|e| e.serial).collect();
        serials.sort_unstable();
        if serials.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error("two credentials share a serial"));
        }
        let depth = fit_depth(entries.len())?;
        let leaves = entries
            .iter()
            .map(|e| {
                Ok(leaf(
                    scheme,
                    ty,
                    ty.encode(e.attribute)?,
                    e.serial,
                    e.expiry,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let zeros = zero_hashes(scheme, depth);
        let levels = levels(leaves, &zeros);
        Ok(Self {
            commitment: IssuerCommitment {
                ty,
                depth,
                root: top(&levels, &zeros),
            },
            entries,
            levels,
        })
    }

    pub fn commitment(&self) -> IssuerCommitment {
        self.commitment
    }

    /// The credential with this serial, for its holder.
    pub fn credential(&self, serial: u64) -> Result<Credential> {
        let index = self
            .entries
            .iter()
            .position(|e| e.serial == serial)
            .ok_or_else(|| error("no credential has this serial"))?;
        let entry = self.entries[index];
        Ok(Credential {
            issuer: self.commitment,
            attribute: entry.attribute,
            serial,
            expiry: entry.expiry,
            path: SetPath::member(
                self.commitment.scheme(),
                index as u64,
                siblings_of(
                    self.commitment.scheme(),
                    &self.levels,
                    self.commitment.depth,
                    index,
                ),
            ),
        })
    }

    /// Every credential, in the order the entries were given.
    pub fn credentials(&self) -> Result<Vec<Credential>> {
        self.entries
            .iter()
            .map(|e| self.credential(e.serial))
            .collect()
    }
}

/// A holder's credential. A bearer secret: its text form must be stored and sent like a
/// password, and the contents are overwritten when it is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    issuer: IssuerCommitment,
    attribute: Number,
    serial: u64,
    expiry: u64,
    pub(super) path: SetPath,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.attribute.zeroize();
        self.serial.zeroize();
        self.expiry.zeroize();
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential({}, <redacted>)", self.issuer)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialText {
    issuer: IssuerCommitment,
    attribute: Number,
    serial: Number,
    expiry: Number,
    path: PathText,
}

impl Credential {
    pub fn issuer(&self) -> IssuerCommitment {
        self.issuer
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn expiry(&self) -> u64 {
        self.expiry
    }

    /// Text form for storage. Treat it as secret.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&CredentialText {
            issuer: self.issuer,
            attribute: self.attribute,
            serial: Number::from(self.serial),
            expiry: Number::from(self.expiry),
            path: PathText::from(&self.path),
        })
        .expect("credentials always serialize")
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let text: CredentialText =
            serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))?;
        Ok(Self {
            issuer: text.issuer,
            attribute: text.attribute,
            serial: time(text.serial, "the serial")?,
            expiry: time(text.expiry, "the expiry")?,
            path: text.path.into_path()?,
        })
    }

    /// Present the credential to a verifier whose clock reads `now`: fresh commitments to the
    /// attribute, serial and expiry, and the claim over them. Nothing links two presentations.
    pub fn present(&self, now: u64) -> Result<Presentation> {
        let scheme = self.issuer.scheme();
        let (attribute, a) = Commitment::commit_in(scheme, self.issuer.ty, self.attribute)?;
        let (serial, s) = Commitment::commit_in(scheme, SERIAL_TYPE, self.serial)?;
        let (expiry, e) = Commitment::commit_in(scheme, SERIAL_TYPE, self.expiry)?;
        Ok(Presentation {
            claim: Predicate::credential(attribute, serial, expiry, self.issuer, now),
            attribute,
            serial,
            expiry,
            openings: vec![a, s, e],
            path: self.path.clone(),
        })
    }
}

/// One presentation: the public claim and the private witness for it.
pub struct Presentation {
    claim: Predicate,
    attribute: Commitment,
    serial: Commitment,
    expiry: Commitment,
    openings: Vec<Opening>,
    path: SetPath,
}

impl Presentation {
    pub fn claim(&self) -> &Predicate {
        &self.claim
    }

    /// The commitment to the attribute, for further claims about it (`at_least`, `in_any_range`).
    pub fn attribute(&self) -> Commitment {
        self.attribute
    }

    pub fn serial(&self) -> Commitment {
        self.serial
    }

    pub fn expiry(&self) -> Commitment {
        self.expiry
    }

    /// The secrets for [`Presentation::claim`] in the order the JSON entry points take them: the
    /// three openings, then the credential's path.
    pub(super) fn secrets(&self) -> Vec<String> {
        let openings = self.openings.iter().map(Opening::to_secret_json);
        openings.chain([self.path.to_json()]).collect()
    }

    /// The witness for [`Presentation::claim`] on its own.
    pub fn witness(self) -> Witness {
        Witness::from(self.openings).with_path(self.path)
    }

    /// The credential together with `also` (claims over [`Presentation::attribute`] or other
    /// commitments the caller also opens) and, when `revoked` is given, that the serial is not in
    /// that revocation set (a `SetTree` of `u64` serials). Fails when the serial is revoked.
    pub fn all(
        self,
        also: Vec<Predicate>,
        revoked: Option<&SetTree>,
    ) -> Result<(Conjunction, ConjunctionWitness)> {
        let serial_value = self.openings[1].value();
        let mut claims = vec![self.claim];
        claims.extend(also);
        let mut paths = vec![self.path];
        if let Some(set) = revoked {
            claims.push(Predicate::not_member_of(self.serial, set.commitment()));
            paths.push(set.absence_path(serial_value)?);
        }
        Ok((
            Conjunction::new(claims)?,
            ConjunctionWitness {
                openings: self.openings,
                paths,
            },
        ))
    }
}

/// Why the three held values and `path` do not show a valid credential under `issuer` at `now`;
/// `Ok(None)` when they do.
pub(super) fn refusal(
    issuer: &IssuerCommitment,
    now: Number,
    held: [Number; 3],
    path: Option<&SetPath>,
) -> Result<Option<String>> {
    let path = path.ok_or_else(|| error("a credential claim needs the credential's path"))?;
    path.check_shape(issuer.scheme(), issuer.depth)?;
    let [attribute, serial, expiry] = held;
    let (serial, expiry) = (time(serial, "the serial")?, time(expiry, "the expiry")?);
    if expiry < time(now, "now")? {
        return Ok(Some(format!(
            "the credential expired at {expiry}, before {}",
            time(now, "now")?
        )));
    }
    let encoded = issuer.ty.encode(attribute)?;
    let leaf = leaf(issuer.scheme(), issuer.ty, encoded, serial, expiry);
    Ok((path.root(leaf) != issuer.root).then(|| {
        "these values are not a credential of this issuer (the path does not reach its root)"
            .to_owned()
    }))
}

pub(super) fn statement(
    attribute: &Commitment,
    serial: &Commitment,
    expiry: &Commitment,
    issuer: &IssuerCommitment,
    now: Number,
) -> Result<Statement> {
    let ty = attribute.ty();
    if issuer.ty != ty {
        return Err(error(format!(
            "a {ty} attribute cannot be checked against an issuer of {}",
            issuer.ty
        )));
    }
    same_scheme(attribute, issuer.scheme(), "issuer")?;
    for (name, commitment) in [("serial", serial), ("expiry", expiry)] {
        if commitment.ty() != SERIAL_TYPE {
            return Err(error(format!(
                "the {name} must be committed as {SERIAL_TYPE}, not {}",
                commitment.ty()
            )));
        }
    }
    let fields = vec![
        digest("a_commitment", attribute),
        digest("s_commitment", serial),
        digest("e_commitment", expiry),
        signed(ty),
        elements("root", issuer.root.signals()),
        limbs("now", SERIAL_TYPE, now)?,
    ];
    let slots = ["a_", "s_", "e_"]
        .iter()
        .enumerate()
        .map(|(i, prefix)| Slot::prefixed(prefix, Some(i)))
        .collect();
    Ok(Statement::new(
        format!("cred{}_{}", issuer.depth, ty.width.bits()),
        ty,
        slots,
        vec![*attribute, *serial, *expiry],
        fields,
    )
    .with_path(PathShape {
        absent: false,
        depth: issuer.depth,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(attribute: i32, serial: u64, expiry: u64) -> CredentialEntry {
        CredentialEntry {
            attribute: Number::from(attribute),
            serial,
            expiry,
        }
    }

    fn issuer() -> CredentialIssuer {
        CredentialIssuer::new(
            IntType::I32,
            [entry(25, 1, 2_000), entry(-3, 2, 100), entry(40, 3, 3_000)],
        )
        .unwrap()
    }

    fn judged(credential: &Credential, now: u64) -> Option<String> {
        let held = [
            credential.attribute,
            Number::from(credential.serial),
            Number::from(credential.expiry),
        ];
        refusal(
            &credential.issuer,
            Number::from(now),
            held,
            Some(&credential.path),
        )
        .unwrap()
    }

    #[test]
    fn issued_credentials_are_valid_until_they_expire() {
        let issuer = issuer();
        for credential in issuer.credentials().unwrap() {
            assert_eq!(judged(&credential, 50), None);
            assert_eq!(judged(&credential, credential.expiry), None, "inclusive");
            assert!(judged(&credential, credential.expiry + 1)
                .unwrap()
                .contains("expired"));
        }
    }

    #[test]
    fn values_that_were_never_issued_are_refused() {
        let issuer = issuer();
        let genuine = issuer.credential(1).unwrap();
        let held = |attribute: i32, serial: u64, expiry: u64| {
            [
                Number::from(attribute),
                Number::from(serial),
                Number::from(expiry),
            ]
        };
        for forged in [held(26, 1, 2_000), held(25, 9, 2_000), held(25, 1, 9_999)] {
            let reason = refusal(
                &issuer.commitment(),
                Number::from(0u8),
                forged,
                Some(&genuine.path),
            );
            assert!(reason.unwrap().unwrap().contains("not a credential"));
        }
        let other = CredentialIssuer::new(IntType::I32, [entry(25, 1, 2_000)]).unwrap();
        let held = [Number::from(25), Number::from(1u8), Number::from(2_000u32)];
        let cross = refusal(
            &other.commitment(),
            Number::from(0u8),
            held,
            Some(&genuine.path),
        );
        assert!(
            cross.unwrap().is_some(),
            "another issuer's root rejects the path"
        );
    }

    #[test]
    fn groth16_issuers_present_with_groth16_commitments() {
        let entries = [entry(25, 1, 2_000)];
        let issuer = CredentialIssuer::new_in(Scheme::Groth16, IntType::I32, entries).unwrap();
        let commitment = issuer.commitment();
        assert!(commitment.to_text().starts_with("groth16:issuer:i32:8:"));
        assert_eq!(
            IssuerCommitment::from_text(&commitment.to_text()).unwrap(),
            commitment
        );
        let credential = issuer.credential(1).unwrap();
        assert_eq!(judged(&credential, 50), None);
        let presentation = credential.present(50).unwrap();
        assert_eq!(presentation.attribute().scheme(), Scheme::Groth16);
        let statement = presentation.claim().statement().unwrap();
        assert_eq!(
            (statement.circuit(), statement.scheme()),
            ("cred8_32", Scheme::Groth16)
        );
        let spartan = CredentialIssuer::new(IntType::I32, entries).unwrap();
        let held = [Number::from(25), Number::from(1u8), Number::from(2_000u32)];
        let cross = refusal(
            &spartan.commitment(),
            Number::from(0u8),
            held,
            Some(&credential.path),
        );
        assert!(
            cross.is_err(),
            "a groth16 path never checks against a spartan root"
        );
    }

    #[test]
    fn serials_are_unique_and_the_tree_is_bounded() {
        assert!(CredentialIssuer::new(IntType::U32, [entry(1, 7, 1), entry(2, 7, 1)]).is_err());
        assert!(CredentialIssuer::new(IntType::U32, [entry(-1, 7, 1)]).is_err());
        assert!(issuer().credential(99).is_err());
    }

    #[test]
    fn text_forms_round_trip_and_reject_garbage() {
        let issuer = issuer();
        let commitment = issuer.commitment();
        assert_eq!(
            IssuerCommitment::from_text(&commitment.to_text()).unwrap(),
            commitment
        );
        for bad in ["", "issuer:i32:8:00", "issuer:i32:9:aa", "set:i32:8:aa"] {
            assert!(IssuerCommitment::from_text(bad).is_err(), "{bad}");
        }
        let credential = issuer.credential(2).unwrap();
        assert_eq!(
            Credential::from_json(&credential.to_json()).unwrap(),
            credential
        );
        assert!(Credential::from_json("{}").is_err());
        assert!(format!("{credential:?}").contains("redacted"));
    }

    #[test]
    fn the_statement_checks_types_and_names_the_circuit() {
        let issuer = issuer();
        let presentation = issuer.credential(1).unwrap().present(10).unwrap();
        let statement = presentation.claim().statement().unwrap();
        assert_eq!(statement.circuit(), "cred8_32");
        assert_eq!(statement.committed().len(), 3);
        let attribute = presentation.attribute();
        let wrong_serial = Commitment::commit_with_blinding(IntType::U32, 1u8, [1; 8])
            .unwrap()
            .0;
        let claim = Predicate::credential(
            attribute,
            wrong_serial,
            wrong_serial,
            issuer.commitment(),
            10u8,
        );
        assert!(claim.statement().is_err());
        let narrow = Commitment::commit_with_blinding(IntType::I64, 1u8, [1; 8])
            .unwrap()
            .0;
        let serial = Commitment::commit_with_blinding(IntType::U64, 1u8, [1; 8])
            .unwrap()
            .0;
        let mismatched = Predicate::credential(narrow, serial, serial, issuer.commitment(), 10u8);
        assert!(mismatched.statement().is_err());
        assert!(
            Predicate::credential(attribute, serial, serial, issuer.commitment(), -1)
                .statement()
                .is_err()
        );
    }
}
