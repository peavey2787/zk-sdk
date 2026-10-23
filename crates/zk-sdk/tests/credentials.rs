//! Real full-ZK proofs for issuer-backed credentials: an attribute, serial and expiry under an
//! issuer's published root, presented without saying which credential it is, optionally together
//! with further claims about the attribute and proof that the serial is not revoked. Nothing is
//! mocked; each success is a Spartan-WHIR proof verified by an independent `Predicates` instance
//! against statements derived from the claims alone.

use std::sync::OnceLock;

use zk_sdk::predicate::{
    self, CredentialEntry, CredentialIssuer, IntType, Number, Predicate, Predicates, SetTree,
};

/// The Merkle-path circuits exceed the size upstream supports at 116 bits; this opt-in is the only
/// way to run them.
fn authorized() -> Predicates {
    Predicates::new().with_minimum_bits(115)
}

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(authorized)
}

const NOW: u64 = 1_000;

fn issuer() -> CredentialIssuer {
    let entry = |attribute: i32, serial: u64, expiry: u64| CredentialEntry {
        attribute: Number::from(attribute),
        serial,
        expiry,
    };
    CredentialIssuer::new(
        IntType::I32,
        [
            entry(25, 11, 5_000),
            entry(17, 12, 5_000),
            entry(40, 13, 900),
        ],
    )
    .unwrap()
}

#[test]
fn a_credential_is_presented_and_bound_to_issuer_and_time() {
    let issuer = issuer();
    let presentation = issuer.credential(11).unwrap().present(NOW).unwrap();
    let claim = presentation.claim().clone();
    let proof = zk().prove(&claim, presentation.witness()).unwrap();
    authorized().verify(&claim, &proof).unwrap();

    // The verifier builds the claim from its own clock and the issuer it trusts.
    let Predicate::Credential {
        attribute,
        serial,
        expiry,
        ..
    } = claim.clone()
    else {
        panic!("not a credential claim");
    };
    let other = CredentialIssuer::new(
        IntType::I32,
        [CredentialEntry {
            attribute: Number::from(25),
            serial: 11,
            expiry: 5_000,
        }],
    )
    .unwrap();
    for stale in [
        Predicate::credential(attribute, serial, expiry, issuer.commitment(), NOW + 1),
        Predicate::credential(attribute, serial, expiry, other.commitment(), NOW),
    ] {
        assert!(authorized().verify(&stale, &proof).is_err(), "{stale:?}");
    }
}

#[test]
fn expired_or_foreign_credentials_cannot_be_presented() {
    let issuer = issuer();
    let expired = issuer.credential(13).unwrap().present(NOW).unwrap();
    let claim = expired.claim().clone();
    let error = zk()
        .prove(&claim, expired.witness())
        .unwrap_err()
        .to_string();
    assert!(error.contains("expired"), "{error}");

    let foreign = CredentialIssuer::new(
        IntType::I32,
        [CredentialEntry {
            attribute: Number::from(25),
            serial: 11,
            expiry: 5_000,
        }],
    )
    .unwrap();
    let presentation = foreign.credential(11).unwrap().present(NOW).unwrap();
    let claim = Predicate::credential(
        presentation.attribute(),
        presentation.serial(),
        presentation.expiry(),
        issuer.commitment(),
        NOW,
    );
    assert!(zk().prove(&claim, presentation.witness()).is_err());
}

#[test]
fn presentations_share_nothing_and_the_circuits_need_the_115_bit_opt_in() {
    let credential = issuer().credential(12).unwrap();
    let (first, second) = (
        credential.present(NOW).unwrap(),
        credential.present(NOW).unwrap(),
    );
    assert_ne!(first.attribute(), second.attribute());
    assert_ne!(first.serial(), second.serial());
    assert!(Predicates::new().security_bits("cred8_32").is_err());
    assert_eq!(authorized().security_bits("cred8_32").unwrap(), 115);
    assert_eq!(authorized().security_bits("cred20_128").unwrap(), 115);
}

#[test]
fn a_revoked_credential_cannot_be_presented_as_unrevoked() {
    let issuer = issuer();
    let revoked = SetTree::new(IntType::U64, [Number::from(12u8)]).unwrap();
    let presentation = issuer.credential(12).unwrap().present(NOW).unwrap();
    let error = presentation
        .all(Vec::new(), Some(&revoked))
        .map(drop)
        .unwrap_err()
        .to_string();
    assert!(error.contains("member"), "{error}");
}

#[test]
fn json_entry_points_present_an_adult_holder_with_an_unrevoked_credential() {
    let issued = predicate::credential_issue(
        "i32",
        r#"[{"attribute":"25","serial":"11","expiry":"5000"},{"attribute":"17","serial":"12","expiry":"5000"}]"#,
    )
    .unwrap();
    let issued: serde_json::Value = serde_json::from_str(&issued).unwrap();
    let adult = issued["credentials"][0].as_str().unwrap();
    let options = r#"{"also":[{"kind":"compare","commitment":"$attribute","op":"ge","bound":"18"}],"revoked":["12","99"]}"#;
    let presented = predicate::credential_present(adult, "1000", options).unwrap();
    let claim = presented.claim();
    let proof = predicate::prove(zk(), &claim, presented.secrets.clone()).unwrap();
    predicate::verify(&authorized(), &claim, &proof).unwrap();

    // The minor's credential is genuine and unrevoked, but the age claim is false for it, so no
    // proof of any part exists; and a revoked serial cannot even be presented as unrevoked.
    let minor = issued["credentials"][1].as_str().unwrap();
    let unlisted = options.replace(r#""12","99""#, r#""99""#);
    let presented = predicate::credential_present(minor, "1000", &unlisted).unwrap();
    let error = predicate::prove(zk(), &presented.claim(), presented.secrets.clone())
        .unwrap_err()
        .to_string();
    assert!(error.contains("claim 1"), "{error}");
    assert!(predicate::credential_present(minor, "1000", options).is_err());
}
