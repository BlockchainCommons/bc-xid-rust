mod common;

use bc_components::{PrivateKeyBase, PublicKeysProvider};
use bc_envelope::prelude::*;
use bc_rand::make_fake_random_number_generator;
use bc_xid::{
    Key, XIDDocument, XIDGeneratorOptions, XIDGenesisMarkOptions,
    XIDInceptionKeyOptions, XIDPrivateKeyOptions, XIDSigningOptions,
};
use indoc::indoc;
use provenance_mark::ProvenanceMarkResolution;

fn xid_document_with_custom_assertion() -> XIDDocument {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Omit,
            XIDGeneratorOptions::Omit,
            XIDSigningOptions::None,
        )
        .unwrap()
        .add_assertion("customField", "customValue");

    XIDDocument::try_from(envelope).unwrap()
}

#[test]
fn xid_document_parses_and_preserves_custom_assertions() {
    let xid_document = xid_document_with_custom_assertion();
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Omit,
            XIDGeneratorOptions::Omit,
            XIDSigningOptions::None,
        )
        .unwrap();

    // expected-text-output-rubric:
    #[rustfmt::skip]
    assert_actual_expected!(envelope.format(), indoc! {r#"
        XID(71274df1) [
            "customField": "customValue"
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}.trim());
}

#[test]
fn xid_document_key_mutation_preserves_custom_assertions() {
    let mut xid_document = xid_document_with_custom_assertion();

    let mut rng = make_fake_random_number_generator();
    let _inception_base = PrivateKeyBase::new_using(&mut rng);
    let second_base = PrivateKeyBase::new_using(&mut rng);
    xid_document
        .add_key(Key::new_allow_all(second_base.public_keys()))
        .unwrap();

    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Omit,
            XIDGeneratorOptions::Omit,
            XIDSigningOptions::None,
        )
        .unwrap();

    assert!(
        envelope
            .format()
            .contains(r#""customField": "customValue""#)
    );
    assert_eq!(xid_document.keys().len(), 2);
}

#[test]
fn xid_document_provenance_mutation_preserves_custom_assertions() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::Passphrase(
            "test passphrase".to_string(),
            Some(ProvenanceMarkResolution::High),
            Some(Date::from_string("2024-01-01").unwrap()),
            Some(CBOR::from("Genesis")),
        ),
    );
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Omit,
            XIDGeneratorOptions::Include,
            XIDSigningOptions::None,
        )
        .unwrap()
        .add_assertion("customField", "customValue");

    let mut xid_document = XIDDocument::try_from(envelope).unwrap();
    xid_document
        .next_provenance_mark_with_embedded_generator(
            None,
            Some(Date::from_string("2024-01-02").unwrap()),
            Some(CBOR::from("Next")),
        )
        .unwrap();

    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Omit,
            XIDGeneratorOptions::Include,
            XIDSigningOptions::None,
        )
        .unwrap();

    assert!(
        envelope
            .format()
            .contains(r#""customField": "customValue""#)
    );
    assert_eq!(xid_document.provenance().unwrap().seq(), 1);
}
