mod common;

use bc_components::{PrivateKeyBase, PublicKeysProvider, XIDProvider};
use bc_envelope::prelude::*;
use bc_rand::make_fake_random_number_generator;
use bc_xid::{Delegate, HasPermissions, Privilege, XIDDocument};
use indoc::indoc;

#[test]
fn test_delegate() {
    let mut rng = make_fake_random_number_generator();

    // Create Alice's XIDDocument
    let alice_private_key_base = PrivateKeyBase::new_using(&mut rng);
    let alice_xid_document = XIDDocument::from(&alice_private_key_base);

    let envelope = alice_xid_document.clone().into_envelope();
    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected);

    // Create Bob's XIDDocument
    let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
    let bob_public_keys = bob_private_key_base.public_keys();
    let bob_xid_document = XIDDocument::from(bob_public_keys);

    let envelope = bob_xid_document.clone().into_envelope();
    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        XID(7c30cafe) [
            'key': PublicKeys(b8164d99, SigningPublicKey(7c30cafe, SchnorrPublicKey(448e2868)), EncapsulationPublicKey(e472f495, X25519PublicKey(e472f495))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected);

    let mut bob_unresolved_delegate =
        Delegate::new(XIDDocument::from_xid(bob_xid_document.xid()));
    bob_unresolved_delegate.add_allow(Privilege::Encrypt);
    bob_unresolved_delegate.add_allow(Privilege::Sign);

    let envelope = bob_unresolved_delegate.clone().into_envelope();
    let bob_unresolved_delegate_2 = Delegate::try_from(&envelope).unwrap();
    assert_eq!(bob_unresolved_delegate, bob_unresolved_delegate_2);

    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        {
            XID(7c30cafe)
        } [
            'allow': 'Encrypt'
            'allow': 'Sign'
        ]
    "#}
    ).trim();
    assert_actual_expected!(envelope.format(), expected);

    let mut alice_xid_document_with_unresolved_delegate =
        alice_xid_document.clone();
    alice_xid_document_with_unresolved_delegate
        .add_delegate(bob_unresolved_delegate)
        .unwrap();
    let envelope = alice_xid_document_with_unresolved_delegate
        .clone()
        .into_envelope();
    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        XID(71274df1) [
            'delegate': {
                XID(7c30cafe)
            } [
                'allow': 'Encrypt'
                'allow': 'Sign'
            ]
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected);

    // Make Bob a Delegate with specific permissions
    let mut bob_delegate = Delegate::new(bob_xid_document);
    bob_delegate.add_allow(Privilege::Encrypt);
    bob_delegate.add_allow(Privilege::Sign);

    let envelope = bob_delegate.clone().into_envelope();
    let bob_delegate_2 = Delegate::try_from(&envelope).unwrap();
    assert_eq!(bob_delegate, bob_delegate_2);

    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        {
            XID(7c30cafe) [
                'key': PublicKeys(b8164d99, SigningPublicKey(7c30cafe, SchnorrPublicKey(448e2868)), EncapsulationPublicKey(e472f495, X25519PublicKey(e472f495))) [
                    'allow': 'All'
                ]
            ]
        } [
            'allow': 'Encrypt'
            'allow': 'Sign'
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected);

    // Add Bob as a Delegate to Alice's XIDDocument
    let mut alice_xid_document_with_delegate = alice_xid_document.clone();
    alice_xid_document_with_delegate
        .add_delegate(bob_delegate)
        .unwrap();
    let envelope = alice_xid_document_with_delegate.clone().into_envelope();
    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        XID(71274df1) [
            'delegate': {
                XID(7c30cafe) [
                    'key': PublicKeys(b8164d99, SigningPublicKey(7c30cafe, SchnorrPublicKey(448e2868)), EncapsulationPublicKey(e472f495, X25519PublicKey(e472f495))) [
                        'allow': 'All'
                    ]
                ]
            } [
                'allow': 'Encrypt'
                'allow': 'Sign'
            ]
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected);
}
