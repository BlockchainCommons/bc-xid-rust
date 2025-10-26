mod common;

use bc_components::{PublicKeysProvider, URI};
use bc_envelope::{EnvelopeEncodable, PrivateKeyBase};
use bc_rand::make_fake_random_number_generator;
use bc_xid::{
    HasPermissions, Privilege, Service, XIDDocument, XIDDocumentKeyOptions,
};

#[test]
fn test_1() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();

    let alice_private_key_base = PrivateKeyBase::new_using(&mut rng);
    let alice_public_keys = alice_private_key_base.public_keys();

    let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
    let bob_public_keys = bob_private_key_base.public_keys();
    let bob_xid_document = XIDDocument::new(Some(
        XIDDocumentKeyOptions::PublicKey(bob_public_keys),
    ));

    let mut service =
        Service::new(URI::try_from("https://example.com").unwrap());

    service.add_key(&alice_public_keys).unwrap();
    assert!(service.add_key(&alice_public_keys).is_err());

    service.add_delegate(&bob_xid_document).unwrap();
    assert!(service.add_delegate(&bob_xid_document).is_err());

    service.add_allow(Privilege::Encrypt);
    service.add_allow(Privilege::Sign);

    service.set_name("Example Service").unwrap();

    service.add_capability("com.example.messaging").unwrap();
    assert!(service.add_capability("com.example.messaging").is_err());

    let envelope = service.to_envelope();
    #[rustfmt::skip]
    let expected = indoc::indoc! {r#"
        URI(https://example.com) [
            'allow': 'Encrypt'
            'allow': 'Sign'
            'capability': "com.example.messaging"
            'delegate': Reference(7c30cafe)
            'key': Reference(eb9b1cae)
            'name': "Example Service"
        ]
    "#}.trim();
    assert_eq!(envelope.format(), expected);

    let service2 = Service::try_from(&envelope).unwrap();
    assert_eq!(service, service2);
}
