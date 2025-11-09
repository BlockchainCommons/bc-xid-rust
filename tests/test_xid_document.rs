mod common;
use std::collections::HashSet;

use bc_components::{
    EncapsulationScheme, KeyDerivationMethod, PrivateKeyBase, PrivateKeys,
    PrivateKeysProvider, PublicKeysProvider, SignatureScheme, URI, XID,
    XIDProvider, tags,
};
use bc_envelope::{PublicKeys, prelude::*};
use bc_rand::make_fake_random_number_generator;
use bc_xid::{
    Delegate, Error, HasPermissions, Key, Privilege, Service, XIDDocument,
    XIDGeneratorOptions, XIDGenesisMarkOptions, XIDInceptionKeyOptions,
    XIDPrivateKeyOptions, XIDSigningOptions,
};
use indoc::indoc;
use provenance_mark::ProvenanceMarkResolution;

#[test]
fn xid_document() {
    // Create a XID document.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let public_keys = private_key_base.public_keys();
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(public_keys),
        XIDGenesisMarkOptions::None,
    );

    // Extract the XID from the XID document.
    let xid = xid_document.xid();

    // Convert the XID document to an Envelope.
    let envelope = xid_document.clone().into_envelope();
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected_format);

    // Convert the Envelope back to a XIDDocument.
    let xid_document2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, xid_document2);

    // Convert the XID document to a UR
    let xid_document_ur = xid_document.ur_string();
    assert_eq!(
        xid_document_ur,
        "ur:xid/tpsplftpsotanshdhdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnoyaylftpsotansgylftanshfhdcxhslkfzemaylrwttynsdlghrydpmdfzvdglndloimaahykorefddtsguogmvlahqztansgrhdcxetlewzvlwyfdtobeytidosbamkswaomwwfyabakssakggegychesmerkcatekpcxoycsfncsfggmplgshd"
    );
    let xid_document2 = XIDDocument::from_ur_string(&xid_document_ur).unwrap();
    assert_eq!(xid_document, xid_document2);

    // Print the document's XID in debug format, which shows the full
    // identifier.
    let xid_debug = format!("{:?}", xid);
    assert_eq!(
        xid_debug,
        "XID(71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c)"
    );

    // Print the document's XID in display format, which shows the short
    // identifier (first 4 bytes).
    let xid_display = format!("{}", xid);
    assert_eq!(xid_display, "XID(71274df1)");

    // Print the CBOR diagnostic notation for the XID.
    let xid_cbor_diagnostic = xid.to_cbor().diagnostic();
    #[rustfmt::skip]
    assert_eq!(xid_cbor_diagnostic, (indoc! {r#"
        40024(
            h'71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c'
        )
    "#}).trim());

    // Print the hex encoding of the XID.
    with_tags!(|tags: &dyn dcbor::TagsStoreTrait| {
        assert_eq!(tags.name_for_value(tags::TAG_XID), "xid");
    });

    let xid_cbor_hex = xid.to_cbor().hex_annotated();
    #[rustfmt::skip]
    assert_actual_expected!(xid_cbor_hex, (indoc! {r#"
        d9 9c58                                 # tag(40024) xid
            5820                                # bytes(32)
                71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c
    "#}).trim());

    // Print the XID's Bytewords and Bytemoji identifiers.
    let bytewords_identifier = xid.bytewords_identifier(true);
    assert_eq!(bytewords_identifier, "🅧 JUGS DELI GIFT WHEN");
    let bytemoji_identifier = xid.bytemoji_identifier(true);
    assert_eq!(bytemoji_identifier, "🅧 🌊 😹 🌽 🐞");

    // Print the XID's UR.
    let xid_ur = xid.ur_string();
    assert_eq!(
        xid_ur,
        "ur:xid/hdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnvsbyrdfw"
    );
    let xid2 = XID::from_ur_string(&xid_ur).unwrap();
    assert_eq!(xid, xid2);
}

#[test]
fn xid_document_pq() {
    bc_envelope::register_tags();

    // Create post-quantum keys.
    let (signing_private_key, signing_public_key) =
        SignatureScheme::MLDSA44.keypair();
    let (encapsulation_private_key, encapsulation_public_key) =
        EncapsulationScheme::MLKEM512.keypair();
    let private_keys =
        PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
    let public_keys =
        PublicKeys::new(signing_public_key, encapsulation_public_key);

    // Create the XID document.
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicAndPrivateKeys(public_keys, private_keys),
        XIDGenesisMarkOptions::None,
    );

    // Convert the XID document to an Envelope.
    let envelope = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    // Convert the Envelope back to a XIDDocument.
    let xid_document2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, xid_document2);

    // Convert the XID document to a UR. Note that this UR will *not*
    // contain the `PrivateKeys`.
    let xid_document_ur = xid_document.ur_string();

    // The documents should *not* match, because the UR does not
    // contain the `PrivateKeys`.
    let xid_document2 = XIDDocument::from_ur_string(&xid_document_ur).unwrap();
    assert_ne!(xid_document, xid_document2);

    // But the XIDs should match.
    assert_eq!(xid_document.xid(), xid_document2.xid());

    // And the `PublicKeys` should match.
    let public_keys_1: HashSet<PublicKeys> = xid_document
        .keys()
        .iter()
        .map(|k| k.public_keys().clone())
        .collect();
    let public_keys_2: HashSet<PublicKeys> = xid_document2
        .keys()
        .iter()
        .map(|k| k.public_keys().clone())
        .collect();
    assert_eq!(public_keys_1, public_keys_2);
}

#[test]
fn minimal_xid_document() {
    // Create a XID.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid = XID::from(&private_key_base);

    // Create a XIDDocument directly from the XID.
    let xid_document = XIDDocument::from(xid);

    // Convert the XIDDocument to an Envelope.
    let envelope = xid_document.clone().into_envelope();

    // The envelope is just the XID as its subject, with no assertions.
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1)
    "#}).trim();
    assert_eq!(envelope.format(), expected_format);

    // Convert the Envelope back to a XIDDocument.
    let xid_document2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, xid_document2);

    // The CBOR encoding of the XID and the XIDDocument should be the same.
    let xid_cbor = xid.to_cbor();
    let xid_document_cbor = xid_document.to_cbor();
    assert_eq!(xid_cbor, xid_document_cbor);

    // Either a XID or a XIDDocument can be created from the CBOR encoding.
    let xid2 = XID::try_from(xid_cbor).unwrap();
    assert_eq!(xid, xid2);
    let xid_document2 = XIDDocument::try_from(xid_document_cbor).unwrap();
    assert_eq!(xid_document, xid_document2);

    // The UR of the XID and the XIDDocument should be the same.
    let xid_ur = xid.ur_string();
    let expected_ur = "ur:xid/hdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnvsbyrdfw";
    assert_eq!(xid_ur, expected_ur);
    let xid_document_ur = xid_document.ur_string();
    assert_eq!(xid_document_ur, expected_ur);
}

#[test]
fn document_with_resolution_methods() {
    // Create a XID document.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let public_keys = private_key_base.public_keys();
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(public_keys),
        XIDGenesisMarkOptions::None,
    );

    // Add resolution methods.
    xid_document.add_resolution_method(
        URI::try_from("https://resolver.example.com").unwrap(),
    );
    xid_document.add_resolution_method(URI::try_from("btcr:01234567").unwrap());

    // Convert the XID document to an Envelope.
    let envelope = xid_document.clone().into_envelope();
    // println!("{}", envelope.format());
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1) [
            'dereferenceVia': URI(btcr:01234567)
            'dereferenceVia': URI(https://resolver.example.com)
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected_format);

    // Convert the Envelope back to a XIDDocument.
    let xid_document2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, xid_document2);
}

#[test]
fn signed_xid_document() {
    // Generate the inception key.
    let mut rng = make_fake_random_number_generator();
    let private_inception_key = PrivateKeyBase::new_using(&mut rng);
    let public_inception_key = private_inception_key.public_keys();

    // Create a XIDDocument for the inception key.
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(public_inception_key),
        XIDGenesisMarkOptions::None,
    );

    let envelope = xid_document.clone().into_envelope();
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected_format);

    let signed_envelope =
        xid_document.to_signed_envelope(&private_inception_key);
    // println!("{}", signed_envelope.format());
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_actual_expected!(signed_envelope.format(), expected_format);

    let self_certified_xid_document =
        XIDDocument::try_from_signed_envelope(&signed_envelope).unwrap();
    assert_eq!(xid_document, self_certified_xid_document);
}

#[test]
fn with_provenance() {
    provenance_mark::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_inception_key = PrivateKeyBase::new_using(&mut rng);
    let inception_key = private_inception_key.public_keys();

    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(inception_key),
        XIDGenesisMarkOptions::Passphrase(
            "test".to_string(),
            Some(ProvenanceMarkResolution::Quartile),
            Some(Date::from_string("2025-01-01").unwrap()),
            None,
        ),
    );
    let signed_envelope =
        xid_document.to_signed_envelope(&private_inception_key);
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
                'provenance': ProvenanceMark(8aeb51a1)
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_actual_expected!(signed_envelope.format(), expected_format);

    let self_certified_xid_document =
        XIDDocument::try_from_signed_envelope(&signed_envelope).unwrap();
    // The provenance mark should match, but the generator won't be present
    // after deserialization
    assert_eq!(xid_document.xid(), self_certified_xid_document.xid());
    assert_eq!(
        xid_document.provenance(),
        self_certified_xid_document.provenance()
    );
    assert_eq!(xid_document.keys(), self_certified_xid_document.keys());
}

#[test]
fn with_private_key() {
    let mut rng = make_fake_random_number_generator();
    let private_inception_key = PrivateKeyBase::new_using(&mut rng);
    let public_inception_key = private_inception_key.public_keys();

    //
    // A `XIDDocument` can be created from a private key, in which case it
    // will include the private key.
    //

    let xid_document_including_private_key = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_inception_key.clone()),
        XIDGenesisMarkOptions::None,
    );

    //
    // By default, the `Envelope` representation of a `XIDDocument` will
    // omit the private key.
    //

    let signed_envelope_omitting_private_key =
        xid_document_including_private_key
            .to_signed_envelope(&private_inception_key);
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_actual_expected!(
        signed_envelope_omitting_private_key.format(),
        expected_format
    );
    let xid_document2 = XIDDocument::try_from_signed_envelope(
        &signed_envelope_omitting_private_key,
    )
    .unwrap();

    //
    // A `XIDDocument` can be created from a public key, in which case its
    // `Envelope` representation is identical to the default representation.
    //

    let xid_document_excluding_private_key = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(public_inception_key),
        XIDGenesisMarkOptions::None,
    );
    assert_eq!(xid_document_excluding_private_key, xid_document2);

    //
    // The private key can be included in the `Envelope` by explicitly
    // specifying that it should be included.
    //
    // The 'privateKey' assertion is salted to decorrelate the the private
    // key.
    //

    let signed_envelope_including_private_key =
        xid_document_including_private_key.to_signed_envelope_opt(
            &private_inception_key,
            XIDPrivateKeyOptions::Include,
        );
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    {
                        'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, SchnorrPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
                    } [
                        'salt': Salt
                    ]
                    'allow': 'All'
                ]
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_actual_expected!(
        signed_envelope_including_private_key.format(),
        expected_format
    );

    //
    // If the private key is included, the `XIDDocument` is reconstructed
    // with it and is exactly the same as the original.
    //

    let xid_document2 = XIDDocument::try_from_signed_envelope(
        &signed_envelope_including_private_key,
    )
    .unwrap();
    assert_eq!(xid_document_including_private_key, xid_document2);

    //
    // The private key assertion can be elided.
    //

    let signed_document_eliding_private_key =
        xid_document_including_private_key.to_signed_envelope_opt(
            &private_inception_key,
            XIDPrivateKeyOptions::Elide,
        );
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                    ELIDED
                ]
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_actual_expected!(
        signed_document_eliding_private_key.format(),
        expected_format
    );

    //
    // A `XIDDocument` reconstructed from an envelope with the private key
    // elided is the same as the `XIDDocument` created from only the public
    // key.
    //

    let xid_document2 = XIDDocument::try_from_signed_envelope(
        &signed_document_eliding_private_key,
    )
    .unwrap();
    assert_eq!(xid_document_excluding_private_key, xid_document2);
}

#[test]
fn change_key() {
    // Create a XID document.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    // Remove the inception key.
    let mut xid_document_2 = xid_document.clone();
    let inception_key = xid_document_2.remove_inception_key().unwrap();
    assert_eq!(xid_document.inception_key(), Some(&inception_key));
    assert!(xid_document_2.inception_key().is_none());
    assert!(xid_document_2.is_empty());

    let xid_document2_envelope = xid_document_2
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1)
    "#}).trim();
    assert_actual_expected!(xid_document2_envelope.format(), expected_format);

    // Create a new key.
    let private_key_base_2 = PrivateKeyBase::new_using(&mut rng);
    let public_keys_2 = private_key_base_2.public_keys();

    // Add the new key to the empty XID document.
    let key_2 = Key::new_allow_all(public_keys_2);
    xid_document_2.add_key(key_2.clone()).unwrap();
    let xid_document2_envelope = xid_document_2
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(b8164d99, SigningPublicKey(7c30cafe, SchnorrPublicKey(448e2868)), EncapsulationPublicKey(e472f495, X25519PublicKey(e472f495))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_actual_expected!(xid_document2_envelope.format(), expected_format);

    // Same XID, but different key.
    assert_ne!(xid_document, xid_document_2);

    // The new XID document does not have an inception key.
    assert!(xid_document_2.inception_key().is_none());

    // But it does have an encrypter and a verifier.
    assert!(xid_document_2.encryption_key().is_some());
    assert!(xid_document_2.verification_key().is_some());
}

#[test]
fn with_service() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();

    let alice_private_key_base = PrivateKeyBase::new_using(&mut rng);
    let alice_public_keys = alice_private_key_base.public_keys();
    let mut alice_xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(alice_public_keys.clone()),
        XIDGenesisMarkOptions::None,
    );
    alice_xid_document
        .set_name_for_key(&alice_public_keys, "Alice")
        .unwrap();

    let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
    let bob_public_keys = bob_private_key_base.public_keys();
    let mut bob_xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(bob_public_keys.clone()),
        XIDGenesisMarkOptions::None,
    );
    bob_xid_document
        .set_name_for_key(&bob_public_keys, "Bob")
        .unwrap();
    let mut bob_delegate = Delegate::new(&bob_xid_document);
    bob_delegate.add_allow(Privilege::Sign);
    bob_delegate.add_allow(Privilege::Encrypt);

    alice_xid_document.add_delegate(bob_delegate).unwrap();

    let service_uri = URI::try_from("https://example.com").unwrap();
    let mut service = Service::new(&service_uri);

    service.add_key(&alice_public_keys).unwrap();
    service.add_delegate(&bob_xid_document).unwrap();
    service.add_allow(Privilege::Encrypt);
    service.add_allow(Privilege::Sign);
    service.set_name("Example Service").unwrap();
    service.add_capability("com.example.messaging").unwrap();

    alice_xid_document.add_service(service).unwrap();

    let envelope = alice_xid_document.clone().into_envelope();
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        XID(71274df1) [
            'delegate': {
                XID(7c30cafe) [
                    'key': PublicKeys(b8164d99, SigningPublicKey(7c30cafe, SchnorrPublicKey(448e2868)), EncapsulationPublicKey(e472f495, X25519PublicKey(e472f495))) [
                        'allow': 'All'
                        'nickname': "Bob"
                    ]
                ]
            } [
                'allow': 'Encrypt'
                'allow': 'Sign'
            ]
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
                'nickname': "Alice"
            ]
            'service': URI(https://example.com) [
                'allow': 'Encrypt'
                'allow': 'Sign'
                'capability': "com.example.messaging"
                'delegate': Reference(7c30cafe)
                'key': Reference(eb9b1cae)
                'name': "Example Service"
            ]
        ]
    "#}).trim();
    assert_actual_expected!(envelope.format(), expected);

    let alice_xid_document_2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(alice_xid_document, alice_xid_document_2);

    // Can't remove the key or delegate while a service references them.
    assert!(alice_xid_document.remove_key(&alice_public_keys).is_err());
    assert!(
        alice_xid_document
            .remove_delegate(&bob_xid_document)
            .is_err()
    );

    // Remove the service.
    alice_xid_document.remove_service(&service_uri).unwrap();
    // Now the key and delegate can be removed.
    alice_xid_document.remove_key(&alice_public_keys).unwrap();
    alice_xid_document
        .remove_delegate(&bob_xid_document)
        .unwrap();
}

#[test]
fn xid_document_with_encrypted_private_keys() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let public_keys = private_key_base.public_keys();
    let password = b"secure_xid_password";

    //
    // Create an XID document with private keys.
    //
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicAndPrivateKeys(
            public_keys,
            private_keys.clone(),
        ),
        XIDGenesisMarkOptions::None,
    );

    //
    // Convert to envelope with encrypted private keys using Argon2id.
    //
    let envelope_encrypted = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    // The private key should be encrypted in the envelope.
    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypted.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': ENCRYPTED [
                        'hasSecret': EncryptedKey(Argon2id)
                    ]
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    //
    // Try to extract without password - should succeed but keys won't have
    // private key material.
    //
    let xid_doc_no_password =
        XIDDocument::from_unsigned_envelope(&envelope_encrypted).unwrap();
    let inception_key = xid_doc_no_password.inception_key().unwrap();
    assert!(inception_key.private_keys().is_none());

    //
    // Extract with wrong password - should succeed but keys won't have
    // private key material.
    //
    let wrong_password = b"wrong_password";
    let xid_doc_wrong_password =
        XIDDocument::from_unsigned_envelope_with_password(
            &envelope_encrypted,
            Some(wrong_password),
        )
        .unwrap();
    let inception_key = xid_doc_wrong_password.inception_key().unwrap();
    assert!(inception_key.private_keys().is_none());

    //
    // Extract with correct password - should succeed and keys should have
    // private key material.
    //
    let xid_doc_with_password =
        XIDDocument::from_unsigned_envelope_with_password(
            &envelope_encrypted,
            Some(password),
        )
        .unwrap();
    let inception_key = xid_doc_with_password.inception_key().unwrap();
    assert_eq!(inception_key.private_keys(), Some(&private_keys));
    assert_eq!(xid_doc_with_password, xid_document);
}

#[test]
fn xid_document_with_encrypted_multiple_keys() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let password = b"multi_key_password";

    //
    // Create an XID document with inception key.
    //
    let inception_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(inception_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    //
    // Add a second key with private key material.
    //
    let second_base = PrivateKeyBase::new_using(&mut rng);
    let second_key = Key::new_with_private_key_base(second_base.clone());
    xid_document.add_key(second_key).unwrap();

    //
    // Convert to envelope with all private keys encrypted using Scrypt.
    //
    let envelope_encrypted = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // Extract with password - both keys should have their private key
    // material.
    //
    let xid_doc_decrypted = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_encrypted,
        Some(password),
    )
    .unwrap();

    assert_eq!(xid_doc_decrypted.keys().len(), 2);
    for key in xid_doc_decrypted.keys() {
        assert!(key.private_keys().is_some());
    }
    assert_eq!(xid_doc_decrypted, xid_document);
}

#[test]
fn xid_document_private_key_modes() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    //
    // Mode 1: Omit private keys (default)
    //
    let envelope_omit = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    #[rustfmt::skip]
    assert_actual_expected!(envelope_omit.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}.trim());

    // Can extract, but private keys will be None
    let doc_omit = XIDDocument::from_unsigned_envelope(&envelope_omit).unwrap();
    assert!(doc_omit.inception_key().unwrap().private_keys().is_none());

    //
    // Mode 2: Include private keys in plaintext
    //
    let envelope_include = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    assert_actual_expected!(envelope_include.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, SchnorrPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    // Can extract with private keys
    let doc_include =
        XIDDocument::from_unsigned_envelope(&envelope_include).unwrap();
    assert!(
        doc_include
            .inception_key()
            .unwrap()
            .private_keys()
            .is_some()
    );
    assert_eq!(doc_include, xid_document);

    //
    // Mode 3: Elide private keys (maintains digest tree)
    //
    let envelope_elide = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Elide,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    assert_actual_expected!(envelope_elide.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
                ELIDED
            ]
        ]
    "#}.trim());

    // Can extract, but private keys will be None
    let doc_elide =
        XIDDocument::from_unsigned_envelope(&envelope_elide).unwrap();
    assert!(doc_elide.inception_key().unwrap().private_keys().is_none());

    // Elided envelope is equivalent to included envelope (same digest)
    assert!(envelope_elide.is_equivalent_to(&envelope_include));

    //
    // Mode 4: Encrypt private keys with password (Argon2id)
    //
    let password = b"test_password_123";
    let envelope_encrypt = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypt.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': ENCRYPTED [
                        'hasSecret': EncryptedKey(Argon2id)
                    ]
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    // Without password, private keys will be None
    let doc_no_pwd =
        XIDDocument::from_unsigned_envelope(&envelope_encrypt).unwrap();
    assert!(doc_no_pwd.inception_key().unwrap().private_keys().is_none());

    // With correct password, can extract with private keys
    let doc_with_pwd = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_encrypt,
        Some(password),
    )
    .unwrap();
    assert!(
        doc_with_pwd
            .inception_key()
            .unwrap()
            .private_keys()
            .is_some()
    );
    assert_eq!(doc_with_pwd, xid_document);
}

#[test]
fn xid_document_encrypted_with_different_methods() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let password = b"test_password";

    //
    // Test Argon2id (recommended)
    //
    let envelope_argon2id = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    #[rustfmt::skip]
    assert_actual_expected!(envelope_argon2id.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': ENCRYPTED [
                        'hasSecret': EncryptedKey(Argon2id)
                    ]
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    //
    // Test PBKDF2
    //
    let envelope_pbkdf2 = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::PBKDF2,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    assert_actual_expected!(envelope_pbkdf2.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': ENCRYPTED [
                        'hasSecret': EncryptedKey(PBKDF2(SHA256))
                    ]
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    //
    // Test Scrypt
    //
    let envelope_scrypt = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    #[rustfmt::skip]
    assert_actual_expected!(envelope_scrypt.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': ENCRYPTED [
                        'hasSecret': EncryptedKey(Scrypt)
                    ]
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    //
    // All methods should be decryptable with the same password.
    //
    for envelope in &[envelope_argon2id, envelope_pbkdf2, envelope_scrypt] {
        let doc = XIDDocument::from_unsigned_envelope_with_password(
            envelope,
            Some(password),
        )
        .unwrap();
        assert_eq!(doc, xid_document);
    }
}

#[test]
fn xid_document_reencrypt_with_different_password() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let password1 = b"first_password";
    let password2 = b"second_password";

    //
    // Encrypt with first password.
    //
    let envelope1 = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password1.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    //
    // Load with first password.
    //
    let doc_decrypted = XIDDocument::from_unsigned_envelope_with_password(
        &envelope1,
        Some(password1),
    )
    .unwrap();
    assert_eq!(doc_decrypted, xid_document);
    assert!(
        doc_decrypted
            .inception_key()
            .unwrap()
            .private_keys()
            .is_some()
    );

    //
    // Re-encrypt with second password.
    //
    let envelope2 = doc_decrypted
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password2.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // First password should not work on second envelope.
    //
    let doc_wrong_pwd = XIDDocument::from_unsigned_envelope_with_password(
        &envelope2,
        Some(password1),
    )
    .unwrap();
    assert!(
        doc_wrong_pwd
            .inception_key()
            .unwrap()
            .private_keys()
            .is_none()
    );

    //
    // Second password should work.
    //
    let doc_reencrypted = XIDDocument::from_unsigned_envelope_with_password(
        &envelope2,
        Some(password2),
    )
    .unwrap();
    assert_eq!(doc_reencrypted, xid_document);
    assert_eq!(
        doc_reencrypted
            .inception_key()
            .unwrap()
            .private_keys()
            .unwrap(),
        &private_keys
    );

    //
    // The two encrypted envelopes should be different (different passwords).
    //
    assert_ne!(envelope1.ur_string(), envelope2.ur_string());

    //
    // But the salt should be preserved (same Key identity).
    //
    let salt1 = xid_document
        .inception_key()
        .unwrap()
        .private_key_salt()
        .unwrap();
    let salt2 = doc_reencrypted
        .inception_key()
        .unwrap()
        .private_key_salt()
        .unwrap();
    assert_eq!(salt1, salt2);
}

#[test]
fn xid_document_change_encryption_method() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let password = b"shared_password";

    //
    // Encrypt with Argon2id.
    //
    let envelope_argon2id = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // Load and decrypt.
    //
    let doc_decrypted = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_argon2id,
        Some(password),
    )
    .unwrap();

    //
    // Re-encrypt with Scrypt.
    //
    let envelope_scrypt = doc_decrypted
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // Verify the method changed.
    //
    let format_argon2id = envelope_argon2id.format();
    let format_scrypt = envelope_scrypt.format();
    assert!(format_argon2id.contains("EncryptedKey(Argon2id)"));
    assert!(format_scrypt.contains("EncryptedKey(Scrypt)"));

    //
    // Both should decrypt with the same password.
    //
    let doc_from_scrypt = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_scrypt,
        Some(password),
    )
    .unwrap();
    assert_eq!(doc_from_scrypt, xid_document);

    //
    // Salt should be preserved across method changes.
    //
    assert_eq!(
        doc_decrypted.inception_key().unwrap().private_key_salt(),
        doc_from_scrypt.inception_key().unwrap().private_key_salt()
    );
}

#[test]
fn xid_document_encrypt_decrypt_plaintext_roundtrip() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let password = b"test_password";

    //
    // Start with plaintext.
    //
    let envelope_plaintext = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    assert_actual_expected!(envelope_plaintext.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, SchnorrPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    //
    // Load plaintext document.
    //
    let doc_from_plaintext =
        XIDDocument::from_unsigned_envelope(&envelope_plaintext).unwrap();
    assert_eq!(doc_from_plaintext, xid_document);

    //
    // Encrypt it.
    //
    let envelope_encrypted = doc_from_plaintext
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypted.format(), indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                {
                    'privateKey': ENCRYPTED [
                        'hasSecret': EncryptedKey(Argon2id)
                    ]
                } [
                    'salt': Salt
                ]
                'allow': 'All'
            ]
        ]
    "#}.trim());

    //
    // Decrypt it.
    //
    let doc_decrypted = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_encrypted,
        Some(password),
    )
    .unwrap();
    assert_eq!(doc_decrypted, xid_document);
    assert_eq!(
        doc_decrypted
            .inception_key()
            .unwrap()
            .private_keys()
            .unwrap(),
        &private_keys
    );

    //
    // Convert back to plaintext.
    //
    let envelope_plaintext2 = doc_decrypted
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // Should match original plaintext.
    //
    let doc_final =
        XIDDocument::from_unsigned_envelope(&envelope_plaintext2).unwrap();
    assert_eq!(doc_final, xid_document);

    //
    // Salt should be consistent throughout.
    //
    let salt_original = xid_document
        .inception_key()
        .unwrap()
        .private_key_salt()
        .unwrap();
    let salt_final = doc_final
        .inception_key()
        .unwrap()
        .private_key_salt()
        .unwrap();
    assert_eq!(salt_original, salt_final);
}

#[test]
fn xid_document_switch_between_storage_modes() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let password = b"mode_switch_password";

    //
    // Mode 1: Plaintext
    //
    let envelope_plaintext = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    let doc1 =
        XIDDocument::from_unsigned_envelope(&envelope_plaintext).unwrap();
    assert_eq!(doc1, xid_document);

    //
    // Mode 2: Encrypted
    //
    let envelope_encrypted = doc1
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    let doc2 = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_encrypted,
        Some(password),
    )
    .unwrap();
    assert_eq!(doc2, xid_document);

    //
    // Mode 3: Omitted
    //
    let envelope_omit = doc2
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    let doc3 = XIDDocument::from_unsigned_envelope(&envelope_omit).unwrap();
    // Different because private keys are omitted
    assert_ne!(doc3, xid_document);
    assert!(doc3.inception_key().unwrap().private_keys().is_none());

    //
    // Can't get back to full document from omitted.
    // But if we go back to doc2, we can.
    //
    let envelope_plaintext2 = doc2
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    let doc4 =
        XIDDocument::from_unsigned_envelope(&envelope_plaintext2).unwrap();
    assert_eq!(doc4, xid_document);

    //
    // Mode 4: Elided (maintains digest)
    //
    let envelope_elide = doc2
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Elide,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();
    let doc5 = XIDDocument::from_unsigned_envelope(&envelope_elide).unwrap();
    assert_ne!(doc5, xid_document);
    assert!(doc5.inception_key().unwrap().private_keys().is_none());

    //
    // Elided should be equivalent to plaintext (same digest).
    //
    assert!(envelope_elide.is_equivalent_to(&envelope_plaintext));
}

#[test]
fn xid_document_preserves_encrypted_keys_when_modified() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let password = b"secret_password";

    //
    // Create document with encrypted private keys.
    //
    let envelope_encrypted = xid_document
        .clone()
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // Load without password - encrypted keys are preserved but not accessible.
    //
    let mut doc_no_password =
        XIDDocument::from_unsigned_envelope(&envelope_encrypted).unwrap();

    // Private keys are not accessible
    assert!(
        doc_no_password
            .inception_key()
            .unwrap()
            .private_keys()
            .is_none()
    );

    // But encrypted keys ARE present
    assert!(
        doc_no_password
            .inception_key()
            .unwrap()
            .has_encrypted_private_keys()
    );

    //
    // Modify the document (add a resolution method).
    //
    let method_uri = URI::new("https://resolver.example.com").unwrap();
    doc_no_password.add_resolution_method(method_uri.clone());

    //
    // Serialize with Include option - encrypted keys should be preserved.
    //
    let envelope_after_modification = doc_no_password
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    //
    // The encrypted keys should still be there (not decrypted, still
    // encrypted).
    //
    #[rustfmt::skip]
    let format = envelope_after_modification.format();
    assert!(format.contains("ENCRYPTED"));
    assert!(format.contains("hasSecret"));
    assert!(format.contains("dereference"));

    //
    // Load with password - should decrypt the keys.
    //
    let doc_with_password = XIDDocument::from_unsigned_envelope_with_password(
        &envelope_after_modification,
        Some(password),
    )
    .unwrap();

    // Should have the resolution method we added
    assert!(doc_with_password.resolution_methods().contains(&method_uri));

    // Should have decrypted private keys
    assert!(
        doc_with_password
            .inception_key()
            .unwrap()
            .private_keys()
            .is_some()
    );
}

#[test]
fn private_key_envelope_for_key() {
    let prvkey_base = PrivateKeyBase::new();
    let doc = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(prvkey_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let pubkeys = doc.inception_key().unwrap().public_keys().clone();

    // Get unencrypted private key
    let envelope = doc
        .private_key_envelope_for_key(&pubkeys, None)
        .unwrap()
        .unwrap();

    let private_keys = PrivateKeys::try_from(envelope.subject()).unwrap();
    assert_eq!(private_keys, prvkey_base.private_keys());
}

#[test]
fn private_key_envelope_for_key_encrypted() {
    let prvkey_base = PrivateKeyBase::new();
    let password = "test-password";

    // Create document with encrypted key
    let doc = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(prvkey_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    let envelope_encrypted = doc
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.as_bytes().to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    let doc_encrypted =
        XIDDocument::from_unsigned_envelope(&envelope_encrypted).unwrap();
    let pubkeys = doc_encrypted.inception_key().unwrap().public_keys().clone();

    // Without password - should get encrypted envelope
    let encrypted_env = doc_encrypted
        .private_key_envelope_for_key(&pubkeys, None)
        .unwrap()
        .unwrap();
    let formatted = encrypted_env.format();
    assert!(formatted.contains("ENCRYPTED"));
    assert!(formatted.contains("hasSecret"));

    // With correct password - should get decrypted keys
    let decrypted_env = doc_encrypted
        .private_key_envelope_for_key(&pubkeys, Some(password))
        .unwrap()
        .unwrap();
    let private_keys = PrivateKeys::try_from(decrypted_env.subject()).unwrap();
    assert_eq!(private_keys, prvkey_base.private_keys());

    // With wrong password - should error
    let result =
        doc_encrypted.private_key_envelope_for_key(&pubkeys, Some("wrong"));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidPassword));
}

#[test]
fn private_key_envelope_for_key_not_found() {
    let prvkey_base = PrivateKeyBase::new();
    let doc = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(prvkey_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    // Try to get key that doesn't exist
    let other_pubkeys = PrivateKeyBase::new().public_keys();
    let result = doc
        .private_key_envelope_for_key(&other_pubkeys, None)
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn private_key_envelope_for_key_no_private_key() {
    // Create document with public key only
    let pubkeys = PrivateKeyBase::new().public_keys();
    let doc = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(pubkeys.clone()),
        XIDGenesisMarkOptions::None,
    );

    // Should return None (no private key present)
    let result = doc.private_key_envelope_for_key(&pubkeys, None).unwrap();
    assert!(result.is_none());
}

#[test]
fn new_xid_document() {
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::Default,
        XIDGenesisMarkOptions::None,
    );
    println!(
        "{}",
        xid_document
            .to_envelope(
                XIDPrivateKeyOptions::Include,
                XIDGeneratorOptions::default(),
                XIDSigningOptions::default()
            )
            .unwrap()
            .format()
    );
}

#[test]
fn test_signing_options_none() {
    // Create a XID document with private keys.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    // Convert to envelope with SigningOptions::None.
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::None,
        )
        .unwrap();

    // Envelope should not have a wrapped subject (not signed).
    assert!(!envelope.subject().is_wrapped());

    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        XID(71274df1) [
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}).trim();
    assert_eq!(envelope.format(), expected_format);
}

#[test]
fn test_signing_options_inception() {
    // Create a XID document with private keys.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    // Convert to envelope with SigningOptions::Inception.
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::Inception,
        )
        .unwrap();

    // Envelope subject should be wrapped (this is how sign() works).
    assert!(envelope.subject().is_wrapped());

    #[rustfmt::skip]
    let expected_format = (indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_eq!(envelope.format(), expected_format);

    // Verify the signature can be validated.
    let xid_document2 =
        XIDDocument::try_from_signed_envelope(&envelope).unwrap();
    // Note: xid_document2 won't have private keys since we didn't provide a password
    assert_eq!(xid_document.xid(), xid_document2.xid());
}

#[test]
fn test_signing_options_inception_missing_private_key() {
    // Create a XID document without private keys.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let public_keys = private_key_base.public_keys();
    let xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(public_keys),
        XIDGenesisMarkOptions::None,
    );

    // Attempting to sign with inception key should fail.
    let result = xid_document.to_envelope(
        XIDPrivateKeyOptions::default(),
        XIDGeneratorOptions::default(),
        XIDSigningOptions::Inception,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::MissingInceptionKey));
}

#[test]
fn test_signing_options_private_keys() {
    // Create a XID document.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    // Create a separate signing key.
    let signing_key = PrivateKeyBase::new_using(&mut rng);
    let signing_private_keys = signing_key.private_keys();

    // Sign with the separate key.
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::PrivateKeys(signing_private_keys.clone()),
        )
        .unwrap();

    // Envelope subject should be wrapped (signed).
    assert!(envelope.subject().is_wrapped());

    // The envelope should have a signature - just verify it's formatted correctly
    assert!(envelope.format().contains("'signed': Signature"));
}

#[test]
fn test_signing_options_signing_private_key() {
    // Create a XID document.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    // Create a separate signing key.
    let signing_key = PrivateKeyBase::new_using(&mut rng);
    let signing_private_key = signing_key.schnorr_signing_private_key();

    // Sign with the separate signing private key.
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::SigningPrivateKey(signing_private_key.clone()),
        )
        .unwrap();

    // Envelope subject should be wrapped (signed).
    assert!(envelope.subject().is_wrapped());

    // The envelope should have a signature - just verify it's formatted correctly
    assert!(envelope.format().contains("'signed': Signature"));
}

#[test]
fn test_signing_options_with_private_key_options() {
    // Create a XID document with private keys.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    // Sign with inception key and include private keys.
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Include,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::Inception,
        )
        .unwrap();

    // Envelope subject should be wrapped (signed).
    assert!(envelope.subject().is_wrapped());

    // Unwrap to get inner envelope.
    let inner_envelope = envelope.try_unwrap().unwrap();

    // Extract XIDDocument and verify it has private keys.
    let xid_document2 = XIDDocument::try_from(&inner_envelope).unwrap();
    assert!(xid_document2.inception_key().unwrap().has_private_keys());
}

#[test]
fn test_backward_compatibility_to_unsigned_envelope() {
    // Verify that the old API still works.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::default(),
        )
        .unwrap();

    assert!(!envelope.subject().is_wrapped());
    assert_eq!(
        envelope.format(),
        xid_document
            .to_envelope(
                XIDPrivateKeyOptions::default(),
                XIDGeneratorOptions::default(),
                XIDSigningOptions::None,
            )
            .unwrap()
            .format()
    );
}

#[test]
fn test_backward_compatibility_to_signed_envelope() {
    // Verify that the old API still works.
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    let envelope = xid_document.to_signed_envelope(&private_key_base);

    assert!(envelope.subject().is_wrapped());

    // Should be equivalent to using SigningOptions with the same key.
    let envelope2 = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::None,
        )
        .unwrap()
        .sign(&private_key_base);

    assert_eq!(envelope.format(), envelope2.format());
}
