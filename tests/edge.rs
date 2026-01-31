mod common;

use bc_components::{DigestProvider, PrivateKeyBase, PublicKeysProvider, XIDProvider};
use bc_envelope::prelude::*;
use bc_rand::make_fake_random_number_generator;
use bc_xid::{
    XIDDocument, XIDGeneratorOptions, XIDGenesisMarkOptions,
    XIDInceptionKeyOptions, XIDPrivateKeyOptions, XIDSigningOptions,
    XIDVerifySignature,
};
use indoc::indoc;

/// Helper to create a basic edge envelope with the three required assertions.
fn make_edge(
    subject: &str,
    is_a: &str,
    source: &Envelope,
    target: &Envelope,
) -> Envelope {
    Envelope::new(subject)
        .add_assertion(known_values::IS_A, is_a)
        .add_assertion(known_values::SOURCE, source.clone())
        .add_assertion(known_values::TARGET, target.clone())
}

// -------------------------------------------------------------------
// Adding and querying edges on XIDDocument
// -------------------------------------------------------------------

#[test]
fn test_xid_document_initially_has_no_edges() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    assert!(!xid_document.has_edges());
    assert!(xid_document.edges().is_empty());
    assert_eq!(xid_document.edges().len(), 0);
}

#[test]
fn test_xid_document_add_edge() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    let edge = make_edge("knows-bob", "schema:colleague", &alice, &bob);

    xid_document.add_edge(edge);

    assert!(xid_document.has_edges());
    assert_eq!(xid_document.edges().len(), 1);
}

#[test]
fn test_xid_document_add_multiple_edges() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    let edge1 = make_edge("knows-bob", "schema:colleague", &alice, &bob);
    let edge2 = make_edge("self-desc", "foaf:Person", &alice, &alice);

    xid_document.add_edge(edge1);
    xid_document.add_edge(edge2);

    assert_eq!(xid_document.edges().len(), 2);
}

#[test]
fn test_xid_document_get_edge_by_digest() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    let digest = edge.digest();

    xid_document.add_edge(edge.clone());

    let retrieved = xid_document.get_edge(digest).unwrap();
    assert!(retrieved.is_equivalent_to(&edge));
}

#[test]
fn test_xid_document_get_edge_nonexistent() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);

    assert!(xid_document.get_edge(edge.digest()).is_none());
}

#[test]
fn test_xid_document_remove_edge() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    let digest = edge.digest();

    xid_document.add_edge(edge);
    assert!(xid_document.has_edges());

    let removed = xid_document.remove_edge(digest);
    assert!(removed.is_some());
    assert!(!xid_document.has_edges());
}

#[test]
fn test_xid_document_remove_edge_nonexistent() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);

    let removed = xid_document.remove_edge(edge.digest());
    assert!(removed.is_none());
}

#[test]
fn test_xid_document_clear_edges() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    xid_document.add_edge(make_edge("e1", "foaf:Person", &alice, &alice));
    xid_document.add_edge(make_edge("e2", "schema:colleague", &alice, &bob));
    assert_eq!(xid_document.edges().len(), 2);

    xid_document.clear_edges();
    assert!(!xid_document.has_edges());
    assert_eq!(xid_document.edges().len(), 0);
}

// -------------------------------------------------------------------
// Envelope format with edges
// -------------------------------------------------------------------

#[test]
fn test_xid_document_with_single_edge_format() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    xid_document.add_edge(edge);

    let envelope = xid_document.clone().into_envelope();

    #[rustfmt::skip]
    assert_actual_expected!(envelope.format(), indoc! {r#"
        XID(71274df1) [
            'edge': "cred-1" [
                'isA': "foaf:Person"
                'source': "Alice"
                'target': "Alice"
            ]
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}.trim());

    // Round-trip
    let xid_document2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, xid_document2);
}

#[test]
fn test_xid_document_with_multiple_edges_format() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    let edge1 = make_edge("self-desc", "foaf:Person", &alice, &alice);
    let edge2 = make_edge("knows-bob", "schema:colleague", &alice, &bob);
    xid_document.add_edge(edge1);
    xid_document.add_edge(edge2);

    let envelope = xid_document.clone().into_envelope();
    let format = envelope.format();

    // Both edges should appear
    assert!(format.contains("'edge': \"self-desc\""));
    assert!(format.contains("'edge': \"knows-bob\""));
    assert!(format.contains("'isA': \"foaf:Person\""));
    assert!(format.contains("'isA': \"schema:colleague\""));

    // Round-trip
    let xid_document2 = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, xid_document2);
}

// -------------------------------------------------------------------
// Envelope round-trip via UR
// -------------------------------------------------------------------

#[test]
fn test_xid_document_with_edges_ur_roundtrip() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    xid_document.add_edge(make_edge("cred-1", "foaf:Person", &alice, &alice));
    xid_document.add_edge(make_edge("knows-bob", "schema:colleague", &alice, &bob));

    let ur = xid_document.ur_string();
    let recovered = XIDDocument::from_ur_string(&ur).unwrap();

    assert_eq!(xid_document, recovered);
    assert_eq!(recovered.edges().len(), 2);
}

// -------------------------------------------------------------------
// Edges with signed XIDDocument
// -------------------------------------------------------------------

#[test]
fn test_xid_document_with_edges_signed() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    xid_document.add_edge(edge);

    let signed_envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::Inception,
        )
        .unwrap();

    #[rustfmt::skip]
    assert_actual_expected!(signed_envelope.format(), indoc! {r#"
        {
            XID(71274df1) [
                'edge': "cred-1" [
                    'isA': "foaf:Person"
                    'source': "Alice"
                    'target': "Alice"
                ]
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
            ]
        } [
            'signed': Signature
        ]
    "#}.trim());

    // Recover with signature verification
    let recovered = XIDDocument::from_envelope(
        &signed_envelope,
        None,
        XIDVerifySignature::Inception,
    )
    .unwrap();
    assert_eq!(xid_document.xid(), recovered.xid());
    assert!(recovered.has_edges());
    assert_eq!(recovered.edges().len(), 1);
}

// -------------------------------------------------------------------
// Edges with encrypted private keys
// -------------------------------------------------------------------

#[test]
fn test_xid_document_with_edges_and_encrypted_keys() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(private_key_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    xid_document.add_edge(edge);

    let password = b"test_password";
    let envelope = xid_document
        .to_envelope(
            XIDPrivateKeyOptions::Encrypt {
                method: bc_components::KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
            XIDGeneratorOptions::default(),
            XIDSigningOptions::None,
        )
        .unwrap();

    // Edges should coexist with encrypted keys
    let format = envelope.format();
    assert!(format.contains("'edge'"));
    assert!(format.contains("ENCRYPTED"));

    // Round-trip with decryption
    let recovered = XIDDocument::from_envelope(
        &envelope,
        Some(password),
        XIDVerifySignature::None,
    )
    .unwrap();
    assert_eq!(xid_document, recovered);
    assert!(recovered.has_edges());
}

// -------------------------------------------------------------------
// Edges persist across modifications
// -------------------------------------------------------------------

#[test]
fn test_xid_document_edges_persist_after_modifications() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    xid_document.add_edge(edge);
    assert!(xid_document.has_edges());

    // Add a resolution method — edges should still be present
    xid_document.add_resolution_method(
        bc_components::URI::try_from("https://resolver.example.com").unwrap(),
    );
    assert!(xid_document.has_edges());
    assert_eq!(xid_document.edges().len(), 1);

    // Serialize and recover
    let envelope = xid_document.clone().into_envelope();
    let recovered = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, recovered);
    assert!(recovered.has_edges());
}

// -------------------------------------------------------------------
// Edge accessors on edges within XIDDocument
// -------------------------------------------------------------------

#[test]
fn test_xid_document_edge_accessors() -> Result<(), EnvelopeError> {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    let edge = make_edge("knows-bob", "schema:colleague", &alice, &bob);
    let digest = edge.digest();

    xid_document.add_edge(edge);

    let retrieved = xid_document.get_edge(digest).unwrap();
    assert_actual_expected!(retrieved.edge_is_a()?.format(), r#""schema:colleague""#);
    assert_actual_expected!(retrieved.edge_source()?.format(), r#""Alice""#);
    assert_actual_expected!(retrieved.edge_target()?.format(), r#""Bob""#);
    assert_actual_expected!(retrieved.edge_subject()?.format(), r#""knows-bob""#);

    Ok(())
}

// -------------------------------------------------------------------
// Edge iteration
// -------------------------------------------------------------------

#[test]
fn test_xid_document_edge_iteration() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    xid_document.add_edge(make_edge("e1", "foaf:Person", &alice, &alice));
    xid_document.add_edge(make_edge("e2", "schema:colleague", &alice, &bob));
    xid_document.add_edge(make_edge("e3", "schema:CreativeWork", &alice, &bob));

    let count = xid_document.edges().iter().count();
    assert_eq!(count, 3);

    // All iterated edges should validate
    for (_digest, edge) in xid_document.edges().iter() {
        assert!(edge.validate_edge().is_ok());
    }
}

// -------------------------------------------------------------------
// Edges with extra assertions beyond the required three
// -------------------------------------------------------------------

#[test]
fn test_xid_document_edge_with_additional_assertions() -> Result<(), EnvelopeError> {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    let edge = Envelope::new("knows-bob")
        .add_assertion(known_values::IS_A, "schema:colleague")
        .add_assertion(known_values::SOURCE, alice.clone())
        .add_assertion(known_values::TARGET, bob.clone())
        .add_assertion("department", "Engineering")
        .add_assertion("since", "2024-01-15");

    xid_document.add_edge(edge);

    let envelope = xid_document.clone().into_envelope();

    #[rustfmt::skip]
    assert_actual_expected!(envelope.format(), indoc! {r#"
        XID(71274df1) [
            'edge': "knows-bob" [
                'isA': "schema:colleague"
                "department": "Engineering"
                "since": "2024-01-15"
                'source': "Alice"
                'target': "Bob"
            ]
            'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                'allow': 'All'
            ]
        ]
    "#}.trim());

    // Round-trip preserves extra assertions
    let recovered = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, recovered);

    let edge = recovered.edges().iter().next().unwrap().1;
    assert!(edge.validate_edge().is_ok());
    assert_actual_expected!(edge.edge_is_a()?.format(), r#""schema:colleague""#);

    Ok(())
}

// -------------------------------------------------------------------
// Edges coexist with attachments
// -------------------------------------------------------------------

#[test]
fn test_xid_document_edges_coexist_with_attachments() {
    use bc_envelope::Attachable;

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    xid_document.add_edge(edge);
    xid_document.add_attachment("metadata", "com.example", None);

    assert!(xid_document.has_edges());
    assert!(xid_document.has_attachments());

    let envelope = xid_document.clone().into_envelope();
    let format = envelope.format();
    assert!(format.contains("'edge'"));
    assert!(format.contains("'attachment'"));

    let recovered = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, recovered);
    assert!(recovered.has_edges());
    assert!(recovered.has_attachments());
}

// -------------------------------------------------------------------
// Edge equality — same edge added to two documents
// -------------------------------------------------------------------

#[test]
fn test_xid_document_edge_equality_via_roundtrip() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::new(
        XIDInceptionKeyOptions::PublicKeys(private_key_base.public_keys()),
        XIDGenesisMarkOptions::None,
    );

    let alice = Envelope::new("Alice");
    let edge = make_edge("cred-1", "foaf:Person", &alice, &alice);
    xid_document.add_edge(edge);

    // Round-trip through envelope should produce equal documents
    let envelope = xid_document.clone().into_envelope();
    let recovered = XIDDocument::try_from(envelope).unwrap();
    assert_eq!(xid_document, recovered);
}

// -------------------------------------------------------------------
// Edge removal leaves other edges intact
// -------------------------------------------------------------------

#[test]
fn test_xid_document_remove_one_edge_leaves_others() {
    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let mut xid_document = XIDDocument::from(&private_key_base);

    let alice = Envelope::new("Alice");
    let bob = Envelope::new("Bob");
    let edge1 = make_edge("e1", "foaf:Person", &alice, &alice);
    let edge2 = make_edge("e2", "schema:colleague", &alice, &bob);
    let digest1 = edge1.digest();
    let digest2 = edge2.digest();

    xid_document.add_edge(edge1);
    xid_document.add_edge(edge2);
    assert_eq!(xid_document.edges().len(), 2);

    xid_document.remove_edge(digest1);
    assert_eq!(xid_document.edges().len(), 1);
    assert!(xid_document.get_edge(digest2).is_some());
    assert!(xid_document.get_edge(digest1).is_none());
}
