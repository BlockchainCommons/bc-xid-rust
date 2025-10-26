mod common;

use std::collections::HashSet;

use bc_components::{KeyDerivationMethod, PrivateKeyBase, PrivateKeys, PrivateKeysProvider, PublicKeysProvider, URI};
use bc_envelope::prelude::*;
use bc_rand::make_fake_random_number_generator;
use indoc::indoc;

use bc_xid::{Error, HasNickname, HasPermissions, Key, PrivateKeyOptions, Privilege};

#[test]
fn test_key() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let _ = private_key_base.private_keys();
    let public_keys = private_key_base.public_keys();

    let resolver1 = URI::new("https://resolver.example.com").unwrap();
    let resolver2 = URI::new(
        "btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33"
    ).unwrap();
    let resolvers: HashSet<URI> =
        vec![resolver1, resolver2].into_iter().collect();

    let mut key = Key::new(public_keys);
    key.endpoints_mut().extend(resolvers);
    key.add_allow(Privilege::All);
    key.set_nickname("Alice's key".to_string());

    let envelope = key.clone().into_envelope();
    let key2 = Key::try_from(&envelope).unwrap();
    assert_eq!(key, key2);

    #[rustfmt::skip]
    assert_actual_expected!(envelope.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            'allow': 'All'
            'endpoint': URI(btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33)
            'endpoint': URI(https://resolver.example.com)
            'nickname': "Alice's key"
        ]
    "#}.trim());
}

#[test]
fn test_with_private_key() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let public_keys = private_key_base.public_keys();

    //
    // A `Key` can be constructed from a `PrivateKeys` implicitly gets
    // all permissions.
    //

    let key_including_private_key = Key::new_with_private_keys(
        private_keys.clone(),
        public_keys.clone(),
    );

    //
    // Permissions given to a `Key` constructed from a `PublicKeys` are
    // explicit.
    //

    let key_omitting_private_key =
        Key::new_allow_all(private_key_base.public_keys());

    //
    // When converting to an `Envelope`, the default is to omit the private
    // key because it is sensitive.
    //

    let envelope_omitting_private_key =
        key_including_private_key.clone().into_envelope();

    #[rustfmt::skip]
    assert_actual_expected!(envelope_omitting_private_key.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            'allow': 'All'
        ]
    "#}.trim());

    //
    // If the private key is omitted, the Key is reconstructed without it.
    //

    let key2 = Key::try_from(&envelope_omitting_private_key).unwrap();
    assert_eq!(key_omitting_private_key, key2);

    //
    // The private key can be included in the envelope by explicitly
    // specifying that it should be included.
    //
    // The 'privateKey' assertion is salted to decorrelate the private key.
    //

    let envelope_including_private_key = key_including_private_key
        .clone()
        .into_envelope_opt(PrivateKeyOptions::Include);

    #[rustfmt::skip]
    assert_actual_expected!(envelope_including_private_key.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, ECPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());

    //
    // If the private key is included, the Key is reconstructed with it and
    // is exactly the same as the original.
    //

    let key2 = Key::try_from(&envelope_including_private_key).unwrap();
    assert_eq!(key_including_private_key, key2);

    //
    // The private key assertion can be elided.
    //

    let envelope_eliding_private_key = key_including_private_key
        .clone()
        .into_envelope_opt(PrivateKeyOptions::Elide);

    #[rustfmt::skip]
    assert_actual_expected!(envelope_eliding_private_key.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            'allow': 'All'
            ELIDED
        ]
    "#}.trim());

    //
    // If the private key is elided, the Key is reconstructed without it.
    //

    let key2 = Key::try_from(&envelope_eliding_private_key).unwrap();
    assert_eq!(key_omitting_private_key, key2);

    //
    // The elided envelope has the same root hash as the envelope including
    // the private key, affording inclusion proofs.
    //

    assert!(
        envelope_eliding_private_key
            .is_equivalent_to(&envelope_including_private_key)
    );
}

#[test]
fn test_key_with_encrypted_private_key() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let public_keys = private_key_base.public_keys();
    let password = b"correct_horse_battery_staple";

    let key = Key::new_with_private_keys(
        private_keys.clone(),
        public_keys.clone(),
    );

    //
    // Encrypt the private key with Argon2id.
    //
    let envelope_encrypted =
        key.clone().into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.to_vec(),
        });

    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypted.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': ENCRYPTED [
                    'hasSecret': EncryptedKey(Argon2id)
                ]
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());

    //
    // Extract without password - should succeed but private key is None.
    //
    let key_no_password =
        Key::try_from_envelope(&envelope_encrypted, None).unwrap();
    assert!(key_no_password.private_keys().is_none());
    assert_eq!(key_no_password.public_keys(), &public_keys);

    //
    // Extract with wrong password - should succeed but private key is None.
    //
    let wrong_password = b"wrong_password";
    let key_wrong_password =
        Key::try_from_envelope(&envelope_encrypted, Some(wrong_password))
            .unwrap();
    assert!(key_wrong_password.private_keys().is_none());

    //
    // Extract with correct password - should succeed with private key.
    //
    let key_decrypted =
        Key::try_from_envelope(&envelope_encrypted, Some(password))
            .unwrap();
    assert_eq!(key_decrypted.private_keys(), Some(&private_keys));
    assert_eq!(key_decrypted, key);
}

#[test]
fn test_key_encrypted_with_different_methods() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let public_keys = private_key_base.public_keys();
    let password = b"test_password_123";

    let key = Key::new_with_private_keys(
        private_keys.clone(),
        public_keys.clone(),
    );

    //
    // Test encryption with Argon2id (recommended).
    //
    let envelope_argon2id =
        key.clone().into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.to_vec(),
        });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_argon2id.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': ENCRYPTED [
                    'hasSecret': EncryptedKey(Argon2id)
                ]
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());
    let key_argon2id =
        Key::try_from_envelope(&envelope_argon2id, Some(password)).unwrap();
    assert_eq!(key_argon2id, key);

    //
    // Test encryption with PBKDF2.
    //
    let envelope_pbkdf2 =
        key.clone().into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::PBKDF2,
            password: password.to_vec(),
        });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_pbkdf2.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': ENCRYPTED [
                    'hasSecret': EncryptedKey(PBKDF2(SHA256))
                ]
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());
    let key_pbkdf2 =
        Key::try_from_envelope(&envelope_pbkdf2, Some(password)).unwrap();
    assert_eq!(key_pbkdf2, key);

    //
    // Test encryption with Scrypt.
    //
    let envelope_scrypt =
        key.clone().into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Scrypt,
            password: password.to_vec(),
        });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_scrypt.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': ENCRYPTED [
                    'hasSecret': EncryptedKey(Scrypt)
                ]
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());
    let key_scrypt =
        Key::try_from_envelope(&envelope_scrypt, Some(password)).unwrap();
    assert_eq!(key_scrypt, key);

    //
    // Each encryption produces a different envelope (different salts/nonces).
    //
    assert_ne!(envelope_argon2id.ur_string(), envelope_pbkdf2.ur_string());
    assert_ne!(envelope_pbkdf2.ur_string(), envelope_scrypt.ur_string());
    assert_ne!(envelope_argon2id.ur_string(), envelope_scrypt.ur_string());
}

#[test]
fn test_key_private_key_storage_modes() {
    bc_envelope::register_tags();

    let mut rng = make_fake_random_number_generator();
    let private_key_base = PrivateKeyBase::new_using(&mut rng);
    let private_keys = private_key_base.private_keys();
    let public_keys = private_key_base.public_keys();

    let key = Key::new_with_private_keys(
        private_keys.clone(),
        public_keys.clone(),
    );

    //
    // Mode 1: Omit private key (default, most secure for sharing).
    //
    let envelope_omit = key.clone().into_envelope();
    #[rustfmt::skip]
    assert_actual_expected!(envelope_omit.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            'allow': 'All'
        ]
    "#}.trim());

    let key_omit = Key::try_from(&envelope_omit).unwrap();
    assert!(key_omit.private_keys().is_none());

    //
    // Mode 2: Include private key in plaintext.
    //
    let envelope_include =
        key.clone().into_envelope_opt(PrivateKeyOptions::Include);
    #[rustfmt::skip]
    assert_actual_expected!(envelope_include.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, ECPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());

    let key_include = Key::try_from(&envelope_include).unwrap();
    assert_eq!(key_include, key);

    //
    // Mode 3: Elide private key (maintains digest for proofs).
    //
    let envelope_elide =
        key.clone().into_envelope_opt(PrivateKeyOptions::Elide);
    #[rustfmt::skip]
    assert_actual_expected!(envelope_elide.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            'allow': 'All'
            ELIDED
        ]
    "#}.trim());

    let key_elide = Key::try_from(&envelope_elide).unwrap();
    assert!(key_elide.private_keys().is_none());
    assert!(envelope_elide.is_equivalent_to(&envelope_include));

    //
    // Mode 4: Encrypt private key with password.
    //
    let password = b"secure_password";
    let envelope_encrypt =
        key.clone().into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.to_vec(),
        });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypt.format(), indoc! {r#"
        PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
            {
                'privateKey': ENCRYPTED [
                    'hasSecret': EncryptedKey(Argon2id)
                ]
            } [
                'salt': Salt
            ]
            'allow': 'All'
        ]
    "#}.trim());

    // Without password
    let key_no_pwd =
        Key::try_from_envelope(&envelope_encrypt, None).unwrap();
    assert!(key_no_pwd.private_keys().is_none());

    // With password
    let key_with_pwd =
        Key::try_from_envelope(&envelope_encrypt, Some(password)).unwrap();
    assert_eq!(key_with_pwd, key);
}

#[test]
fn test_private_key_envelope_no_private_key() {
    // Key with no private key
    let pubkeys = PrivateKeyBase::new().public_keys();
    let key = Key::new(&pubkeys);

    let result = key.private_key_envelope(None).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_private_key_envelope_unencrypted() {
    // Key with unencrypted private key
    let prvkey_base = PrivateKeyBase::new();
    let key = Key::new_with_private_key_base(prvkey_base.clone());

    let envelope = key.private_key_envelope(None).unwrap().unwrap();

    // Should be able to extract PrivateKeys from the envelope
    let private_keys = PrivateKeys::try_from(envelope.subject()).unwrap();
    assert_eq!(private_keys, prvkey_base.private_keys());
}

#[test]
fn test_private_key_envelope_encrypted_no_password() {
    let prvkey_base = PrivateKeyBase::new();
    let key = Key::new_with_private_key_base(prvkey_base.clone());
    let password = "test-password";

    // Encrypt the key
    let envelope_encrypted =
        key.into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.as_bytes().to_vec(),
        });

    let key_encrypted =
        Key::try_from_envelope(&envelope_encrypted, None).unwrap();

    // Get encrypted envelope without password
    let encrypted_envelope =
        key_encrypted.private_key_envelope(None).unwrap().unwrap();

    // Should be encrypted - check that it contains ENCRYPTED marker
    let formatted = encrypted_envelope.format();
    assert!(formatted.contains("ENCRYPTED"));
    assert!(formatted.contains("hasSecret"));
}

#[test]
fn test_private_key_envelope_encrypted_correct_password() {
    let prvkey_base = PrivateKeyBase::new();
    let key = Key::new_with_private_key_base(prvkey_base.clone());
    let password = "test-password";

    // Encrypt the key
    let envelope_encrypted =
        key.into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.as_bytes().to_vec(),
        });

    let key_encrypted =
        Key::try_from_envelope(&envelope_encrypted, None).unwrap();

    // Get decrypted envelope with correct password
    let decrypted_envelope = key_encrypted
        .private_key_envelope(Some(password))
        .unwrap()
        .unwrap();

    // Should be decrypted
    assert!(!decrypted_envelope.is_encrypted());
    let private_keys =
        PrivateKeys::try_from(decrypted_envelope.subject()).unwrap();
    assert_eq!(private_keys, prvkey_base.private_keys());
}

#[test]
fn test_private_key_envelope_encrypted_wrong_password() {
    let prvkey_base = PrivateKeyBase::new();
    let key = Key::new_with_private_key_base(prvkey_base.clone());
    let password = "test-password";

    // Encrypt the key
    let envelope_encrypted =
        key.into_envelope_opt(PrivateKeyOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.as_bytes().to_vec(),
        });

    let key_encrypted =
        Key::try_from_envelope(&envelope_encrypted, None).unwrap();

    // Try to decrypt with wrong password
    let result = key_encrypted.private_key_envelope(Some("wrong-password"));

    // Should return InvalidPassword error
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidPassword));
}
