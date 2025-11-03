mod common;

use bc_components::KeyDerivationMethod;
use bc_envelope::prelude::*;
use bc_xid::{Error, MarkGeneratorOptions, Provenance};
use dcbor::Date;
use indoc::indoc;
use provenance_mark::{ProvenanceMarkGenerator, ProvenanceMarkResolution};

#[test]
fn test_provenance() {
    bc_envelope::register_tags();
    provenance_mark::register_tags();

    let mut generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator.next(date, Some("Test mark"));

    let provenance = Provenance::new(mark.clone());
    assert_eq!(provenance.mark(), &mark);
    assert!(provenance.generator().is_none());

    let envelope = provenance.clone().into_envelope();
    let provenance2 = Provenance::try_from(&envelope).unwrap();
    assert_eq!(provenance, provenance2);

    assert_actual_expected!(envelope.format(), "ProvenanceMark(adbd6aa8)");
}

#[test]
fn test_with_generator() {
    bc_envelope::register_tags();
    provenance_mark::register_tags();

    let mut generator_for_mark = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator_for_mark.next(date, Some("Test mark"));

    // Create a fresh generator for storage (so seq is back to 0)
    let generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );

    //
    // A `Provenance` can be constructed with a generator.
    //

    let provenance_including_generator =
        Provenance::new_with_generator(generator.clone(), mark.clone());

    //
    // A `Provenance` without the generator
    //

    let provenance_omitting_generator = Provenance::new(mark.clone());

    //
    // When converting to an `Envelope`, the default is to omit the generator
    // because it is sensitive.
    //

    let envelope_omitting_generator =
        provenance_including_generator.clone().into_envelope();

    assert_actual_expected!(
        envelope_omitting_generator.format(),
        "ProvenanceMark(adbd6aa8)"
    );

    //
    // If the generator is omitted, the Provenance is reconstructed without it.
    //

    let provenance2 =
        Provenance::try_from(&envelope_omitting_generator).unwrap();
    assert_eq!(provenance_omitting_generator, provenance2);

    //
    // The generator can be included in the envelope by explicitly
    // specifying that it should be included.
    //
    // The 'provenanceGenerator' assertion is salted to decorrelate the generator.
    //

    let envelope_including_generator = provenance_including_generator
        .clone()
        .into_envelope_opt(MarkGeneratorOptions::Include);

    #[rustfmt::skip]
    assert_actual_expected!(envelope_including_generator.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': Bytes(32) [
                    'isA': "provenance-generator"
                    "next-seq": 0
                    "res": 3
                    "rng-state": Bytes(32)
                    "seed": Bytes(32)
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());

    //
    // If the generator is included, the Provenance is reconstructed with it and
    // is exactly the same as the original.
    //

    let provenance2 =
        Provenance::try_from(&envelope_including_generator).unwrap();
    assert_eq!(provenance_including_generator, provenance2);

    //
    // The generator assertion can be elided.
    //

    let envelope_eliding_generator = provenance_including_generator
        .clone()
        .into_envelope_opt(MarkGeneratorOptions::Elide);

    #[rustfmt::skip]
    assert_actual_expected!(envelope_eliding_generator.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            ELIDED
        ]
    "#}.trim());

    //
    // If the generator is elided, the Provenance is reconstructed without it.
    //

    let provenance2 =
        Provenance::try_from(&envelope_eliding_generator).unwrap();
    assert_eq!(provenance_omitting_generator, provenance2);

    //
    // The elided envelope has the same root hash as the envelope including
    // the generator, affording inclusion proofs.
    //

    assert!(
        envelope_eliding_generator
            .is_equivalent_to(&envelope_including_generator)
    );
}

#[test]
fn test_provenance_with_encrypted_generator() {
    bc_envelope::register_tags();
    provenance_mark::register_tags();

    let mut generator_for_mark = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator_for_mark.next(date, Some("Test mark"));

    // Create a fresh generator for storage (so seq is back to 0)
    let generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let password = b"correct_horse_battery_staple";

    let provenance =
        Provenance::new_with_generator(generator.clone(), mark.clone());

    //
    // Encrypt the generator with Argon2id.
    //
    let envelope_encrypted =
        provenance
            .clone()
            .into_envelope_opt(MarkGeneratorOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            });

    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypted.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': ENCRYPTED [
                    'hasSecret': EncryptedKey(Argon2id)
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());

    //
    // Extract without password - should succeed but generator is None.
    //
    let provenance_no_password =
        Provenance::try_from_envelope(&envelope_encrypted, None).unwrap();
    assert!(provenance_no_password.generator().is_none());
    assert_eq!(provenance_no_password.mark(), &mark);

    //
    // Extract with wrong password - should succeed but generator is None.
    //
    let wrong_password = b"wrong_password";
    let provenance_wrong_password = Provenance::try_from_envelope(
        &envelope_encrypted,
        Some(wrong_password),
    )
    .unwrap();
    assert!(provenance_wrong_password.generator().is_none());

    //
    // Extract with correct password - should succeed with generator.
    //
    let provenance_decrypted =
        Provenance::try_from_envelope(&envelope_encrypted, Some(password))
            .unwrap();
    assert_eq!(provenance_decrypted.generator(), Some(&generator));
    assert_eq!(provenance_decrypted, provenance);
}

#[test]
fn test_provenance_encrypted_with_different_methods() {
    bc_envelope::register_tags();
    provenance_mark::register_tags();

    let mut generator_for_mark = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator_for_mark.next(date, Some("Test mark"));

    // Create a fresh generator for storage (so seq is back to 0)
    let generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let password = b"test_password_123";

    let provenance =
        Provenance::new_with_generator(generator.clone(), mark.clone());

    //
    // Test encryption with Argon2id (recommended).
    //
    let envelope_argon2id =
        provenance
            .clone()
            .into_envelope_opt(MarkGeneratorOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_argon2id.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': ENCRYPTED [
                    'hasSecret': EncryptedKey(Argon2id)
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());
    let provenance_argon2id =
        Provenance::try_from_envelope(&envelope_argon2id, Some(password))
            .unwrap();
    assert_eq!(provenance_argon2id, provenance);

    //
    // Test encryption with PBKDF2.
    //
    let envelope_pbkdf2 =
        provenance
            .clone()
            .into_envelope_opt(MarkGeneratorOptions::Encrypt {
                method: KeyDerivationMethod::PBKDF2,
                password: password.to_vec(),
            });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_pbkdf2.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': ENCRYPTED [
                    'hasSecret': EncryptedKey(PBKDF2(SHA256))
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());
    let provenance_pbkdf2 =
        Provenance::try_from_envelope(&envelope_pbkdf2, Some(password))
            .unwrap();
    assert_eq!(provenance_pbkdf2, provenance);

    //
    // Test encryption with Scrypt.
    //
    let envelope_scrypt =
        provenance
            .clone()
            .into_envelope_opt(MarkGeneratorOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_scrypt.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': ENCRYPTED [
                    'hasSecret': EncryptedKey(Scrypt)
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());
    let provenance_scrypt =
        Provenance::try_from_envelope(&envelope_scrypt, Some(password))
            .unwrap();
    assert_eq!(provenance_scrypt, provenance);

    //
    // Each encryption produces a different envelope (different salts/nonces).
    //
    assert_ne!(envelope_argon2id.ur_string(), envelope_pbkdf2.ur_string());
    assert_ne!(envelope_pbkdf2.ur_string(), envelope_scrypt.ur_string());
    assert_ne!(envelope_argon2id.ur_string(), envelope_scrypt.ur_string());
}

#[test]
fn test_provenance_generator_storage_modes() {
    bc_envelope::register_tags();
    provenance_mark::register_tags();

    let mut generator_for_mark = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator_for_mark.next(date, Some("Test mark"));

    // Create a fresh generator for storage (so seq is back to 0)
    let generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );

    let provenance =
        Provenance::new_with_generator(generator.clone(), mark.clone());

    //
    // Mode 1: Omit generator (default, most secure for sharing).
    //
    let envelope_omit = provenance.clone().into_envelope();
    let formatted = envelope_omit.format();
    assert!(formatted.starts_with("ProvenanceMark"));
    assert!(!formatted.contains("provenanceGenerator"));

    let provenance_omit = Provenance::try_from(&envelope_omit).unwrap();
    assert!(provenance_omit.generator().is_none());

    //
    // Mode 2: Include generator in plaintext.
    //
    let envelope_include = provenance
        .clone()
        .into_envelope_opt(MarkGeneratorOptions::Include);
    #[rustfmt::skip]
    assert_actual_expected!(envelope_include.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': Bytes(32) [
                    'isA': "provenance-generator"
                    "next-seq": 0
                    "res": 3
                    "rng-state": Bytes(32)
                    "seed": Bytes(32)
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());

    let provenance_include = Provenance::try_from(&envelope_include).unwrap();
    assert_eq!(provenance_include, provenance);

    //
    // Mode 3: Elide generator (maintains digest for proofs).
    //
    let envelope_elide = provenance
        .clone()
        .into_envelope_opt(MarkGeneratorOptions::Elide);
    #[rustfmt::skip]
    assert_actual_expected!(envelope_elide.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            ELIDED
        ]
    "#}.trim());

    let provenance_elide = Provenance::try_from(&envelope_elide).unwrap();
    assert!(provenance_elide.generator().is_none());
    assert!(envelope_elide.is_equivalent_to(&envelope_include));

    //
    // Mode 4: Encrypt generator with password.
    //
    let password = b"secure_password";
    let envelope_encrypt =
        provenance
            .clone()
            .into_envelope_opt(MarkGeneratorOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            });
    #[rustfmt::skip]
    assert_actual_expected!(envelope_encrypt.format(), indoc! {r#"
        ProvenanceMark(adbd6aa8) [
            {
                'provenanceGenerator': ENCRYPTED [
                    'hasSecret': EncryptedKey(Argon2id)
                ]
            } [
                'salt': Salt
            ]
        ]
    "#}.trim());

    // Without password
    let provenance_no_pwd =
        Provenance::try_from_envelope(&envelope_encrypt, None).unwrap();
    assert!(provenance_no_pwd.generator().is_none());

    // With password
    let provenance_with_pwd =
        Provenance::try_from_envelope(&envelope_encrypt, Some(password))
            .unwrap();
    assert_eq!(provenance_with_pwd, provenance);
}

#[test]
fn test_generator_envelope_no_generator() {
    // Provenance with no generator
    let mut generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator.next(date, Some("Test mark"));
    let provenance = Provenance::new(mark.clone());

    let result = provenance.generator_envelope(None).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_generator_envelope_unencrypted() {
    // Provenance with unencrypted generator
    let mut generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator.next(date, Some("Test mark"));
    let provenance = Provenance::new_with_generator(generator.clone(), mark);

    let envelope = provenance.generator_envelope(None).unwrap().unwrap();

    // Should be able to extract ProvenanceMarkGenerator from the envelope
    let extracted_generator =
        ProvenanceMarkGenerator::try_from(envelope).unwrap();
    assert_eq!(extracted_generator, generator);
}

#[test]
fn test_generator_envelope_encrypted_no_password() {
    let mut generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator.next(date, Some("Test mark"));
    let provenance = Provenance::new_with_generator(generator.clone(), mark);
    let password = "test-password";

    // Encrypt the provenance
    let envelope_encrypted =
        provenance.into_envelope_opt(MarkGeneratorOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.as_bytes().to_vec(),
        });

    let provenance_encrypted =
        Provenance::try_from_envelope(&envelope_encrypted, None).unwrap();

    // Get encrypted envelope without password
    let encrypted_envelope = provenance_encrypted
        .generator_envelope(None)
        .unwrap()
        .unwrap();

    // Should be encrypted - check that it contains ENCRYPTED marker
    assert_actual_expected!(
        encrypted_envelope.format(),
        indoc! {r#"
        ENCRYPTED [
            'hasSecret': EncryptedKey(Argon2id)
        ]
    "#}
        .trim()
    );
}

#[test]
fn test_generator_envelope_encrypted_correct_password() {
    let mut generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator.next(date, Some("Test mark"));
    let provenance = Provenance::new_with_generator(generator.clone(), mark);
    let password = "test-password";

    // Encrypt the provenance
    let envelope_encrypted =
        provenance.into_envelope_opt(MarkGeneratorOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.as_bytes().to_vec(),
        });

    let provenance_encrypted =
        Provenance::try_from_envelope(&envelope_encrypted, None).unwrap();

    // Get decrypted envelope with correct password
    let decrypted_envelope = provenance_encrypted
        .generator_envelope(Some(password))
        .unwrap()
        .unwrap();

    // Should be decrypted
    assert!(!decrypted_envelope.is_encrypted());
    let extracted_generator =
        ProvenanceMarkGenerator::try_from(decrypted_envelope).unwrap();
    assert_eq!(extracted_generator, generator);
}

#[test]
fn test_generator_envelope_encrypted_wrong_password() {
    let mut generator = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::High,
        "test_passphrase",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let mark = generator.next(date, Some("Test mark"));
    let provenance = Provenance::new_with_generator(generator.clone(), mark);
    let password = "test-password";

    // Encrypt the provenance
    let envelope_encrypted =
        provenance.into_envelope_opt(MarkGeneratorOptions::Encrypt {
            method: KeyDerivationMethod::Argon2id,
            password: password.as_bytes().to_vec(),
        });

    let provenance_encrypted =
        Provenance::try_from_envelope(&envelope_encrypted, None).unwrap();

    // Try to decrypt with wrong password
    let result =
        provenance_encrypted.generator_envelope(Some("wrong-password"));

    // Should return InvalidPassword error
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidPassword));
}
