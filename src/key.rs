use std::collections::HashSet;

use bc_components::{
    EncapsulationPublicKey, KeyDerivationMethod, PrivateKeys,
    PrivateKeysProvider, PublicKeys, PublicKeysProvider, Reference,
    ReferenceProvider, Salt, SigningPublicKey, URI, Verifier,
};
use bc_envelope::{PrivateKeyBase, prelude::*};
use known_values::{ENDPOINT, NICKNAME, PRIVATE_KEY};

use super::Permissions;
use crate::{Error, HasNickname, HasPermissions, Privilege, Result};

/// Private key data that can be either decrypted or encrypted.
#[derive(Debug, Clone)]
pub enum PrivateKeyData {
    /// Decrypted private keys that can be used for signing/decryption.
    Decrypted(PrivateKeys),

    /// Encrypted private key envelope that cannot be used without decryption.
    /// This preserves the encrypted assertion when a document is loaded
    /// without the decryption password.
    ///
    /// Note: Envelope uses internal reference counting (Rc/Arc) so cloning
    /// is cheap - no need for additional wrapper.
    Encrypted(Envelope),
}
impl PartialEq for PrivateKeyData {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Decrypted(a), Self::Decrypted(b)) => a == b,
            (Self::Encrypted(a), Self::Encrypted(b)) => {
                // Compare envelopes by their UR string representation
                a.ur_string() == b.ur_string()
            }
            _ => false,
        }
    }
}

impl Eq for PrivateKeyData {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    public_keys: PublicKeys,
    private_keys: Option<(PrivateKeyData, Salt)>,
    nickname: String,
    endpoints: HashSet<URI>,
    permissions: Permissions,
}
impl Verifier for Key {
    fn verify(
        &self,
        signature: &bc_components::Signature,
        message: &dyn AsRef<[u8]>,
    ) -> bool {
        self.public_keys.verify(signature, message)
    }
}

impl PublicKeysProvider for Key {
    fn public_keys(&self) -> PublicKeys {
        self.public_keys.clone()
    }
}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_keys.hash(state);
    }
}

impl Key {
    pub fn new(public_keys: impl AsRef<PublicKeys>) -> Self {
        Self {
            public_keys: public_keys.as_ref().clone(),
            private_keys: None,
            nickname: String::new(),
            endpoints: HashSet::new(),
            permissions: Permissions::new(),
        }
    }

    pub fn new_allow_all(public_keys: impl AsRef<PublicKeys>) -> Self {
        Self {
            public_keys: public_keys.as_ref().clone(),
            private_keys: None,
            nickname: String::new(),
            endpoints: HashSet::new(),
            permissions: Permissions::new_allow_all(),
        }
    }

    pub fn new_with_private_keys(
        private_keys: PrivateKeys,
        public_keys: PublicKeys,
    ) -> Self {
        let salt = Salt::new_with_len(32).unwrap();
        Self {
            public_keys,
            private_keys: Some((PrivateKeyData::Decrypted(private_keys), salt)),
            nickname: String::new(),
            endpoints: HashSet::new(),
            permissions: Permissions::new_allow_all(),
        }
    }

    pub fn new_with_private_key_base(private_key_base: PrivateKeyBase) -> Self {
        let private_keys = private_key_base.private_keys();
        let public_keys = private_key_base.public_keys();
        Self::new_with_private_keys(private_keys, public_keys)
    }

    pub fn public_keys(&self) -> &PublicKeys {
        &self.public_keys
    }

    pub fn private_keys(&self) -> Option<&PrivateKeys> {
        self.private_keys.as_ref().and_then(|(data, _)| match data {
            PrivateKeyData::Decrypted(keys) => Some(keys),
            PrivateKeyData::Encrypted(_) => None,
        })
    }

    pub fn has_private_keys(&self) -> bool {
        matches!(
            self.private_keys.as_ref(),
            Some((PrivateKeyData::Decrypted(_), _))
        )
    }

    pub fn has_encrypted_private_keys(&self) -> bool {
        matches!(
            self.private_keys.as_ref(),
            Some((PrivateKeyData::Encrypted(_), _))
        )
    }

    pub fn private_key_salt(&self) -> Option<&Salt> {
        self.private_keys.as_ref().map(|(_, salt)| salt)
    }

    /// Extract the private key data as an Envelope, optionally decrypting it.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if no private key is present
    /// - `Ok(Some(Envelope))` containing:
    ///   - Decrypted `PrivateKeys` if unencrypted
    ///   - Decrypted `PrivateKeys` if encrypted and correct password provided
    ///   - Encrypted envelope if encrypted and no password provided
    /// - `Err(...)` if encrypted and wrong password provided
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_xid::Key;
    /// use bc_envelope::prelude::*;
    /// use bc_components::PrivateKeyBase;
    ///
    /// // Unencrypted key
    /// let prvkey_base = PrivateKeyBase::new();
    /// let key = Key::new_with_private_key_base(prvkey_base.clone());
    /// let envelope = key.private_key_envelope(None).unwrap().unwrap();
    /// // Returns envelope containing PrivateKeys
    ///
    /// // Encrypted key without password
    /// // Returns the encrypted envelope as-is
    ///
    /// // Encrypted key with correct password
    /// // Returns envelope containing decrypted PrivateKeys
    /// ```
    pub fn private_key_envelope(
        &self,
        password: Option<&str>,
    ) -> Result<Option<Envelope>> {
        match &self.private_keys {
            None => Ok(None),
            Some((PrivateKeyData::Decrypted(private_keys), _)) => {
                // Unencrypted key - return as envelope
                Ok(Some(Envelope::new(private_keys.clone())))
            }
            Some((PrivateKeyData::Encrypted(encrypted_envelope), _)) => {
                if let Some(pwd) = password {
                    // Try to decrypt with provided password
                    match encrypted_envelope.clone().unlock_subject(pwd) {
                        Ok(decrypted) => {
                            // Successfully decrypted
                            Ok(Some(decrypted))
                        }
                        Err(_) => {
                            // Wrong password
                            Err(Error::InvalidPassword)
                        }
                    }
                } else {
                    // No password provided, return encrypted envelope as-is
                    Ok(Some(encrypted_envelope.clone()))
                }
            }
        }
    }

    pub fn signing_public_key(&self) -> &SigningPublicKey {
        self.public_keys.signing_public_key()
    }

    pub fn encapsulation_public_key(&self) -> &EncapsulationPublicKey {
        self.public_keys.enapsulation_public_key()
    }

    pub fn endpoints(&self) -> &HashSet<URI> {
        &self.endpoints
    }

    pub fn endpoints_mut(&mut self) -> &mut HashSet<URI> {
        &mut self.endpoints
    }

    pub fn add_endpoint(&mut self, endpoint: URI) {
        self.endpoints.insert(endpoint);
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }

    pub fn add_permission(&mut self, privilege: Privilege) {
        self.permissions.add_allow(privilege);
    }
}

impl HasNickname for Key {
    fn nickname(&self) -> &str {
        &self.nickname
    }

    fn set_nickname(&mut self, nickname: impl Into<String>) {
        self.nickname = nickname.into();
    }
}

impl HasPermissions for Key {
    fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }
}

/// Options for handling private keys in envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum PrivateKeyOptions {
    /// Omit the private key from the envelope (default).
    #[default]
    Omit,

    /// Include the private key in plaintext (with salt for decorrelation).
    Include,

    /// Include the private key assertion but elide it (maintains digest tree).
    Elide,

    /// Include the private key encrypted with a password using the specified
    /// key derivation method.
    Encrypt {
        method: KeyDerivationMethod,
        password: Vec<u8>,
    },
}

impl Key {
    fn private_key_assertion_envelope(&self) -> Envelope {
        let (private_key_data, salt) = self.private_keys.clone().unwrap();
        match private_key_data {
            PrivateKeyData::Decrypted(private_keys) => {
                Envelope::new_assertion(PRIVATE_KEY, private_keys)
                    .add_salt_instance(salt)
            }
            PrivateKeyData::Encrypted(encrypted_envelope) => {
                // Already encrypted, just wrap with privateKey predicate and salt
                Envelope::new_assertion(PRIVATE_KEY, encrypted_envelope)
                    .add_salt_instance(salt)
            }
        }
    }

    fn extract_optional_private_key_with_password(
        envelope: &Envelope,
        password: Option<&[u8]>,
    ) -> Result<Option<(PrivateKeyData, Salt)>> {
        if let Some(private_key_assertion) =
            envelope.optional_assertion_with_predicate(PRIVATE_KEY)?
        {
            let private_key_object =
                private_key_assertion.subject().try_object()?;

            // Extract the salt (always present)
            let salt = private_key_assertion
                .extract_object_for_predicate::<Salt>(known_values::SALT)?;

            // Check if the private key object is locked with a password
            if private_key_object.is_locked_with_password() {
                // Need a password to decrypt
                if let Some(pwd) = password {
                    // Try to unlock with the password
                    match private_key_object.unlock_subject(pwd) {
                        Ok(decrypted) => {
                            // Successfully decrypted, extract the private key
                            let private_keys_cbor =
                                decrypted.subject().try_leaf()?;
                            let private_keys =
                                PrivateKeys::try_from(private_keys_cbor)?;
                            return Ok(Some((
                                PrivateKeyData::Decrypted(private_keys),
                                salt,
                            )));
                        }
                        Err(_) => {
                            // Wrong password or decryption failed
                            // Store the encrypted envelope for later
                            return Ok(Some((
                                PrivateKeyData::Encrypted(
                                    private_key_object.clone(),
                                ),
                                salt,
                            )));
                        }
                    }
                } else {
                    // No password provided, store encrypted envelope
                    return Ok(Some((
                        PrivateKeyData::Encrypted(private_key_object.clone()),
                        salt,
                    )));
                }
            }

            // Extract plaintext private key
            let private_keys_cbor = private_key_object.try_leaf()?;
            let private_keys = PrivateKeys::try_from(private_keys_cbor)?;
            return Ok(Some((PrivateKeyData::Decrypted(private_keys), salt)));
        }
        Ok(None)
    }

    pub fn into_envelope_opt(
        self,
        private_key_options: PrivateKeyOptions,
    ) -> Envelope {
        let mut envelope = Envelope::new(self.public_keys().clone());
        if let Some((private_key_data, _)) = &self.private_keys {
            match private_key_data {
                PrivateKeyData::Encrypted(_) => {
                    // Always preserve encrypted keys, regardless of options
                    let assertion_envelope =
                        self.private_key_assertion_envelope();
                    envelope = envelope
                        .add_assertion_envelope(assertion_envelope)
                        .unwrap();
                }
                PrivateKeyData::Decrypted(_) => {
                    // For decrypted keys, respect the private_key_options
                    match private_key_options {
                        PrivateKeyOptions::Include => {
                            let assertion_envelope =
                                self.private_key_assertion_envelope();
                            envelope = envelope
                                .add_assertion_envelope(assertion_envelope)
                                .unwrap();
                        }
                        PrivateKeyOptions::Elide => {
                            let assertion_envelope =
                                self.private_key_assertion_envelope().elide();
                            envelope = envelope
                                .add_assertion_envelope(assertion_envelope)
                                .unwrap();
                        }
                        PrivateKeyOptions::Encrypt { method, password } => {
                            let (private_keys, salt) =
                                self.private_keys.clone().unwrap();

                            match private_keys {
                                PrivateKeyData::Decrypted(keys) => {
                                    // Create an envelope with just the private keys
                                    let private_keys_envelope =
                                        Envelope::new(keys);

                                    // Encrypt it using lock_subject
                                    let encrypted = private_keys_envelope
                                        .lock_subject(method, password)
                                        .expect(
                                            "Failed to encrypt private key",
                                        );

                                    // Create the privateKey assertion with the encrypted envelope
                                    let assertion_envelope =
                                        Envelope::new_assertion(
                                            PRIVATE_KEY,
                                            encrypted,
                                        )
                                        .add_salt_instance(salt);

                                    envelope = envelope
                                        .add_assertion_envelope(
                                            assertion_envelope,
                                        )
                                        .unwrap();
                                }
                                PrivateKeyData::Encrypted(
                                    encrypted_envelope,
                                ) => {
                                    // Already encrypted - we can't re-encrypt without
                                    // decrypting first. Just preserve the existing
                                    // encrypted envelope.
                                    let assertion_envelope =
                                        Envelope::new_assertion(
                                            PRIVATE_KEY,
                                            encrypted_envelope,
                                        )
                                        .add_salt_instance(salt);

                                    envelope = envelope
                                        .add_assertion_envelope(
                                            assertion_envelope,
                                        )
                                        .unwrap();
                                }
                            }
                        }
                        PrivateKeyOptions::Omit => {
                            // Omit decrypted private keys
                        }
                    }
                }
            }
        }

        envelope = envelope.add_nonempty_string_assertion(
            known_values::NICKNAME,
            self.nickname,
        );

        envelope = self
            .endpoints
            .into_iter()
            .fold(envelope, |envelope, endpoint| {
                envelope.add_assertion(ENDPOINT, endpoint)
            });

        self.permissions.add_to_envelope(envelope)
    }
}

impl EnvelopeEncodable for Key {
    fn into_envelope(self) -> Envelope {
        self.into_envelope_opt(PrivateKeyOptions::Omit)
    }
}

impl TryFrom<&Envelope> for Key {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        Self::try_from_envelope(envelope, None)
    }
}

impl TryFrom<Envelope> for Key {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        Key::try_from(&envelope)
    }
}

impl Key {
    /// Try to extract a `Key` from an envelope, optionally providing a
    /// password to decrypt an encrypted private key.
    ///
    /// If the private key is encrypted and no password is provided, the `Key`
    /// will be created without the private key (it will be `None`).
    pub fn try_from_envelope(
        envelope: &Envelope,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let public_keys = PublicKeys::try_from(envelope.subject().try_leaf()?)?;
        let private_keys = Key::extract_optional_private_key_with_password(
            envelope, password,
        )?;

        let nickname = envelope.extract_object_for_predicate_with_default(
            NICKNAME,
            String::new(),
        )?;

        let mut endpoints = HashSet::new();
        for assertion in envelope.assertions_with_predicate(ENDPOINT) {
            let endpoint =
                URI::try_from(assertion.try_object()?.subject().try_leaf()?)?;
            endpoints.insert(endpoint);
        }
        let permissions = Permissions::try_from_envelope(envelope)?;
        Ok(Self {
            public_keys,
            private_keys,
            nickname,
            endpoints,
            permissions,
        })
    }
}

impl ReferenceProvider for &Key {
    fn reference(&self) -> Reference {
        self.public_keys.reference()
    }
}

#[cfg(test)]
mod tests {
    use bc_components::{PrivateKeysProvider, PublicKeysProvider};
    use bc_envelope::PrivateKeyBase;
    use bc_rand::make_fake_random_number_generator;
    use indoc::indoc;

    use super::*;
    use crate::Privilege;

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
        assert_eq!(envelope.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_omitting_private_key.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_including_private_key.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
                {
                    'privateKey': PrivateKeys(fb7c8739)
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
        assert_eq!(envelope_eliding_private_key.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_encrypted.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_argon2id.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_pbkdf2.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_scrypt.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_omit.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_include.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
                {
                    'privateKey': PrivateKeys(fb7c8739)
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
        assert_eq!(envelope_elide.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
        assert_eq!(envelope_encrypt.format(), indoc! {r#"
            PublicKeys(eb9b1cae) [
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
}
