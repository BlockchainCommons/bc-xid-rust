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
    fn public_keys(&self) -> PublicKeys { self.public_keys.clone() }
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

    pub fn public_keys(&self) -> &PublicKeys { &self.public_keys }

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
    /// use bc_components::PrivateKeyBase;
    /// use bc_envelope::prelude::*;
    /// use bc_xid::Key;
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

    pub fn endpoints(&self) -> &HashSet<URI> { &self.endpoints }

    pub fn endpoints_mut(&mut self) -> &mut HashSet<URI> { &mut self.endpoints }

    pub fn add_endpoint(&mut self, endpoint: URI) {
        self.endpoints.insert(endpoint);
    }

    pub fn permissions(&self) -> &Permissions { &self.permissions }

    pub fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }

    pub fn add_permission(&mut self, privilege: Privilege) {
        self.permissions.add_allow(privilege);
    }
}

impl HasNickname for Key {
    fn nickname(&self) -> &str { &self.nickname }

    fn set_nickname(&mut self, nickname: impl Into<String>) {
        self.nickname = nickname.into();
    }
}

impl HasPermissions for Key {
    fn permissions(&self) -> &Permissions { &self.permissions }

    fn permissions_mut(&mut self) -> &mut Permissions { &mut self.permissions }
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
                // Already encrypted, just wrap with privateKey predicate and
                // salt
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
                                    // Create an envelope with just the private
                                    // keys
                                    let private_keys_envelope =
                                        Envelope::new(keys);

                                    // Encrypt it using lock_subject
                                    let encrypted = private_keys_envelope
                                        .lock_subject(method, password)
                                        .expect(
                                            "Failed to encrypt private key",
                                        );

                                    // Create the privateKey assertion with the
                                    // encrypted envelope
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
                                    // Already encrypted - we can't re-encrypt
                                    // without
                                    // decrypting first. Just preserve the
                                    // existing
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

    fn try_from(envelope: Envelope) -> Result<Self> { Key::try_from(&envelope) }
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
    fn reference(&self) -> Reference { self.public_keys.reference() }
}
