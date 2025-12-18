use std::collections::HashSet;

use bc_components::{
    EncapsulationPublicKey, PrivateKeyBase, PrivateKeys, PrivateKeysProvider,
    PublicKeys, PublicKeysProvider, Reference, ReferenceProvider, Signer,
    SigningPrivateKey, SigningPublicKey, URI, XID, XIDProvider, tags::TAG_XID,
};
use bc_envelope::prelude::*;
use dcbor::prelude::CBORError;
use known_values::{
    ATTACHMENT_RAW, DELEGATE, DELEGATE_RAW, DEREFERENCE_VIA,
    DEREFERENCE_VIA_RAW, KEY, KEY_RAW, PROVENANCE, PROVENANCE_RAW, SERVICE,
    SERVICE_RAW,
};
use provenance_mark::{
    ProvenanceMark, ProvenanceMarkGenerator, ProvenanceMarkResolution,
    ProvenanceSeed,
};

use super::{Delegate, Key};
use crate::{
    Error, HasNickname, HasPermissions, Provenance, Result, Service,
    XIDGeneratorOptions, XIDPrivateKeyOptions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XIDDocument {
    xid: XID,
    resolution_methods: HashSet<URI>,
    keys: HashSet<Key>,
    delegates: HashSet<Delegate>,
    services: HashSet<Service>,
    provenance: Option<Provenance>,
    attachments: Attachments,
}

#[derive(Default)]
pub enum XIDInceptionKeyOptions {
    #[default]
    Default,
    PublicKeys(PublicKeys),
    PublicAndPrivateKeys(PublicKeys, PrivateKeys),
    PrivateKeyBase(PrivateKeyBase),
}

#[derive(Default)]
pub enum XIDGenesisMarkOptions {
    #[default]
    None,
    Passphrase(
        String,
        Option<ProvenanceMarkResolution>,
        Option<Date>,
        Option<CBOR>,
    ),
    Seed(
        ProvenanceSeed,
        Option<ProvenanceMarkResolution>,
        Option<Date>,
        Option<CBOR>,
    ),
}

/// Options for signing an envelope.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum XIDSigningOptions {
    /// Do not sign the envelope (default).
    #[default]
    None,

    /// Sign with the XID's inception key (must be available as a signing key).
    Inception,

    /// Sign with a provided `PrivateKeys`.
    PrivateKeys(PrivateKeys),

    /// Sign with a provided `SigningPrivateKey`.
    SigningPrivateKey(SigningPrivateKey),
}

/// Options for verifying the signature on an envelope when loading an
/// XIDDocument.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum XIDVerifySignature {
    /// Do not verify the signature (default).
    #[default]
    None,

    /// Verify that the envelope is signed with the inception key.
    Inception,
}

impl XIDDocument {
    pub fn new(
        key_options: XIDInceptionKeyOptions,
        mark_options: XIDGenesisMarkOptions,
    ) -> Self {
        let inception_key = Self::inception_key_for_options(key_options);
        let provenance = Self::genesis_mark_with_options(mark_options).map(
            |(generator, mark)| Provenance::new_with_generator(generator, mark),
        );

        let mut xid_doc = Self {
            xid: XID::new(inception_key.public_keys().signing_public_key()),
            resolution_methods: HashSet::new(),
            keys: HashSet::new(),
            delegates: HashSet::new(),
            services: HashSet::new(),
            provenance,
            attachments: Attachments::new(),
        };

        xid_doc.add_key(inception_key).unwrap();

        xid_doc
    }

    fn inception_key_for_options(options: XIDInceptionKeyOptions) -> Key {
        match options {
            XIDInceptionKeyOptions::Default => {
                // Default: generate a new key pair and include private key
                let private_key_base = PrivateKeyBase::new();
                let public_keys = private_key_base.public_keys();
                let private_keys = private_key_base.private_keys();
                Key::new_with_private_keys(private_keys, public_keys)
            }
            XIDInceptionKeyOptions::PublicKeys(public_keys) => {
                // Public key only, no private key
                Key::new_allow_all(&public_keys)
            }
            XIDInceptionKeyOptions::PublicAndPrivateKeys(
                public_keys,
                private_keys,
            ) => {
                // Both public and private keys
                Key::new_with_private_keys(private_keys, public_keys)
            }
            XIDInceptionKeyOptions::PrivateKeyBase(private_key_base) => {
                // Derive both keys from private key base
                let public_keys = private_key_base.public_keys();
                let private_keys = private_key_base.private_keys();
                Key::new_with_private_keys(private_keys, public_keys)
            }
        }
    }

    fn genesis_mark_with_options(
        options: XIDGenesisMarkOptions,
    ) -> Option<(ProvenanceMarkGenerator, ProvenanceMark)> {
        use ProvenanceMarkGenerator;
        match options {
            XIDGenesisMarkOptions::None => None,
            XIDGenesisMarkOptions::Passphrase(passphrase, res, date, info) => {
                let mut generator =
                    ProvenanceMarkGenerator::new_with_passphrase(
                        res.unwrap_or(ProvenanceMarkResolution::High),
                        &passphrase,
                    );
                let date = date.unwrap_or_else(dcbor::Date::now);
                let mark = generator.next(date, info);
                Some((generator, mark))
            }
            XIDGenesisMarkOptions::Seed(seed, res, date, info) => {
                let mut generator = ProvenanceMarkGenerator::new_with_seed(
                    res.unwrap_or(ProvenanceMarkResolution::High),
                    seed,
                );
                let date = date.unwrap_or_else(dcbor::Date::now);
                let mark = generator.next(date, info);
                Some((generator, mark))
            }
        }
    }

    pub fn from_xid(xid: impl Into<XID>) -> Self {
        Self {
            xid: xid.into(),
            resolution_methods: HashSet::new(),
            keys: HashSet::new(),
            delegates: HashSet::new(),
            services: HashSet::new(),
            provenance: None,
            attachments: Attachments::new(),
        }
    }

    pub fn resolution_methods(&self) -> &HashSet<URI> {
        &self.resolution_methods
    }

    pub fn resolution_methods_mut(&mut self) -> &mut HashSet<URI> {
        &mut self.resolution_methods
    }

    pub fn add_resolution_method(&mut self, method: URI) {
        self.resolution_methods.insert(method);
    }

    pub fn remove_resolution_method(
        &mut self,
        method: impl AsRef<URI>,
    ) -> Option<URI> {
        self.resolution_methods.take(method.as_ref())
    }

    pub fn keys(&self) -> &HashSet<Key> { &self.keys }

    pub fn keys_mut(&mut self) -> &mut HashSet<Key> { &mut self.keys }

    pub fn add_key(&mut self, key: Key) -> Result<()> {
        if self.find_key_by_public_keys(key.public_keys()).is_some() {
            return Err(Error::Duplicate { item: "key".to_string() });
        }
        self.keys.insert(key);
        Ok(())
    }

    pub fn find_key_by_public_keys(
        &self,
        key: &dyn PublicKeysProvider,
    ) -> Option<&Key> {
        let key = key.public_keys();
        self.keys.iter().find(|k| k.public_keys() == &key)
    }

    pub fn find_key_by_reference(&self, reference: &Reference) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| k.public_keys().reference() == *reference)
    }

    /// Get the private key envelope for a specific key, optionally decrypting
    /// it.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - The public keys identifying the key to retrieve
    /// * `password` - Optional password for decryption
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if the key is not found or has no private key
    /// - `Ok(Some(Envelope))` containing:
    ///   - Decrypted `PrivateKeys` if unencrypted
    ///   - Decrypted `PrivateKeys` if encrypted and correct password provided
    ///   - Encrypted envelope if encrypted and no password provided
    /// - `Err(Error::InvalidPassword)` if encrypted and wrong password provided
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_components::{PrivateKeyBase, PublicKeysProvider};
    /// use bc_envelope::prelude::*;
    /// use bc_xid::{XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
    ///
    /// let prvkey_base = PrivateKeyBase::new();
    /// let doc = XIDDocument::new(
    ///     XIDInceptionKeyOptions::PrivateKeyBase(prvkey_base.clone()),
    ///     XIDGenesisMarkOptions::None,
    /// );
    ///
    /// // Get unencrypted private key
    /// let key = doc.keys().iter().next().unwrap();
    /// let envelope = doc
    ///     .private_key_envelope_for_key(key.public_keys(), None)
    ///     .unwrap()
    ///     .unwrap();
    /// ```
    pub fn private_key_envelope_for_key(
        &self,
        public_keys: &PublicKeys,
        password: Option<&str>,
    ) -> Result<Option<Envelope>> {
        match self.find_key_by_public_keys(public_keys) {
            None => Ok(None),
            Some(key) => key.private_key_envelope(password),
        }
    }

    pub fn take_key(&mut self, key: &dyn PublicKeysProvider) -> Option<Key> {
        if let Some(key) = self.find_key_by_public_keys(key).cloned() {
            self.keys.take(&key)
        } else {
            None
        }
    }

    pub fn remove_key(&mut self, key: &dyn PublicKeysProvider) -> Result<()> {
        if self.services_reference_key(key) {
            return Err(Error::StillReferenced { item: "key".to_string() });
        }
        if self.take_key(key).is_none() {
            return Err(Error::NotFound { item: "key".to_string() });
        }
        Ok(())
    }

    pub fn set_name_for_key(
        &mut self,
        key: &dyn PublicKeysProvider,
        name: impl Into<String>,
    ) -> Result<()> {
        let mut key = self
            .take_key(key)
            .ok_or_else(|| Error::NotFound { item: "key".to_string() })?;
        key.set_nickname(name);
        self.add_key(key)
    }

    pub fn is_inception_signing_key(
        &self,
        signing_public_key: &SigningPublicKey,
    ) -> bool {
        self.xid.validate(signing_public_key)
    }

    pub fn inception_signing_key(&self) -> Option<&SigningPublicKey> {
        if let Some(key) = self.keys.iter().find(|k| {
            self.is_inception_signing_key(k.public_keys().signing_public_key())
        }) {
            Some(key.public_keys().signing_public_key())
        } else {
            None
        }
    }

    pub fn inception_key(&self) -> Option<&Key> {
        self.keys.iter().find(|k| {
            self.is_inception_signing_key(k.public_keys().signing_public_key())
        })
    }

    pub fn remove_inception_key(&mut self) -> Option<Key> {
        if let Some(key) = self.inception_key().cloned() {
            self.keys.take(&key)
        } else {
            None
        }
    }

    pub fn verification_key(&self) -> Option<&SigningPublicKey> {
        // Prefer the inception key for verification.
        if let Some(key) = self.inception_key() {
            Some(key.public_keys().signing_public_key())
        } else if let Some(key) = self.keys.iter().next() {
            Some(key.public_keys().signing_public_key())
        } else {
            None
        }
    }

    pub fn encryption_key(&self) -> Option<&EncapsulationPublicKey> {
        // Prefer the inception key for encryption.
        if let Some(key) = self.inception_key() {
            Some(key.public_keys().enapsulation_public_key())
        } else if let Some(key) = self.keys.iter().next() {
            Some(key.public_keys().enapsulation_public_key())
        } else {
            None
        }
    }

    /// Get the private keys from the inception key, if available.
    ///
    /// Returns `None` if there is no inception key or if the inception key
    /// does not have private key material (e.g., if it was encrypted and not
    /// decrypted).
    pub fn inception_private_keys(&self) -> Option<&PrivateKeys> {
        self.inception_key().and_then(|key| key.private_keys())
    }

    /// Extract private keys from an envelope containing an encrypted
    /// XIDDocument.
    ///
    /// This is a convenience method that loads the document with the password
    /// and returns the inception key's private keys if available.
    ///
    /// Returns `None` if:
    /// - The document has no inception key
    /// - The inception key has no private key material
    /// - The password is incorrect
    pub fn extract_inception_private_keys_from_envelope(
        envelope: &Envelope,
        password: &[u8],
    ) -> Result<Option<PrivateKeys>> {
        let doc = Self::from_envelope(
            envelope,
            Some(password),
            XIDVerifySignature::None,
        )?;
        Ok(doc.inception_private_keys().cloned())
    }

    pub fn is_empty(&self) -> bool {
        self.resolution_methods.is_empty()
            && self.keys.is_empty()
            && self.delegates.is_empty()
            && self.provenance.is_none()
    }

    // `Delegate` is internally mutable, but the actual key of the `HashSet`,
    // the controller's `XID`, is not.
    #[allow(clippy::mutable_key_type)]
    pub fn delegates(&self) -> &HashSet<Delegate> { &self.delegates }

    // `Delegate` is internally mutable, but the actual key of the `HashSet`,
    // the controller's `XID`, is not.
    #[allow(clippy::mutable_key_type)]
    pub fn delegates_mut(&mut self) -> &mut HashSet<Delegate> {
        &mut self.delegates
    }

    pub fn add_delegate(&mut self, delegate: Delegate) -> Result<()> {
        if self.find_delegate_by_xid(&delegate).is_some() {
            return Err(Error::Duplicate { item: "delegate".to_string() });
        }
        self.delegates.insert(delegate);

        Ok(())
    }

    pub fn find_delegate_by_xid(
        &self,
        xid_provider: &dyn XIDProvider,
    ) -> Option<&Delegate> {
        self.delegates
            .iter()
            .find(|d| d.controller().read().xid() == xid_provider.xid())
    }

    pub fn find_delegate_by_reference(
        &self,
        reference: &Reference,
    ) -> Option<&Delegate> {
        self.delegates
            .iter()
            .find(|d| d.controller().read().xid().reference() == *reference)
    }

    pub fn take_delegate(
        &mut self,
        xid_provider: &dyn XIDProvider,
    ) -> Option<Delegate> {
        if let Some(delegate) = self.find_delegate_by_xid(xid_provider).cloned()
        {
            self.delegates.take(&delegate)
        } else {
            None
        }
    }

    pub fn remove_delegate(
        &mut self,
        xid_provider: &dyn XIDProvider,
    ) -> Result<()> {
        if self.services_reference_delegate(xid_provider) {
            return Err(Error::StillReferenced {
                item: "delegate".to_string(),
            });
        }
        if self.take_delegate(xid_provider).is_none() {
            return Err(Error::NotFound { item: "delegate".to_string() });
        }
        Ok(())
    }

    pub fn find_service_by_uri(
        &self,
        uri: impl AsRef<URI>,
    ) -> Option<&Service> {
        self.services.iter().find(|s| s.uri() == uri.as_ref())
    }

    pub fn services(&self) -> &HashSet<Service> { &self.services }

    pub fn add_service(&mut self, service: Service) -> Result<()> {
        if self.find_service_by_uri(service.uri()).is_some() {
            return Err(Error::Duplicate { item: "service".to_string() });
        }
        self.services.insert(service);
        Ok(())
    }

    pub fn take_service(&mut self, uri: impl AsRef<URI>) -> Option<Service> {
        if let Some(service) = self.find_service_by_uri(uri).cloned() {
            self.services.take(&service)
        } else {
            None
        }
    }

    pub fn check_services_consistency(&self) -> Result<()> {
        for service in &self.services {
            self.check_service_consistency(service)?;
        }
        Ok(())
    }

    pub fn check_service_consistency(&self, service: &Service) -> Result<()> {
        if service.key_references().is_empty()
            && service.delegate_references().is_empty()
        {
            return Err(Error::NoReferences { uri: service.uri().to_string() });
        }

        for key_reference in service.key_references() {
            if self.find_key_by_reference(key_reference).is_none() {
                return Err(Error::UnknownKeyReference {
                    reference: key_reference.to_string(),
                    uri: service.uri().to_string(),
                });
            }
        }

        for delegate_reference in service.delegate_references() {
            if self
                .find_delegate_by_reference(delegate_reference)
                .is_none()
            {
                return Err(Error::UnknownDelegateReference {
                    reference: delegate_reference.to_string(),
                    uri: service.uri().to_string(),
                });
            }
        }

        if service.permissions().allow().is_empty() {
            return Err(Error::NoPermissions {
                uri: service.uri().to_string(),
            });
        }

        Ok(())
    }

    pub fn check_contains_key(
        &self,
        key: &dyn PublicKeysProvider,
    ) -> Result<()> {
        if self.find_key_by_public_keys(key).is_none() {
            return Err(Error::KeyNotFoundInDocument {
                key: key.public_keys().to_string(),
            });
        }
        Ok(())
    }

    pub fn check_contains_delegate(
        &self,
        xid_provider: &dyn XIDProvider,
    ) -> Result<()> {
        if self.find_delegate_by_xid(xid_provider).is_none() {
            return Err(Error::DelegateNotFoundInDocument {
                delegate: xid_provider.xid().to_string(),
            });
        }
        Ok(())
    }

    pub fn services_reference_key(&self, key: &dyn PublicKeysProvider) -> bool {
        let key_reference = key.public_keys().reference();
        self.services
            .iter()
            .any(|service| service.key_references().contains(&key_reference))
    }

    pub fn services_reference_delegate(
        &self,
        xid_provider: &dyn XIDProvider,
    ) -> bool {
        let delegate_reference = xid_provider.xid().reference();
        self.services.iter().any(|service| {
            service.delegate_references().contains(&delegate_reference)
        })
    }

    pub fn remove_service(&mut self, uri: impl AsRef<URI>) -> Result<()> {
        if !self.services.iter().any(|s| s.uri() == uri.as_ref()) {
            return Err(Error::NotFound { item: "service".to_string() });
        }
        self.services.retain(|s| s.uri() != uri.as_ref());
        Ok(())
    }

    pub fn provenance(&self) -> Option<&ProvenanceMark> {
        self.provenance.as_ref().map(|p| p.mark())
    }

    pub fn provenance_generator(&self) -> Option<&ProvenanceMarkGenerator> {
        self.provenance.as_ref().and_then(|p| p.generator())
    }

    pub fn set_provenance(&mut self, provenance: Option<ProvenanceMark>) {
        self.provenance = provenance.map(Provenance::new);
    }

    pub fn set_provenance_with_generator(
        &mut self,
        generator: ProvenanceMarkGenerator,
        mark: ProvenanceMark,
    ) {
        self.provenance = Some(Provenance::new_with_generator(generator, mark));
    }

    /// Advance the provenance mark using the embedded generator.
    ///
    /// This method uses the generator embedded in the document's provenance
    /// to generate the next provenance mark. If the generator is encrypted,
    /// it will be decrypted using the provided password. After
    /// advancement, the generator remains in the document in decrypted
    /// state.
    ///
    /// # Parameters
    ///
    /// - `password`: Optional password to decrypt the generator if encrypted.
    ///   Pass as `Vec<u8>` or `None`.
    /// - `date`: Optional date for the new mark. If `None`, the current date is
    ///   used.
    /// - `info`: Optional CBOR-encodable info to attach to the new mark.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The document does not have a provenance mark
    ///   (`Error::NoProvenanceMark`)
    /// - The document does not have a generator (`Error::NoGenerator`)
    /// - The generator is encrypted and the password is wrong
    ///   (`Error::InvalidPassword`)
    pub fn next_provenance_mark_with_embedded_generator(
        &mut self,
        password: Option<Vec<u8>>,
        date: Option<Date>,
        info: Option<CBOR>,
    ) -> Result<()> {
        // Ensure we have a provenance to advance
        let provenance =
            self.provenance.as_mut().ok_or(Error::NoProvenanceMark)?;

        // Get the current mark
        let current_mark = provenance.mark().clone();

        // Get mutable access to the generator, decrypting if necessary
        let password_ref = password.as_deref();
        let generator = provenance
            .generator_mut(password_ref)?
            .ok_or(Error::NoGenerator)?;

        // Validate chain ID matches
        if generator.chain_id() != current_mark.chain_id() {
            return Err(Error::ChainIdMismatch {
                expected: current_mark.chain_id().to_vec(),
                actual: generator.chain_id().to_vec(),
            });
        }

        // Validate sequence number is correct (next_seq should be current seq +
        // 1)
        let expected_seq = current_mark.seq() + 1;
        if generator.next_seq() != expected_seq {
            return Err(Error::SequenceMismatch {
                expected: expected_seq,
                actual: generator.next_seq(),
            });
        }

        // Generate the next mark
        let date = date.unwrap_or_else(Date::now);
        let next_mark = generator.next(date, info);

        // Update the provenance mark
        provenance.set_mark(next_mark);

        Ok(())
    }

    /// Advance the provenance mark using a provided generator.
    ///
    /// This method uses an external generator to generate the next provenance
    /// mark. The generator is not embedded in the document after
    /// advancement; the caller maintains ownership of the generator.
    ///
    /// # Parameters
    ///
    /// - `generator`: Mutable reference to the external
    ///   `ProvenanceMarkGenerator`.
    /// - `date`: Optional date for the new mark. If `None`, the current date is
    ///   used.
    /// - `info`: Optional CBOR-encodable info to attach to the new mark.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The document does not have a provenance mark
    ///   (`Error::NoProvenanceMark`)
    /// - The document already has an embedded generator
    ///   (`Error::GeneratorConflict`)
    /// - The provided generator's chain ID doesn't match the current mark's
    ///   chain ID
    /// - The provided generator's next_seq doesn't match the expected sequence
    ///   number
    pub fn next_provenance_mark_with_provided_generator(
        &mut self,
        generator: &mut ProvenanceMarkGenerator,
        date: Option<Date>,
        info: Option<CBOR>,
    ) -> Result<()> {
        // Ensure we have a provenance to advance
        let provenance =
            self.provenance.as_mut().ok_or(Error::NoProvenanceMark)?;

        // Check that the document doesn't already have a generator
        if provenance.has_generator() || provenance.has_encrypted_generator() {
            return Err(Error::GeneratorConflict);
        }

        // Get the current mark
        let current_mark = provenance.mark().clone();

        // Validate chain ID matches
        if generator.chain_id() != current_mark.chain_id() {
            return Err(Error::ChainIdMismatch {
                expected: current_mark.chain_id().to_vec(),
                actual: generator.chain_id().to_vec(),
            });
        }

        // Validate sequence number is correct (next_seq should be current seq +
        // 1)
        let expected_seq = current_mark.seq() + 1;
        if generator.next_seq() != expected_seq {
            return Err(Error::SequenceMismatch {
                expected: expected_seq,
                actual: generator.next_seq(),
            });
        }

        // Generate the next mark
        let date = date.unwrap_or_else(Date::now);
        let next_mark = generator.next(date, info);

        // Update the provenance mark
        provenance.set_mark(next_mark);

        Ok(())
    }

    /// Convert XIDDocument to an Envelope.
    pub fn to_envelope(
        &self,
        private_key_options: XIDPrivateKeyOptions,
        generator_options: XIDGeneratorOptions,
        signing_options: XIDSigningOptions,
    ) -> Result<Envelope> {
        let mut envelope = Envelope::new(self.xid);

        // Add an assertion for each resolution method.
        envelope = self
            .resolution_methods
            .iter()
            .cloned()
            .fold(envelope, |envelope, method| {
                envelope.add_assertion(DEREFERENCE_VIA, method)
            });

        // Add an assertion for each key in the set.
        envelope = self.keys.iter().cloned().fold(envelope, |envelope, key| {
            envelope.add_assertion(
                KEY,
                key.into_envelope_opt(private_key_options.clone()),
            )
        });

        // Add an assertion for each delegate.
        envelope = self
            .delegates
            .iter()
            .cloned()
            .fold(envelope, |envelope, delegate| {
                envelope.add_assertion(DELEGATE, delegate)
            });

        // Add an assertion for each service.
        envelope = self
            .services
            .iter()
            .cloned()
            .fold(envelope, |envelope, service| {
                envelope.add_assertion(SERVICE, service)
            });

        // Add the provenance mark with optional generator.
        if let Some(provenance) = &self.provenance {
            envelope = envelope.add_assertion(
                PROVENANCE,
                provenance.clone().into_envelope_opt(generator_options),
            );
        }

        // Apply signing options.
        let envelope = match signing_options {
            XIDSigningOptions::None => envelope,
            XIDSigningOptions::Inception => {
                let inception_key =
                    self.inception_key().ok_or(Error::MissingInceptionKey)?;
                let private_keys = inception_key
                    .private_keys()
                    .ok_or(Error::MissingInceptionKey)?;
                envelope.sign(private_keys)
            }
            XIDSigningOptions::PrivateKeys(ref keys) => envelope.sign(keys),
            XIDSigningOptions::SigningPrivateKey(ref key) => envelope.sign(key),
        };

        Ok(envelope)
    }

    /// Extract an `XIDDocument` from an envelope.
    ///
    /// # Parameters
    ///
    /// - `envelope`: The envelope to extract the document from. Can be signed
    ///   or unsigned.
    /// - `password`: Optional password to decrypt encrypted private keys. If
    ///   private keys are encrypted and no password is provided, the keys will
    ///   be stored without their private key material.
    /// - `verify_signature`: Signature verification mode. Use
    ///   `XIDVerifySignature::None` to skip verification, or
    ///   `XIDVerifySignature::Inception` to verify that the envelope is signed
    ///   with the inception key.
    ///
    /// # Returns
    ///
    /// Returns `Ok(XIDDocument)` on success.
    ///
    /// # Errors
    ///
    /// - `Error::EnvelopeNotSigned`: When `verify_signature` is `Inception` but
    ///   the envelope is not signed.
    /// - `Error::MissingInceptionKey`: When `verify_signature` is `Inception`
    ///   but the inception key is not found in the document.
    /// - `Error::SignatureVerificationFailed`: When the signature verification
    ///   fails.
    /// - `Error::InvalidXid`: When the inception key does not match the XID.
    /// - Other errors from envelope parsing or key extraction.
    pub fn from_envelope(
        envelope: &Envelope,
        password: Option<&[u8]>,
        verify_signature: XIDVerifySignature,
    ) -> Result<Self> {
        // Extract attachments from the outer envelope first, before unwrapping
        let attachments = Attachments::try_from_envelope(envelope)
            .map_err(Error::EnvelopeParsing)?;

        match verify_signature {
            XIDVerifySignature::None => {
                // Extract from the envelope directly (unsigned or ignoring
                // signature)
                let envelope_to_parse = if envelope.subject().is_wrapped() {
                    envelope.subject().try_unwrap()?
                } else {
                    envelope.clone()
                };
                let mut xid_document =
                    Self::from_envelope_inner(&envelope_to_parse, password)?;
                xid_document.attachments = attachments;
                Ok(xid_document)
            }
            XIDVerifySignature::Inception => {
                // Verify that the envelope is signed (subject must be wrapped)
                if !envelope.subject().is_wrapped() {
                    return Err(Error::EnvelopeNotSigned);
                }

                // Unwrap the envelope and construct a provisional XIDDocument
                let unwrapped = envelope.try_unwrap()?;
                let mut xid_document =
                    Self::from_envelope_inner(&unwrapped, password)?;

                // Extract the inception key from the provisional XIDDocument
                let inception_key = xid_document
                    .inception_signing_key()
                    .ok_or(Error::MissingInceptionKey)?;

                // Verify the signature on the envelope using the inception key
                envelope
                    .verify(inception_key)
                    .map_err(|_| Error::SignatureVerificationFailed)?;

                // Extract the XID from the provisional XIDDocument
                let xid = xid_document.xid();

                // Verify that the inception key is the one that generated the
                // XID
                if !xid.validate(inception_key) {
                    Err(Error::InvalidXid)
                } else {
                    xid_document.attachments = attachments;
                    Ok(xid_document)
                }
            }
        }
    }

    /// Internal helper method to extract an `XIDDocument` from an unwrapped
    /// envelope.
    fn from_envelope_inner(
        envelope: &Envelope,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let xid: XID = envelope.subject().try_leaf()?.try_into()?;
        let mut xid_document = XIDDocument::from(xid);
        for assertion in envelope.assertions() {
            let predicate =
                assertion.try_predicate()?.try_known_value()?.value();
            let object = assertion.try_object()?;
            match predicate {
                DEREFERENCE_VIA_RAW => {
                    let method: URI = object
                        .try_leaf()?
                        .try_into()
                        .map_err(|_| Error::InvalidResolutionMethod)?;
                    xid_document.add_resolution_method(method);
                }
                KEY_RAW => {
                    let key = Key::try_from_envelope(&object, password)?;
                    xid_document.add_key(key)?;
                }
                DELEGATE_RAW => {
                    let delegate = Delegate::try_from(object)?;
                    xid_document.add_delegate(delegate)?;
                }
                SERVICE_RAW => {
                    let service = Service::try_from(object)?;
                    xid_document.add_service(service)?;
                }
                PROVENANCE_RAW => {
                    let provenance =
                        Provenance::try_from_envelope(&object, password)?;
                    if xid_document.provenance.is_some() {
                        return Err(Error::MultipleProvenanceMarks);
                    }
                    xid_document.provenance = Some(provenance);
                }
                ATTACHMENT_RAW => {
                    // Attachment assertions are handled separately by
                    // Attachments::try_from_envelope() below, so we skip them
                    // here.
                }
                _ => {
                    return Err(Error::UnexpectedPredicate {
                        predicate: predicate.to_string(),
                    });
                }
            }
        }

        xid_document.check_services_consistency()?;

        Ok(xid_document)
    }

    pub fn to_signed_envelope(&self, signing_key: &impl Signer) -> Envelope {
        self.to_signed_envelope_opt(
            signing_key,
            XIDPrivateKeyOptions::default(),
        )
    }

    pub fn to_signed_envelope_opt(
        &self,
        signing_key: &impl Signer,
        private_key_options: XIDPrivateKeyOptions,
    ) -> Envelope {
        self.to_envelope(
            private_key_options,
            XIDGeneratorOptions::default(),
            XIDSigningOptions::None,
        )
        .expect("envelope should not fail")
        .sign(signing_key)
    }
}

impl Default for XIDDocument {
    fn default() -> Self {
        Self::new(XIDInceptionKeyOptions::Default, XIDGenesisMarkOptions::None)
    }
}

bc_envelope::impl_attachable!(XIDDocument);

impl XIDProvider for XIDDocument {
    fn xid(&self) -> XID { self.xid }
}

impl ReferenceProvider for XIDDocument {
    fn reference(&self) -> Reference { self.xid.reference() }
}

impl AsRef<XIDDocument> for XIDDocument {
    fn as_ref(&self) -> &XIDDocument { self }
}

impl From<XIDDocument> for XID {
    fn from(doc: XIDDocument) -> Self { doc.xid }
}

impl From<XID> for XIDDocument {
    fn from(xid: XID) -> Self { XIDDocument::from_xid(xid) }
}

impl From<PublicKeys> for XIDDocument {
    fn from(inception_key: PublicKeys) -> Self {
        XIDDocument::new(
            XIDInceptionKeyOptions::PublicKeys(inception_key),
            XIDGenesisMarkOptions::None,
        )
    }
}

impl From<PrivateKeyBase> for XIDDocument {
    fn from(inception_key: PrivateKeyBase) -> Self {
        XIDDocument::new(
            XIDInceptionKeyOptions::PrivateKeyBase(inception_key),
            XIDGenesisMarkOptions::None,
        )
    }
}

impl From<&PrivateKeyBase> for XIDDocument {
    fn from(inception_key: &PrivateKeyBase) -> Self {
        XIDDocument::new(
            XIDInceptionKeyOptions::PrivateKeyBase(inception_key.clone()),
            XIDGenesisMarkOptions::None,
        )
    }
}

impl From<XIDDocument> for Envelope {
    fn from(value: XIDDocument) -> Self {
        if value.is_empty() {
            return value.xid.to_envelope();
        }
        let e = value
            .to_envelope(
                XIDPrivateKeyOptions::default(),
                XIDGeneratorOptions::default(),
                XIDSigningOptions::default(),
            )
            .expect("envelope should not fail");
        value.attachments.add_to_envelope(e)
    }
}

impl TryFrom<&Envelope> for XIDDocument {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        Self::from_envelope(envelope, None, XIDVerifySignature::None)
    }
}

impl TryFrom<Envelope> for XIDDocument {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        XIDDocument::try_from(&envelope)
    }
}

impl CBORTagged for XIDDocument {
    fn cbor_tags() -> Vec<Tag> { tags_for_values(&[TAG_XID]) }
}

impl From<XIDDocument> for CBOR {
    fn from(value: XIDDocument) -> Self { value.tagged_cbor() }
}

impl CBORTaggedEncodable for XIDDocument {
    fn untagged_cbor(&self) -> CBOR {
        if self.is_empty() {
            return self.xid.untagged_cbor();
        }
        self.to_envelope(
            XIDPrivateKeyOptions::default(),
            XIDGeneratorOptions::default(),
            XIDSigningOptions::None,
        )
        .expect("envelope should not fail")
        .to_cbor()
    }
}

impl TryFrom<CBOR> for XIDDocument {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for XIDDocument {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        if let Some(byte_string) = cbor.clone().into_byte_string() {
            let xid = XID::from_data_ref(byte_string)?;
            return Ok(Self::from_xid(xid));
        }

        let envelope = Envelope::try_from(cbor)?;
        let xid_doc: Self =
            envelope.try_into().map_err(|e: Error| match e {
                Error::Cbor(cbor_err) => cbor_err,
                _ => CBORError::msg(e.to_string()),
            })?;
        Ok(xid_doc)
    }
}
