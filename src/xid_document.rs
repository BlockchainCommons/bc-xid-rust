use std::collections::HashSet;

use bc_components::{
    EncapsulationPublicKey, PrivateKeyBase, PrivateKeys, PrivateKeysProvider,
    PublicKeys, PublicKeysProvider, Reference, ReferenceProvider, Signer,
    SigningPublicKey, URI, XID, XIDProvider, tags::TAG_XID,
};
use bc_envelope::prelude::*;
use dcbor::prelude::CBORError;
use known_values::{
    DELEGATE, DELEGATE_RAW, DEREFERENCE_VIA, DEREFERENCE_VIA_RAW, KEY, KEY_RAW,
    PROVENANCE, PROVENANCE_RAW, SERVICE, SERVICE_RAW,
};
use provenance_mark::ProvenanceMark;

use super::{Delegate, Key};
use crate::{
    Error, HasNickname, HasPermissions, PrivateKeyOptions, Result, Service,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XIDDocument {
    xid: XID,
    resolution_methods: HashSet<URI>,
    keys: HashSet<Key>,
    delegates: HashSet<Delegate>,
    services: HashSet<Service>,
    provenance: Option<ProvenanceMark>,
}

impl XIDDocument {
    pub fn new(inception_public_key: impl AsRef<PublicKeys>) -> Self {
        let mut doc = Self::new_empty(&inception_public_key);
        doc.add_key(Key::new_allow_all(&inception_public_key))
            .unwrap();
        doc
    }

    pub fn new_empty(inception_public_key: impl AsRef<PublicKeys>) -> Self {
        let xid = XID::new(inception_public_key.as_ref().signing_public_key());
        Self {
            xid,
            resolution_methods: HashSet::new(),
            keys: HashSet::new(),
            delegates: HashSet::new(),
            services: HashSet::new(),
            provenance: None,
        }
    }

    pub fn new_with_keys(
        inception_private_keys: PrivateKeys,
        inception_public_keys: PublicKeys,
    ) -> Self {
        let xid = XID::new(inception_public_keys.signing_public_key());
        let inception_key = Key::new_with_private_keys(
            inception_private_keys,
            inception_public_keys,
        );
        let mut keys = HashSet::new();
        keys.insert(inception_key.clone());
        Self {
            xid,
            resolution_methods: HashSet::new(),
            keys,
            delegates: HashSet::new(),
            services: HashSet::new(),
            provenance: None,
        }
    }

    pub fn new_with_private_key_base(private_key_base: PrivateKeyBase) -> Self {
        let public_keys = private_key_base.public_keys();
        let private_keys = private_key_base.private_keys();
        Self::new_with_keys(private_keys, public_keys)
    }

    pub fn new_with_provenance(
        inception_public_key: PublicKeys,
        provenance: ProvenanceMark,
    ) -> Self {
        let mut doc = Self::new(inception_public_key);
        doc.provenance = Some(provenance);
        doc
    }

    pub fn from_xid(xid: impl Into<XID>) -> Self {
        Self {
            xid: xid.into(),
            resolution_methods: HashSet::new(),
            keys: HashSet::new(),
            delegates: HashSet::new(),
            services: HashSet::new(),
            provenance: None,
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

    pub fn keys(&self) -> &HashSet<Key> {
        &self.keys
    }

    pub fn keys_mut(&mut self) -> &mut HashSet<Key> {
        &mut self.keys
    }

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

    /// Get the private key envelope for a specific key, optionally decrypting it.
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
    /// use bc_xid::XIDDocument;
    /// use bc_envelope::prelude::*;
    /// use bc_components::{PrivateKeyBase, PublicKeysProvider};
    ///
    /// let prvkey_base = PrivateKeyBase::new();
    /// let doc = XIDDocument::new_with_private_key_base(prvkey_base.clone());
    ///
    /// // Get unencrypted private key
    /// let key = doc.keys().iter().next().unwrap();
    /// let envelope = doc.private_key_envelope_for_key(key.public_keys(), None).unwrap().unwrap();
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
            return Some(key.public_keys().signing_public_key());
        } else {
            None
        }
    }

    pub fn encryption_key(&self) -> Option<&EncapsulationPublicKey> {
        // Prefer the inception key for encryption.
        if let Some(key) = self.inception_key() {
            Some(key.public_keys().enapsulation_public_key())
        } else if let Some(key) = self.keys.iter().next() {
            return Some(key.public_keys().enapsulation_public_key());
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
        let doc = Self::from_unsigned_envelope_with_password(
            envelope,
            Some(password),
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
    pub fn delegates(&self) -> &HashSet<Delegate> {
        &self.delegates
    }

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

    pub fn services(&self) -> &HashSet<Service> {
        &self.services
    }

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
        self.provenance.as_ref()
    }

    pub fn set_provenance(&mut self, provenance: Option<ProvenanceMark>) {
        self.provenance = provenance;
    }

    pub fn to_unsigned_envelope(&self) -> Envelope {
        self.to_unsigned_envelope_opt(PrivateKeyOptions::default())
    }

    pub fn to_unsigned_envelope_opt(
        &self,
        private_key_options: PrivateKeyOptions,
    ) -> Envelope {
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

        // Add the provenance mark if any.
        envelope = envelope
            .add_optional_assertion(PROVENANCE, self.provenance.clone());

        envelope
    }

    pub fn from_unsigned_envelope(envelope: &Envelope) -> Result<Self> {
        Self::from_unsigned_envelope_with_password(envelope, None)
    }

    /// Extract an `XIDDocument` from an envelope, optionally providing a
    /// password to decrypt encrypted private keys.
    ///
    /// If private keys are encrypted and no password is provided, the keys
    /// will be stored without their private key material.
    pub fn from_unsigned_envelope_with_password(
        envelope: &Envelope,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        //
        // This technique is more robust than the commented-out technique below,
        // because it will fail if there are unexpected attributes in the
        // envelope.
        //

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
                    let provenance = ProvenanceMark::try_from(object)?;
                    if xid_document.provenance().is_some() {
                        return Err(Error::MultipleProvenanceMarks);
                    }
                    xid_document.set_provenance(Some(provenance));
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

        //
        // Do not use this technique to extract attributes from an envelope,
        // unless you want to ignore unexpected attributes.
        //

        // let resolution_methods = envelope
        //     .extract_objects_for_predicate::<URI>(DEREFERENCE_VIA)?
        //     .into_iter()
        //     .collect::<HashSet<_>>();

        // let keys = envelope
        //     .objects_for_predicate(KEY)
        //     .into_iter()
        //     .map(|key| key.try_into())
        //     .collect::<Result<HashSet<_>>>()?;

        // let delegates = envelope
        //     .object_for_predicate(DELEGATE)
        //     .into_iter()
        //     .map(|delegate| delegate.try_into())
        //     .collect::<Result<HashSet<_>>>()?;

        // let provenance = match
        // envelope.optional_object_for_predicate(PROVENANCE)? {
        //     Some(p) => Some(ProvenanceMark::try_from(p)?),
        //     None => None,
        // };

        // Ok(Self {
        //     xid,
        //     resolution_methods,
        //     keys,
        //     delegates,
        //     provenance,
        // })
    }

    pub fn to_signed_envelope(&self, signing_key: &impl Signer) -> Envelope {
        self.to_signed_envelope_opt(signing_key, PrivateKeyOptions::default())
    }

    pub fn to_signed_envelope_opt(
        &self,
        signing_key: &impl Signer,
        private_key_options: PrivateKeyOptions,
    ) -> Envelope {
        self.to_unsigned_envelope_opt(private_key_options)
            .sign(signing_key)
    }

    pub fn try_from_signed_envelope(
        signed_envelope: &Envelope,
    ) -> Result<Self> {
        // Unwrap the envelope and construct a provisional XIDDocument.
        let xid_document =
            XIDDocument::try_from(&signed_envelope.try_unwrap()?)?;
        // Extract the inception key from the provisional XIDDocument, throwing
        // an error if it is missing.
        let inception_key = xid_document
            .inception_signing_key()
            .ok_or(Error::MissingInceptionKey)?;
        // Verify the signature on the envelope using the inception key.
        signed_envelope.verify(inception_key)?;
        // Extract the XID from the provisional XIDDocument.
        let xid = xid_document.xid();
        // Verify that the inception key is the one that generated the XID.
        if xid.validate(inception_key) {
            // If the inception key is valid return the XIDDocument, now
            // verified.
            Ok(xid_document)
        } else {
            Err(Error::InvalidXid)
        }
    }
}

impl XIDProvider for XIDDocument {
    fn xid(&self) -> XID {
        self.xid
    }
}

impl ReferenceProvider for XIDDocument {
    fn reference(&self) -> Reference {
        self.xid.reference()
    }
}

impl AsRef<XIDDocument> for XIDDocument {
    fn as_ref(&self) -> &XIDDocument {
        self
    }
}

impl From<XIDDocument> for XID {
    fn from(doc: XIDDocument) -> Self {
        doc.xid
    }
}

impl From<XID> for XIDDocument {
    fn from(xid: XID) -> Self {
        XIDDocument::from_xid(xid)
    }
}

impl From<PublicKeys> for XIDDocument {
    fn from(inception_key: PublicKeys) -> Self {
        XIDDocument::new(inception_key)
    }
}

impl From<PrivateKeyBase> for XIDDocument {
    fn from(inception_key: PrivateKeyBase) -> Self {
        XIDDocument::new_with_private_key_base(inception_key)
    }
}

impl From<&PrivateKeyBase> for XIDDocument {
    fn from(inception_key: &PrivateKeyBase) -> Self {
        XIDDocument::new_with_private_key_base(inception_key.clone())
    }
}

impl EnvelopeEncodable for XIDDocument {
    fn into_envelope(self) -> Envelope {
        self.to_unsigned_envelope()
    }
}

impl TryFrom<&Envelope> for XIDDocument {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        Self::from_unsigned_envelope(envelope)
    }
}

impl TryFrom<Envelope> for XIDDocument {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        XIDDocument::try_from(&envelope)
    }
}

impl CBORTagged for XIDDocument {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[TAG_XID])
    }
}

impl From<XIDDocument> for CBOR {
    fn from(value: XIDDocument) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for XIDDocument {
    fn untagged_cbor(&self) -> CBOR {
        if self.is_empty() {
            return self.xid.untagged_cbor();
        }
        self.to_envelope().to_cbor()
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use bc_components::{
        EncapsulationScheme, KeyDerivationMethod, PrivateKeyBase, PrivateKeys,
        PrivateKeysProvider, PublicKeysProvider, SignatureScheme, URI, XID,
        XIDProvider, tags,
    };

    use crate::Error;
    use bc_envelope::{PublicKeys, prelude::*};
    use bc_rand::make_fake_random_number_generator;
    use indoc::indoc;
    use provenance_mark::{
        ProvenanceMarkGenerator, ProvenanceMarkResolution, ProvenanceSeed,
    };

    use crate::{
        Delegate, HasPermissions, Key, PrivateKeyOptions, Privilege, Service,
        XIDDocument,
    };

    #[test]
    fn xid_document() {
        // Create a XID document.
        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let public_keys = private_key_base.public_keys();
        let xid_document = XIDDocument::new(public_keys);

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
        assert_eq!(envelope.format(), expected_format);

        // Convert the Envelope back to a XIDDocument.
        let xid_document2 = XIDDocument::try_from(envelope).unwrap();
        assert_eq!(xid_document, xid_document2);

        // Convert the XID document to a UR
        let xid_document_ur = xid_document.ur_string();
        assert_eq!(
            xid_document_ur,
            "ur:xid/tpsplftpsotanshdhdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnoyaylftpsotansgylftanshfhdcxhslkfzemaylrwttynsdlghrydpmdfzvdglndloimaahykorefddtsguogmvlahqztansgrhdcxetlewzvlwyfdtobeytidosbamkswaomwwfyabakssakggegychesmerkcatekpcxoycsfncsfggmplgshd"
        );
        let xid_document2 =
            XIDDocument::from_ur_string(&xid_document_ur).unwrap();
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
        assert_eq!(xid_cbor_hex, (indoc! {r#"
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
        let private_keys = PrivateKeys::with_keys(
            signing_private_key,
            encapsulation_private_key,
        );
        let public_keys =
            PublicKeys::new(signing_public_key, encapsulation_public_key);

        // Create the XID document.
        let xid_document =
            XIDDocument::new_with_keys(private_keys, public_keys);

        // Convert the XID document to an Envelope.
        let envelope = xid_document
            .clone()
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);

        // Convert the Envelope back to a XIDDocument.
        let xid_document2 = XIDDocument::try_from(envelope).unwrap();
        assert_eq!(xid_document, xid_document2);

        // Convert the XID document to a UR. Note that this UR will *not*
        // contain the `PrivateKeys`.
        let xid_document_ur = xid_document.ur_string();

        // The documents should *not* match, because the UR does not
        // contain the `PrivateKeys`.
        let xid_document2 =
            XIDDocument::from_ur_string(&xid_document_ur).unwrap();
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
        let mut xid_document = XIDDocument::new_empty(&public_keys);

        // Add resolution methods.
        xid_document.add_resolution_method(
            URI::try_from("https://resolver.example.com").unwrap(),
        );
        xid_document
            .add_resolution_method(URI::try_from("btcr:01234567").unwrap());

        // Convert the XID document to an Envelope.
        let envelope = xid_document.clone().into_envelope();
        // println!("{}", envelope.format());
        #[rustfmt::skip]
        let expected_format = (indoc! {r#"
            XID(71274df1) [
                'dereferenceVia': URI(btcr:01234567)
                'dereferenceVia': URI(https://resolver.example.com)
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected_format);

        // Convert the Envelope back to a XIDDocument.
        let xid_document2 = XIDDocument::try_from(envelope).unwrap();
        assert_eq!(xid_document, xid_document2);

        // let cbor = xid_document.to_cbor();
        // println!("{}", cbor.diagnostic());
        // let ur = xid_document.ur();
        // println!("{}", ur);
    }

    #[test]
    fn signed_xid_document() {
        // Generate the inception key.
        let mut rng = make_fake_random_number_generator();
        let private_inception_key = PrivateKeyBase::new_using(&mut rng);
        let public_inception_key = private_inception_key.public_keys();

        // Create a XIDDocument for the inception key.
        let xid_document = XIDDocument::new(public_inception_key);

        let envelope = xid_document.clone().into_envelope();
        #[rustfmt::skip]
        let expected_format = (indoc! {r#"
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected_format);

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
        assert_eq!(signed_envelope.format(), expected_format);

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

        let genesis_seed = ProvenanceSeed::new_using(&mut rng);

        let mut generator = ProvenanceMarkGenerator::new_with_seed(
            ProvenanceMarkResolution::Quartile,
            genesis_seed,
        );
        let date = Date::from_string("2025-01-01").unwrap();
        let provenance = generator.next(date, None::<String>);
        let xid_document =
            XIDDocument::new_with_provenance(inception_key, provenance);
        let signed_envelope =
            xid_document.to_signed_envelope(&private_inception_key);
        #[rustfmt::skip]
        let expected_format = (indoc! {r#"
            {
                XID(71274df1) [
                    'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                        'allow': 'All'
                    ]
                    'provenance': ProvenanceMark(cfe14854)
                ]
            } [
                'signed': Signature
            ]
        "#}).trim();
        assert_eq!(signed_envelope.format(), expected_format);

        let self_certified_xid_document =
            XIDDocument::try_from_signed_envelope(&signed_envelope).unwrap();
        assert_eq!(xid_document, self_certified_xid_document);
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

        let xid_document_including_private_key =
            XIDDocument::new_with_private_key_base(
                private_inception_key.clone(),
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
        assert_eq!(
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

        let xid_document_excluding_private_key =
            XIDDocument::new(public_inception_key);
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
                PrivateKeyOptions::Include,
            );
        #[rustfmt::skip]
        let expected_format = (indoc! {r#"
            {
                XID(71274df1) [
                    'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                        {
                            'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, ECPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
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
        assert_eq!(
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
                PrivateKeyOptions::Elide,
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
        assert_eq!(
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

        let xid_document2_envelope = xid_document_2.to_envelope();
        #[rustfmt::skip]
        let expected_format = (indoc! {r#"
            XID(71274df1)
        "#}).trim();
        assert_eq!(xid_document2_envelope.format(), expected_format);

        // Create a new key.
        let private_key_base_2 = PrivateKeyBase::new_using(&mut rng);
        let public_keys_2 = private_key_base_2.public_keys();

        // Add the new key to the empty XID document.
        let key_2 = Key::new_allow_all(public_keys_2);
        xid_document_2.add_key(key_2.clone()).unwrap();
        let xid_document2_envelope = xid_document_2.to_envelope();
        #[rustfmt::skip]
        let expected_format = (indoc! {r#"
            XID(71274df1) [
                'key': PublicKeys(b8164d99, SigningPublicKey(7c30cafe, SchnorrPublicKey(448e2868)), EncapsulationPublicKey(e472f495, X25519PublicKey(e472f495))) [
                    'allow': 'All'
                ]
            ]
        "#}).trim();
        assert_eq!(xid_document2_envelope.format(), expected_format);

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
        let mut alice_xid_document = XIDDocument::new(&alice_public_keys);
        alice_xid_document
            .set_name_for_key(&alice_public_keys, "Alice")
            .unwrap();

        let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let bob_public_keys = bob_private_key_base.public_keys();
        let mut bob_xid_document = XIDDocument::new(&bob_public_keys);
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
        assert_eq!(envelope.format(), expected);

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
    fn test_xid_document_with_encrypted_private_keys() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let private_keys = private_key_base.private_keys();
        let public_keys = private_key_base.public_keys();
        let password = b"secure_xid_password";

        //
        // Create an XID document with private keys.
        //
        let xid_document = XIDDocument::new_with_keys(
            private_keys.clone(),
            public_keys.clone(),
        );

        //
        // Convert to envelope with encrypted private keys using Argon2id.
        //
        let envelope_encrypted = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
        );

        // The private key should be encrypted in the envelope.
        #[rustfmt::skip]
        assert_eq!(envelope_encrypted.format(), indoc! {r#"
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
    fn test_xid_document_with_encrypted_multiple_keys() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let password = b"multi_key_password";

        //
        // Create an XID document with inception key.
        //
        let inception_base = PrivateKeyBase::new_using(&mut rng);
        let mut xid_document =
            XIDDocument::new_with_private_key_base(inception_base.clone());

        //
        // Add a second key with private key material.
        //
        let second_base = PrivateKeyBase::new_using(&mut rng);
        let second_key = Key::new_with_private_key_base(second_base.clone());
        xid_document.add_key(second_key).unwrap();

        //
        // Convert to envelope with all private keys encrypted using Scrypt.
        //
        let envelope_encrypted = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            },
        );

        //
        // Extract with password - both keys should have their private key
        // material.
        //
        let xid_doc_decrypted =
            XIDDocument::from_unsigned_envelope_with_password(
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
    fn test_xid_document_private_key_modes() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());

        //
        // Mode 1: Omit private keys (default)
        //
        let envelope_omit = xid_document.clone().to_unsigned_envelope();
        #[rustfmt::skip]
        assert_eq!(envelope_omit.format(), indoc! {r#"
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    'allow': 'All'
                ]
            ]
        "#}.trim());

        // Can extract, but private keys will be None
        let doc_omit =
            XIDDocument::from_unsigned_envelope(&envelope_omit).unwrap();
        assert!(doc_omit.inception_key().unwrap().private_keys().is_none());

        //
        // Mode 2: Include private keys in plaintext
        //
        let envelope_include = xid_document
            .clone()
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);
        #[rustfmt::skip]
        assert_eq!(envelope_include.format(), indoc! {r#"
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    {
                        'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, ECPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
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
            .to_unsigned_envelope_opt(PrivateKeyOptions::Elide);
        #[rustfmt::skip]
        assert_eq!(envelope_elide.format(), indoc! {r#"
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
        let envelope_encrypt = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
        );
        #[rustfmt::skip]
        assert_eq!(envelope_encrypt.format(), indoc! {r#"
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
    fn test_xid_document_encrypted_with_different_methods() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());
        let password = b"test_password";

        //
        // Test Argon2id (recommended)
        //
        let envelope_argon2id = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
        );
        #[rustfmt::skip]
        assert_eq!(envelope_argon2id.format(), indoc! {r#"
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
        let envelope_pbkdf2 = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::PBKDF2,
                password: password.to_vec(),
            },
        );
        #[rustfmt::skip]
        assert_eq!(envelope_pbkdf2.format(), indoc! {r#"
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
        let envelope_scrypt = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            },
        );
        #[rustfmt::skip]
        assert_eq!(envelope_scrypt.format(), indoc! {r#"
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
    fn test_xid_document_reencrypt_with_different_password() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let private_keys = private_key_base.private_keys();
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());
        let password1 = b"first_password";
        let password2 = b"second_password";

        //
        // Encrypt with first password.
        //
        let envelope1 = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password1.to_vec(),
            },
        );

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
        let envelope2 = doc_decrypted.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password2.to_vec(),
            },
        );

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
        let doc_reencrypted =
            XIDDocument::from_unsigned_envelope_with_password(
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
    fn test_xid_document_change_encryption_method() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());
        let password = b"shared_password";

        //
        // Encrypt with Argon2id.
        //
        let envelope_argon2id = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
        );

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
        let envelope_scrypt = doc_decrypted.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Scrypt,
                password: password.to_vec(),
            },
        );

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
        let doc_from_scrypt =
            XIDDocument::from_unsigned_envelope_with_password(
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
    fn test_xid_document_encrypt_decrypt_plaintext_roundtrip() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let private_keys = private_key_base.private_keys();
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());
        let password = b"test_password";

        //
        // Start with plaintext.
        //
        let envelope_plaintext = xid_document
            .clone()
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);
        #[rustfmt::skip]
        assert_eq!(envelope_plaintext.format(), indoc! {r#"
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [
                    {
                        'privateKey': PrivateKeys(fb7c8739, SigningPrivateKey(8492209a, ECPrivateKey(d8b5618f)), EncapsulationPrivateKey(b5f1ec8f, X25519PrivateKey(b5f1ec8f)))
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
            .to_unsigned_envelope_opt(PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            });
        #[rustfmt::skip]
        assert_eq!(envelope_encrypted.format(), indoc! {r#"
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
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);

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
    fn test_xid_document_switch_between_storage_modes() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());
        let password = b"mode_switch_password";

        //
        // Mode 1: Plaintext
        //
        let envelope_plaintext = xid_document
            .clone()
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);
        let doc1 =
            XIDDocument::from_unsigned_envelope(&envelope_plaintext).unwrap();
        assert_eq!(doc1, xid_document);

        //
        // Mode 2: Encrypted
        //
        let envelope_encrypted =
            doc1.clone()
                .to_unsigned_envelope_opt(PrivateKeyOptions::Encrypt {
                    method: KeyDerivationMethod::Argon2id,
                    password: password.to_vec(),
                });
        let doc2 = XIDDocument::from_unsigned_envelope_with_password(
            &envelope_encrypted,
            Some(password),
        )
        .unwrap();
        assert_eq!(doc2, xid_document);

        //
        // Mode 3: Omitted
        //
        let envelope_omit = doc2.clone().to_unsigned_envelope();
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
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);
        let doc4 =
            XIDDocument::from_unsigned_envelope(&envelope_plaintext2).unwrap();
        assert_eq!(doc4, xid_document);

        //
        // Mode 4: Elided (maintains digest)
        //
        let envelope_elide = doc2
            .clone()
            .to_unsigned_envelope_opt(PrivateKeyOptions::Elide);
        let doc5 =
            XIDDocument::from_unsigned_envelope(&envelope_elide).unwrap();
        assert_ne!(doc5, xid_document);
        assert!(doc5.inception_key().unwrap().private_keys().is_none());

        //
        // Elided should be equivalent to plaintext (same digest).
        //
        assert!(envelope_elide.is_equivalent_to(&envelope_plaintext));
    }

    #[test]
    fn test_xid_document_preserves_encrypted_keys_when_modified() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid_document =
            XIDDocument::new_with_private_key_base(private_key_base.clone());
        let password = b"secret_password";

        //
        // Create document with encrypted private keys.
        //
        let envelope_encrypted = xid_document.clone().to_unsigned_envelope_opt(
            PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.to_vec(),
            },
        );

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
            .to_unsigned_envelope_opt(PrivateKeyOptions::Include);

        //
        // The encrypted keys should still be there (not decrypted, still encrypted).
        //
        #[rustfmt::skip]
        let format = envelope_after_modification.format();
        assert!(format.contains("ENCRYPTED"));
        assert!(format.contains("hasSecret"));
        assert!(format.contains("dereference"));

        //
        // Load with password - should decrypt the keys.
        //
        let doc_with_password =
            XIDDocument::from_unsigned_envelope_with_password(
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
    fn test_private_key_envelope_for_key() {
        let prvkey_base = PrivateKeyBase::new();
        let doc = XIDDocument::new_with_private_key_base(prvkey_base.clone());
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
    fn test_private_key_envelope_for_key_encrypted() {
        let prvkey_base = PrivateKeyBase::new();
        let password = "test-password";

        // Create document with encrypted key
        let doc = XIDDocument::new_with_private_key_base(prvkey_base.clone());
        let envelope_encrypted =
            doc.to_unsigned_envelope_opt(PrivateKeyOptions::Encrypt {
                method: KeyDerivationMethod::Argon2id,
                password: password.as_bytes().to_vec(),
            });

        let doc_encrypted =
            XIDDocument::from_unsigned_envelope(&envelope_encrypted).unwrap();
        let pubkeys =
            doc_encrypted.inception_key().unwrap().public_keys().clone();

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
        let private_keys =
            PrivateKeys::try_from(decrypted_env.subject()).unwrap();
        assert_eq!(private_keys, prvkey_base.private_keys());

        // With wrong password - should error
        let result =
            doc_encrypted.private_key_envelope_for_key(&pubkeys, Some("wrong"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidPassword));
    }

    #[test]
    fn test_private_key_envelope_for_key_not_found() {
        let prvkey_base = PrivateKeyBase::new();
        let doc = XIDDocument::new_with_private_key_base(prvkey_base.clone());

        // Try to get key that doesn't exist
        let other_pubkeys = PrivateKeyBase::new().public_keys();
        let result = doc
            .private_key_envelope_for_key(&other_pubkeys, None)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_private_key_envelope_for_key_no_private_key() {
        // Create document with public key only
        let pubkeys = PrivateKeyBase::new().public_keys();
        let doc = XIDDocument::new(pubkeys.clone());

        // Should return None (no private key present)
        let result = doc.private_key_envelope_for_key(&pubkeys, None).unwrap();
        assert!(result.is_none());
    }
}
