use std::collections::HashSet;
use anyhow::Result;

use bc_components::{ AgreementPublicKey, PrivateKeyBase, PublicKeyBase, Salt, SigningPublicKey, Verifier, URI };
use bc_envelope::prelude::*;
use known_values::{ENDPOINT, PRIVATE_KEY, NAME};

use crate::{HasPermissions, Privilege};

use super::Permissions;

#[derive(Debug, Clone)]
pub struct Key {
    public_key_base: PublicKeyBase,
    private_key_base: Option<(PrivateKeyBase, Salt)>,
    name: String,
    endpoints: HashSet<URI>,
    permissions: Permissions,
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.public_key_base == other.public_key_base &&
        self.private_key_base == other.private_key_base &&
        self.name == other.name &&
        self.endpoints == other.endpoints &&
        self.permissions == other.permissions
    }
}

impl Verifier for Key {
    fn verify(&self, signature: &bc_components::Signature, message: &dyn AsRef<[u8]>) -> bool {
        self.public_key_base.verify(signature, message)
    }
}

impl Eq for Key {}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_key_base.hash(state);
    }
}

impl Key {
    pub fn new(public_key_base: PublicKeyBase) -> Self {
        Self {
            public_key_base,
            private_key_base: None,
            name: String::new(),
            endpoints: HashSet::new(),
            permissions: Permissions::new(),
        }
    }

    pub fn new_allow_all(public_key_base: PublicKeyBase) -> Self {
        Self {
            public_key_base,
            private_key_base: None,
            name: String::new(),
            endpoints: HashSet::new(),
            permissions: Permissions::new_allow_all(),
        }
    }

    pub fn new_with_private_key(private_key_base: PrivateKeyBase) -> Self {
        let public_key_base = private_key_base.schnorr_public_key_base();
        let salt = Salt::new_for_size(private_key_base.to_cbor_data().len());
        Self {
            public_key_base,
            private_key_base: Some((private_key_base, salt)),
            name: String::new(),
            endpoints: HashSet::new(),
            permissions: Permissions::new_allow_all(),
        }
    }

    pub fn public_key_base(&self) -> &PublicKeyBase {
        &self.public_key_base
    }

    pub fn private_key_base(&self) -> Option<&PrivateKeyBase> {
        self.private_key_base.as_ref().map(|(private_key_base, _)| private_key_base)
    }

    pub fn private_key_salt(&self) -> Option<&Salt> {
        self.private_key_base.as_ref().map(|(_, salt)| salt)
    }

    pub fn signing_public_key(&self) -> &SigningPublicKey {
        self.public_key_base.signing_public_key()
    }

    pub fn agreement_public_key(&self) -> &AgreementPublicKey {
        self.public_key_base.agreement_public_key()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
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

impl HasPermissions for Key {
    fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }

    fn allow(&self) -> &HashSet<Privilege> {
        self.permissions.allow()
    }

    fn deny(&self) -> &HashSet<Privilege> {
        self.permissions.deny()
    }

    fn allow_mut(&mut self) -> &mut HashSet<Privilege> {
        self.permissions.allow_mut()
    }

    fn deny_mut(&mut self) -> &mut HashSet<Privilege> {
        self.permissions.deny_mut()
    }

    fn add_allow(&mut self, privilege: Privilege) {
        self.permissions.add_allow(privilege);
    }

    fn add_deny(&mut self, privilege: Privilege) {
        self.permissions.add_deny(privilege);
    }

    fn remove_allow(&mut self, privilege: &Privilege) {
        self.permissions.remove_allow(privilege);
    }

    fn remove_deny(&mut self, privilege: &Privilege) {
        self.permissions.remove_deny(privilege);
    }

    fn clear_all_permissions(&mut self) {
        self.permissions.clear_all_permissions();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PrivateKeyOptions {
    #[default]
    Omit,
    Include,
    Elide,
}

impl Key {
    fn private_key_assertion_envelope(&self) -> Envelope {
        let (private_key_base, salt) = self.private_key_base.clone().unwrap();
        Envelope::new_assertion(PRIVATE_KEY, private_key_base)
            .add_salt_instance(salt)
    }

    fn extract_optional_private_key(envelope: &Envelope) -> Result<Option<(PrivateKeyBase, Salt)>> {
        if let Some(private_key_assertion) = envelope.optional_assertion_with_predicate(PRIVATE_KEY)? {
            let private_key_base_cbor = private_key_assertion.subject().try_object()?.try_leaf()?;
            let private_key_base = PrivateKeyBase::try_from(private_key_base_cbor)?;
            let salt = private_key_assertion.extract_object_for_predicate::<Salt>(known_values::SALT)?;
            return Ok(Some((private_key_base, salt)));
        }
        Ok(None)
    }

    pub fn into_envelope_opt(self, private_key_options: PrivateKeyOptions) -> Envelope {
        let mut envelope = Envelope::new(self.public_key_base().clone());
            if self.private_key_base.is_some() {
                match private_key_options {
                    PrivateKeyOptions::Include => {
                        let assertion_envelope = self.private_key_assertion_envelope();
                        envelope = envelope.add_assertion_envelope(assertion_envelope).unwrap();
                    }
                    PrivateKeyOptions::Elide => {
                        let assertion_envelope = self.private_key_assertion_envelope().elide();
                        envelope = envelope.add_assertion_envelope(assertion_envelope).unwrap();
                    }
                    PrivateKeyOptions::Omit => {}
                }
            }

        if !self.name.is_empty() {
            envelope = envelope.add_assertion(known_values::NAME, self.name);
        }

        envelope = self.endpoints
            .into_iter()
            .fold(envelope, |envelope, endpoint| envelope.add_assertion(ENDPOINT, endpoint));

        self.permissions.add_to_envelope(envelope)
    }
}

impl EnvelopeEncodable for Key {
    fn into_envelope(self) -> Envelope {
        self.into_envelope_opt(PrivateKeyOptions::Omit)
    }
}

impl TryFrom<&Envelope> for Key {
    type Error = anyhow::Error;

    fn try_from(envelope: &Envelope) -> Result<Self, Self::Error> {
        let public_key_base = PublicKeyBase::try_from(envelope.subject().try_leaf()?)?;
        let private_key_base = Key::extract_optional_private_key(envelope)?;

        let name = envelope.extract_object_for_predicate_with_default(NAME, String::new())?;

        let mut endpoints = HashSet::new();
        for assertion in envelope.assertions_with_predicate(ENDPOINT) {
            let endpoint = URI::try_from(assertion.try_object()?.subject().try_leaf()?)?;
            endpoints.insert(endpoint);
        }
        let permissions = Permissions::try_from_envelope(envelope)?;
        Ok(Self {
            public_key_base,
            private_key_base,
            name,
            endpoints,
            permissions,
        })
    }
}

impl TryFrom<Envelope> for Key {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> Result<Self, Self::Error> {
        Key::try_from(&envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_components::PrivateKeyBase;
    use bc_rand::make_fake_random_number_generator;
    use crate::Privilege;
    use indoc::indoc;

    #[test]
    fn test_key() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let public_key_base = private_key_base.schnorr_public_key_base();

        let resolver1 = URI::new("https://resolver.example.com").unwrap();
        let resolver2 = URI::new("btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33").unwrap();
        let resolvers: HashSet<URI> = vec![resolver1, resolver2].into_iter().collect();

        let mut key = Key::new(public_key_base);
        key.endpoints_mut().extend(resolvers);
        key.add_allow(Privilege::All);
        key.set_name("Alice's key".to_string());

        let envelope = key.clone().into_envelope();
        let key2 = Key::try_from(&envelope).unwrap();
        assert_eq!(key, key2);

        assert_eq!(envelope.format(),
        indoc! {r#"
        PublicKeyBase [
            'allow': 'All'
            'endpoint': URI(btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33)
            'endpoint': URI(https://resolver.example.com)
            'name': "Alice's key"
        ]
        "#}.trim());
    }

    #[test]
    fn test_with_private_key() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);

        //
        // A `Key` can be constructed from a `PrivateKeyBase` implicitly gets
        // all permissions.
        //

        let key_including_private_key = Key::new_with_private_key(private_key_base.clone());

        //
        // Permissions given to a `Key` constructed from a `PublicKeyBase` are
        // explicit.
        //

        let key_omitting_private_key = Key::new_allow_all(private_key_base.schnorr_public_key_base());

        //
        // When converting to an `Envelope`, the default is to omit the private
        // key because it is sensitive.
        //

        let envelope_omitting_private_key = key_including_private_key.clone()
            .into_envelope();

        assert_eq!(envelope_omitting_private_key.format(),
        indoc! {r#"
            PublicKeyBase [
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

        let envelope_including_private_key = key_including_private_key.clone()
            .into_envelope_opt(PrivateKeyOptions::Include);

        assert_eq!(envelope_including_private_key.format(),
        indoc! {r#"
            PublicKeyBase [
                {
                    'privateKey': PrivateKeyBase
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

        let envelope_eliding_private_key = key_including_private_key.clone()
            .into_envelope_opt(PrivateKeyOptions::Elide);

        assert_eq!(envelope_eliding_private_key.format(),
        indoc! {r#"
            PublicKeyBase [
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
        // The elided envelope has the same root hash as the envelope including the private key,
        // affording inclusion proofs.
        //

        assert!(envelope_eliding_private_key.is_equivalent_to(&envelope_including_private_key));
    }
}
