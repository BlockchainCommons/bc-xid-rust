use std::collections::HashSet;

use bc_components::{
    EncapsulationPublicKey, PrivateKeys, PrivateKeysProvider, PublicKeys,
    PublicKeysProvider, Reference, ReferenceProvider, Salt, SigningPublicKey,
    URI, Verifier,
};
use bc_envelope::{PrivateKeyBase, prelude::*};
use known_values::{ENDPOINT, NICKNAME, PRIVATE_KEY};

use super::Permissions;
use crate::{Error, HasNickname, HasPermissions, Privilege, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    public_keys: PublicKeys,
    private_keys: Option<(PrivateKeys, Salt)>,
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
            private_keys: Some((private_keys, salt)),
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
        self.private_keys
            .as_ref()
            .map(|(private_keys, _)| private_keys)
    }

    pub fn private_key_salt(&self) -> Option<&Salt> {
        self.private_keys.as_ref().map(|(_, salt)| salt)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PrivateKeyOptions {
    #[default]
    Omit,
    Include,
    Elide,
}

impl Key {
    fn private_key_assertion_envelope(&self) -> Envelope {
        let (private_keys, salt) = self.private_keys.clone().unwrap();
        Envelope::new_assertion(PRIVATE_KEY, private_keys)
            .add_salt_instance(salt)
    }

    fn extract_optional_private_key(
        envelope: &Envelope,
    ) -> Result<Option<(PrivateKeys, Salt)>> {
        if let Some(private_key_assertion) =
            envelope.optional_assertion_with_predicate(PRIVATE_KEY)?
        {
            // println!(
            //     "private_key_assertion: {}",
            //     private_key_assertion.subject().try_object()?.format()
            // );
            let private_keys_cbor =
                private_key_assertion.subject().try_object()?.try_leaf()?;
            let private_keys = PrivateKeys::try_from(private_keys_cbor)?;
            let salt = private_key_assertion
                .extract_object_for_predicate::<Salt>(known_values::SALT)?;
            return Ok(Some((private_keys, salt)));
        }
        Ok(None)
    }

    pub fn into_envelope_opt(
        self,
        private_key_options: PrivateKeyOptions,
    ) -> Envelope {
        let mut envelope = Envelope::new(self.public_keys().clone());
        if self.private_keys.is_some() {
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
                PrivateKeyOptions::Omit => {}
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
        let public_keys = PublicKeys::try_from(envelope.subject().try_leaf()?)?;
        let private_keys = Key::extract_optional_private_key(envelope)?;

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

impl TryFrom<Envelope> for Key {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> { Key::try_from(&envelope) }
}

impl ReferenceProvider for &Key {
    fn reference(&self) -> Reference { self.public_keys.reference() }
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
}
