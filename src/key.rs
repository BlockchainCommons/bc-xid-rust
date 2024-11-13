use std::collections::HashSet;

use bc_components::{ AgreementPublicKey, PublicKeyBase, SigningPublicKey, Verifier, URI };
use bc_envelope::prelude::*;
use known_values::ENDPOINT;

use crate::{HasPermissions, Privilege};

use super::Permissions;

#[derive(Debug, Clone)]
pub struct Key {
    public_key_base: PublicKeyBase,
    endpoints: HashSet<URI>,
    permissions: Permissions,
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.public_key_base == other.public_key_base
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
            endpoints: HashSet::new(),
            permissions: Permissions::new(),
        }
    }

    pub fn new_allow_all(public_key_base: PublicKeyBase) -> Self {
        Self {
            public_key_base,
            endpoints: HashSet::new(),
            permissions: Permissions::new_allow_all(),
        }
    }

    pub fn public_key_base(&self) -> &PublicKeyBase {
        &self.public_key_base
    }

    pub fn signing_public_key(&self) -> &SigningPublicKey {
        self.public_key_base.signing_public_key()
    }

    pub fn agreement_public_key(&self) -> &AgreementPublicKey {
        self.public_key_base.agreement_public_key()
    }

    pub fn endpoints(&self) -> &HashSet<URI> {
        &self.endpoints
    }

    pub fn endpoints_mut(&mut self) -> &mut HashSet<URI> {
        &mut self.endpoints
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
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
}

impl EnvelopeEncodable for Key {
    fn into_envelope(self) -> Envelope {
        let mut envelope = Envelope::new(self.public_key_base);
        envelope = self.endpoints
            .into_iter()
            .fold(envelope, |envelope, endpoint| envelope.add_assertion(ENDPOINT, endpoint));
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<&Envelope> for Key {
    type Error = anyhow::Error;

    fn try_from(envelope: &Envelope) -> Result<Self, Self::Error> {
        let public_key_base = PublicKeyBase::try_from(envelope.subject().try_leaf()?)?;
        let mut endpoints = HashSet::new();
        for assertion in envelope.assertions_with_predicate(ENDPOINT) {
            let endpoint = URI::try_from(assertion.try_object()?.subject().try_leaf()?)?;
            endpoints.insert(endpoint);
        }
        let permissions = Permissions::try_from_envelope(envelope)?;
        Ok(Self {
            public_key_base,
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
        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let public_key_base = private_key_base.schnorr_public_key_base();

        let resolver1 = URI::new("https://resolver.example.com").unwrap();
        let resolver2 = URI::new("btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33").unwrap();
        let resolvers: HashSet<URI> = vec![resolver1, resolver2].into_iter().collect();

        let mut key = Key::new(public_key_base);
        key.endpoints_mut().extend(resolvers);
        key.add_allow(Privilege::All);
        key.add_deny(Privilege::Verify);

        let envelope = key.clone().into_envelope();
        let key2 = Key::try_from(&envelope).unwrap();
        assert_eq!(key, key2);

        assert_eq!(envelope.format(),
        indoc! {r#"
        PublicKeyBase [
            'allow': 'All'
            'deny': 'Verify'
            'endpoint': URI(btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33)
            'endpoint': URI(https://resolver.example.com)
        ]
        "#}.trim());
    }
}
