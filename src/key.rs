use std::collections::HashSet;

use bc_components::{ PublicKeyBase, URI };
use bc_envelope::prelude::*;
use known_values::ENDPOINT;

use super::Permissions;

#[derive(Debug, Clone)]
pub struct Key {
    key: PublicKeyBase,
    endpoints: HashSet<URI>,
    permissions: Permissions,
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Key {}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl Key {
    pub fn new(key: PublicKeyBase) -> Self {
        Self {
            key,
            endpoints: HashSet::new(),
            permissions: Permissions::new(),
        }
    }

    pub fn new_allow_all(key: PublicKeyBase) -> Self {
        Self {
            key,
            endpoints: HashSet::new(),
            permissions: Permissions::new_allow_all(),
        }
    }

    pub fn key(&self) -> &PublicKeyBase {
        &self.key
    }

    pub fn endpoints(&self) -> &HashSet<URI> {
        &self.endpoints
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn endpoints_mut(&mut self) -> &mut HashSet<URI> {
        &mut self.endpoints
    }

    pub fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }
}

impl EnvelopeEncodable for Key {
    fn into_envelope(self) -> Envelope {
        let mut envelope = Envelope::new(self.key);
        envelope = self.endpoints
            .into_iter()
            .fold(envelope, |envelope, endpoint| envelope.add_assertion(ENDPOINT, endpoint));
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<&Envelope> for Key {
    type Error = anyhow::Error;

    fn try_from(envelope: &Envelope) -> Result<Self, Self::Error> {
        let key = PublicKeyBase::try_from(envelope.subject().try_leaf()?)?;
        let mut endpoints = HashSet::new();
        for assertion in envelope.assertions_with_predicate(ENDPOINT) {
            let endpoint = URI::try_from(assertion.try_object()?.subject().try_leaf()?)?;
            endpoints.insert(endpoint);
        }
        let permissions = Permissions::try_from_envelope(envelope)?;
        Ok(Self {
            key,
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
    use crate::Function;
    use indoc::indoc;

    #[test]
    fn test_key() {
        let mut rng = make_fake_random_number_generator();
        let private_key = PrivateKeyBase::new_using(&mut rng);
        let public_key = private_key.schnorr_public_key_base();

        let resolver1 = URI::new("https://resolver.example.com").unwrap();
        let resolver2 = URI::new("btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33").unwrap();
        let resolvers: HashSet<URI> = vec![resolver1, resolver2].into_iter().collect();

        let mut key = Key::new(public_key);
        key.endpoints_mut().extend(resolvers);
        key.permissions_mut().allow_mut().insert(Function::All);
        key.permissions_mut().deny_mut().insert(Function::Verify);

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
