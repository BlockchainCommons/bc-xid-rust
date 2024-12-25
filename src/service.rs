use std::collections::HashSet;

use bc_components::{ PublicKeyBaseProvider, Reference, ReferenceProvider, XIDProvider, URI };
use bc_envelope::{ extension::{ ALLOW_RAW, CAPABILITY, CAPABILITY_RAW, DELEGATE, DELEGATE_RAW, KEY, KEY_RAW, NAME, NAME_RAW }, Envelope, EnvelopeEncodable };
use anyhow::{Error, Result, bail};

use crate::{ HasName, HasPermissions, Permissions, Privilege };

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    uri: URI,
    key_references: HashSet<Reference>,
    delegate_references: HashSet<Reference>,
    permissions: Permissions,
    capability: String,
    name: String,
}

impl std::hash::Hash for Service {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uri.hash(state);
    }
}

impl Service {
    pub fn new(uri: impl AsRef<URI>) -> Self {
        Self {
            uri: uri.as_ref().clone(),
            key_references: HashSet::new(),
            delegate_references: HashSet::new(),
            permissions: Permissions::new(),
            capability: String::new(),
            name: String::new(),
        }
    }

    pub fn uri(&self) -> &URI {
        &self.uri
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn set_capability(&mut self, capability: impl Into<String>) {
        self.capability = capability.into();
    }

    pub fn add_capability(&mut self, capability: &str) -> Result<()> {
        if !self.capability.is_empty() {
            bail!("Duplicate capability");
        }
        if capability.is_empty() {
            bail!("Capability is empty");
        }
        self.set_capability(capability);

        Ok(())
    }

    pub fn key_references(&self) -> &HashSet<Reference> {
        &self.key_references
    }

    pub fn key_referenecs_mut(&mut self) -> &mut HashSet<Reference> {
        &mut self.key_references
    }

    pub fn add_key_reference(&mut self, key_reference: impl AsRef<Reference>) -> Result<()> {
        if !self.key_references.contains(key_reference.as_ref()) {
            self.key_references.insert(key_reference.as_ref().clone());
        } else {
            bail!("Key already exists");
        }

        Ok(())
    }

    pub fn add_key(&mut self, key: &dyn PublicKeyBaseProvider) -> Result<()> {
        self.add_key_reference(key.public_key_base().reference())
    }

    pub fn delegate_references(&self) -> &HashSet<Reference> {
        &self.delegate_references
    }

    pub fn delegate_references_mut(&mut self) -> &mut HashSet<Reference> {
        &mut self.delegate_references
    }

    pub fn add_delegate_reference(&mut self, delegate_reference: impl AsRef<Reference>) -> Result<()> {
        if !self.delegate_references.contains(delegate_reference.as_ref()) {
            self.delegate_references.insert(delegate_reference.as_ref().clone());
        } else {
            bail!("Delegate already exists");
        }

        Ok(())
    }

    pub fn add_delegate(&mut self, delegate: &dyn XIDProvider) -> Result<()> {
        self.add_delegate_reference(delegate.xid().reference())
    }
}

impl HasName for Service {
    fn name(&self) -> &str {
        &self.name
    }

    fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }
}

impl HasPermissions for Service {
    fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }
}

impl EnvelopeEncodable for Service {
    fn into_envelope(self) -> bc_envelope::Envelope {
        let mut envelope = Envelope::new(self.uri);

        envelope = self.key_references
            .iter()
            .cloned()
            .fold(envelope, |envelope, key| envelope.add_assertion(KEY, key));

        envelope = self.delegate_references
            .iter()
            .cloned()
            .fold(envelope, |envelope, delegate| envelope.add_assertion(DELEGATE, delegate));

        envelope = envelope.add_nonempty_string_assertion(CAPABILITY, self.capability);
        envelope = envelope.add_nonempty_string_assertion(NAME, self.name);
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<Envelope> for Service {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self, Self::Error> {
        Self::try_from(&envelope)
    }
}

impl TryFrom<&Envelope> for Service {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self, Self::Error> {
        let uri: URI = envelope.subject().try_leaf()?.try_into()?;

        let mut service = Service::new(uri);

        for assertion in envelope.assertions() {
            let predicate = assertion.try_predicate()?.try_known_value()?.value();
            let object = assertion.try_object()?;
            if object.has_assertions() {
                bail!("Unexpected nested assertions");
            }
            match predicate {
                KEY_RAW => {
                    let key = Reference::try_from(object.try_leaf()?)?;
                    service.add_key_reference(key)?;
                },
                DELEGATE_RAW => {
                    let delegate = Reference::try_from(object.try_leaf()?)?;
                    service.add_delegate_reference(delegate)?;
                },
                CAPABILITY_RAW => {
                    let capability = object.try_leaf()?.try_into_text()?;
                    service.add_capability(&capability)?;
                },
                NAME_RAW => {
                    let name = object.try_leaf()?.try_into_text()?;
                    service.add_name(&name)?;
                },
                ALLOW_RAW => {
                    service.add_allow(Privilege::try_from(object)?);
                },
                _ => bail!("Unexpected predicate: {}", predicate),
            }
        }

        Ok(service)
    }
}

#[cfg(test)]
mod tests {
    use bc_components::{PublicKeyBaseProvider, URI};
    use bc_envelope::{EnvelopeEncodable, PrivateKeyBase};
    use bc_rand::make_fake_random_number_generator;

    use crate::{HasName, HasPermissions, Privilege, XIDDocument};

    use super::Service;

    #[test]
    fn test_1() {
        bc_envelope::register_tags();

        let mut rng = make_fake_random_number_generator();

        let alice_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let alice_public_key_base = alice_private_key_base.public_key_base();

        let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let bob_public_key_base = bob_private_key_base.public_key_base();
        let bob_xid_document = XIDDocument::new(bob_public_key_base);

        let mut service = Service::new(URI::try_from("https://example.com").unwrap());

        service.add_key(&alice_public_key_base).unwrap();
        assert!(service.add_key(&alice_public_key_base).is_err());

        service.add_delegate(&bob_xid_document).unwrap();
        assert!(service.add_delegate(&bob_xid_document).is_err());

        service.add_allow(Privilege::Encrypt);
        service.add_allow(Privilege::Sign);

        service.add_name("Example Service").unwrap();
        assert!(service.add_name("Example Service").is_err());

        service.add_capability("com.example.messaging").unwrap();
        assert!(service.add_capability("com.example.messaging").is_err());

        let envelope = service.to_envelope();
        let expected = indoc::indoc! {r#"
            URI(https://example.com) [
                'allow': 'Encrypt'
                'allow': 'Sign'
                'capability': "com.example.messaging"
                'delegate': Reference(7c30cafe)
                'key': Reference(eb9b1cae)
                'name': "Example Service"
            ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);

        let service2 = Service::try_from(&envelope).unwrap();
        assert_eq!(service, service2);
    }
}
