use anyhow::{Error, Result};
use bc_components::{Reference, ReferenceProvider, XID, XIDProvider};
use bc_envelope::prelude::*;

use super::{Permissions, Shared, XIDDocument};
use crate::HasPermissions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegate {
    controller: Shared<XIDDocument>,
    permissions: Permissions,
}

impl std::hash::Hash for Delegate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.controller.read().xid().hash(state);
    }
}

impl Delegate {
    pub fn new(controller: impl AsRef<XIDDocument>) -> Self {
        Self {
            controller: Shared::new(controller.as_ref().clone()),
            permissions: Permissions::new(),
        }
    }

    pub fn controller(&self) -> &Shared<XIDDocument> { &self.controller }
}

impl HasPermissions for Delegate {
    fn permissions(&self) -> &Permissions { &self.permissions }

    fn permissions_mut(&mut self) -> &mut Permissions { &mut self.permissions }
}

impl EnvelopeEncodable for Delegate {
    fn into_envelope(self) -> Envelope {
        let doc = self.controller.read();
        let envelope = doc.clone().into_envelope().wrap();
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<&Envelope> for Delegate {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        let permissions = Permissions::try_from_envelope(envelope)?;
        let inner = envelope.try_unwrap()?;
        let controller = Shared::new(XIDDocument::try_from(inner)?);
        Ok(Self { controller, permissions })
    }
}

impl TryFrom<Envelope> for Delegate {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        Self::try_from(&envelope)
    }
}

impl XIDProvider for Delegate {
    fn xid(&self) -> XID { self.controller.read().xid() }
}

impl ReferenceProvider for Delegate {
    fn reference(&self) -> Reference {
        self.controller.read().xid().reference()
    }
}

#[cfg(test)]
mod tests {
    use bc_components::{PrivateKeyBase, PublicKeysProvider};
    use bc_rand::make_fake_random_number_generator;
    use indoc::indoc;

    use super::*;
    use crate::Privilege;

    #[test]
    fn test_delegate() {
        let mut rng = make_fake_random_number_generator();

        // Create Alice's XIDDocument
        let alice_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let alice_xid_document = XIDDocument::from(&alice_private_key_base);

        let envelope = alice_xid_document.clone().into_envelope();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            XID(71274df1) [
                'key': PublicKeys(eb9b1cae) [
                    'allow': 'All'
                ]
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected);

        // Create Bob's XIDDocument
        let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let bob_public_keys = bob_private_key_base.public_keys();
        let bob_xid_document = XIDDocument::from(bob_public_keys);

        let envelope = bob_xid_document.clone().into_envelope();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            XID(7c30cafe) [
                'key': PublicKeys(b8164d99) [
                    'allow': 'All'
                ]
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected);

        let mut bob_unresolved_delegate =
            Delegate::new(XIDDocument::from_xid(bob_xid_document.xid()));
        bob_unresolved_delegate.add_allow(Privilege::Encrypt);
        bob_unresolved_delegate.add_allow(Privilege::Sign);

        let envelope = bob_unresolved_delegate.clone().into_envelope();
        let bob_unresolved_delegate_2 = Delegate::try_from(&envelope).unwrap();
        assert_eq!(bob_unresolved_delegate, bob_unresolved_delegate_2);

        #[rustfmt::skip]
        let expected = (indoc! {r#"
            {
                XID(7c30cafe)
            } [
                'allow': 'Encrypt'
                'allow': 'Sign'
            ]
        "#}
        ).trim();
        assert_eq!(envelope.format(), expected);

        let mut alice_xid_document_with_unresolved_delegate =
            alice_xid_document.clone();
        alice_xid_document_with_unresolved_delegate
            .add_delegate(bob_unresolved_delegate)
            .unwrap();
        let envelope = alice_xid_document_with_unresolved_delegate
            .clone()
            .into_envelope();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            XID(71274df1) [
                'delegate': {
                    XID(7c30cafe)
                } [
                    'allow': 'Encrypt'
                    'allow': 'Sign'
                ]
                'key': PublicKeys(eb9b1cae) [
                    'allow': 'All'
                ]
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected);

        // Make Bob a Delegate with specific permissions
        let mut bob_delegate = Delegate::new(bob_xid_document);
        bob_delegate.add_allow(Privilege::Encrypt);
        bob_delegate.add_allow(Privilege::Sign);

        let envelope = bob_delegate.clone().into_envelope();
        let bob_delegate_2 = Delegate::try_from(&envelope).unwrap();
        assert_eq!(bob_delegate, bob_delegate_2);

        #[rustfmt::skip]
        let expected = (indoc! {r#"
            {
                XID(7c30cafe) [
                    'key': PublicKeys(b8164d99) [
                        'allow': 'All'
                    ]
                ]
            } [
                'allow': 'Encrypt'
                'allow': 'Sign'
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected);

        // Add Bob as a Delegate to Alice's XIDDocument
        let mut alice_xid_document_with_delegate = alice_xid_document.clone();
        alice_xid_document_with_delegate
            .add_delegate(bob_delegate)
            .unwrap();
        let envelope = alice_xid_document_with_delegate.clone().into_envelope();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            XID(71274df1) [
                'delegate': {
                    XID(7c30cafe) [
                        'key': PublicKeys(b8164d99) [
                            'allow': 'All'
                        ]
                    ]
                } [
                    'allow': 'Encrypt'
                    'allow': 'Sign'
                ]
                'key': PublicKeys(eb9b1cae) [
                    'allow': 'All'
                ]
            ]
        "#}).trim();
        assert_eq!(envelope.format(), expected);
    }
}
