use std::collections::HashSet;

use bc_envelope::prelude::*;
use anyhow::{ Error, Result };

use crate::{HasPermissions, Privilege};

use super::{ Shared, XIDDocument, Permissions };

#[derive(Debug, Clone)]
pub struct Delegate {
    controller: Shared<XIDDocument>,
    permissions: Permissions,
}

impl PartialEq for Delegate {
    fn eq(&self, other: &Self) -> bool {
        self.controller.read().xid() == other.controller.read().xid()
    }
}

impl Eq for Delegate {}

impl std::hash::Hash for Delegate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.controller.read().xid().hash(state);
    }
}

impl Delegate {
    pub fn new(controller: XIDDocument) -> Self {
        Self {
            controller: Shared::new(controller),
            permissions: Permissions::new(),
        }
    }

    pub fn controller(&self) -> &Shared<XIDDocument> {
        &self.controller
    }
}

impl HasPermissions for Delegate {
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

impl EnvelopeEncodable for Delegate {
    fn into_envelope(self) -> Envelope {
        let doc = self.controller.read();
        let envelope = if doc.is_empty() {
            doc.clone().into_envelope()
        } else {
            doc.clone().into_envelope().wrap_envelope()
        };
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<&Envelope> for Delegate {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        let permissions = Permissions::try_from_envelope(envelope)?;
        let inner = if envelope.subject().is_wrapped() {
            envelope.unwrap_envelope()?
        } else {
            envelope.clone()
        };
        let controller = Shared::new(XIDDocument::try_from(inner)?);
        Ok(Self {
            controller,
            permissions,
        })
    }
}

impl TryFrom<Envelope> for Delegate {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        Self::try_from(&envelope)
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
    fn test_delegate() {
        let mut rng = make_fake_random_number_generator();

        // Create Alice's XIDDocument
        let alice_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let alice_xid_document = XIDDocument::from(&alice_private_key_base);

        let envelope = alice_xid_document.clone().into_envelope();
        let expected = indoc! {r#"
        XID(71274df1) [
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);

        // Create Bob's XIDDocument
        let bob_private_key_base = PrivateKeyBase::new_using(&mut rng);
        let bob_xid_document = XIDDocument::from(&bob_private_key_base);

        let envelope = bob_xid_document.clone().into_envelope();
        let expected = indoc! {r#"
        XID(7c30cafe) [
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);

        let mut bob_unresolved_delegate = Delegate::new(XIDDocument::from_xid(bob_xid_document.xid()));
        bob_unresolved_delegate.add_deny(Privilege::All);
        bob_unresolved_delegate.add_allow(Privilege::Encrypt);
        bob_unresolved_delegate.add_allow(Privilege::Sign);

        let envelope = bob_unresolved_delegate.clone().into_envelope();
        let bob_unresolved_delegate_2 = Delegate::try_from(&envelope).unwrap();
        assert_eq!(bob_unresolved_delegate, bob_unresolved_delegate_2);

        let expected = indoc! {r#"
        XID(7c30cafe) [
            'allow': 'Encrypt'
            'allow': 'Sign'
            'deny': 'All'
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);

        let mut alice_xid_document_with_unresolved_delegate = alice_xid_document.clone();
        alice_xid_document_with_unresolved_delegate.add_delegate(bob_unresolved_delegate);
        let envelope = alice_xid_document_with_unresolved_delegate.clone().into_envelope();
        let expected = indoc! {r#"
        XID(71274df1) [
            'delegate': XID(7c30cafe) [
                'allow': 'Encrypt'
                'allow': 'Sign'
                'deny': 'All'
            ]
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);

        // Make Bob a Delegate with specific permissions
        let mut bob_delegate = Delegate::new(bob_xid_document);
        bob_delegate.add_deny(Privilege::All);
        bob_delegate.add_allow(Privilege::Encrypt);
        bob_delegate.add_allow(Privilege::Sign);

        let envelope = bob_delegate.clone().into_envelope();
        let bob_delegate_2 = Delegate::try_from(&envelope).unwrap();
        assert_eq!(bob_delegate, bob_delegate_2);

        let expected = indoc! {r#"
        {
            XID(7c30cafe) [
                'key': PublicKeyBase [
                    'allow': 'All'
                ]
            ]
        } [
            'allow': 'Encrypt'
            'allow': 'Sign'
            'deny': 'All'
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);

        // Add Bob as a Delegate to Alice's XIDDocument
        let mut alice_xid_document_with_delegate = alice_xid_document.clone();
        alice_xid_document_with_delegate.add_delegate(bob_delegate);
        let envelope = alice_xid_document_with_delegate.clone().into_envelope();
        let expected = indoc! {r#"
        XID(71274df1) [
            'delegate': {
                XID(7c30cafe) [
                    'key': PublicKeyBase [
                        'allow': 'All'
                    ]
                ]
            } [
                'allow': 'Encrypt'
                'allow': 'Sign'
                'deny': 'All'
            ]
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected);
    }
}

        // // Remove the inception key from Alice's XIDDocument
        // let alice_inception_key = alice_xid_document.inception_key().unwrap().clone();
        // alice_xid_document.remove_key(&alice_inception_key);
        // assert!(alice_xid_document.inception_key().is_none());
        // assert!(alice_xid_document.keys().is_empty());
        // assert!(alice_xid_document.is_empty());

        // let envelope = alice_xid_document.clone().into_envelope();
        // let expected = indoc! {r#"
        // XID(71274df1)
        // "#}.trim();
        // assert_eq!(envelope.format(), expected);
