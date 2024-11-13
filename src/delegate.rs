use bc_envelope::prelude::*;
use anyhow::{ Error, Result };

use crate::Privilege;

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

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }

    pub fn add_allow(&mut self, privilege: Privilege) {
        self.permissions.add_allow(privilege);
    }

    pub fn add_deny(&mut self, privilege: Privilege) {
        self.permissions.add_deny(privilege);
    }

    pub fn remove_allow(&mut self, privilege: &Privilege) {
        self.permissions.remove_allow(privilege);
    }

    pub fn remove_deny(&mut self, privilege: &Privilege) {
        self.permissions.remove_deny(privilege);
    }
}

impl EnvelopeEncodable for Delegate {
    fn into_envelope(self) -> Envelope {
        let doc = self.controller.read();
        let envelope = doc.clone().into_envelope();
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<&Envelope> for Delegate {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        let controller = Shared::new(XIDDocument::try_from(envelope)?);
        let permissions = Permissions::try_from_envelope(envelope)?;
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
    use bc_components::{PrivateKeyBase, XID};
    use bc_rand::make_fake_random_number_generator;
    use crate::{Privilege, Key};
    use indoc::indoc;

    #[test]
    fn test_delegate() {
        let mut rng = make_fake_random_number_generator();

        // Create a new XIDDocument
        let private_key_base_1 = PrivateKeyBase::new_using(&mut rng);
        let mut xid_document_1 = XIDDocument::from(&private_key_base_1);
        let xid_envelope_1 = xid_document_1.clone().into_envelope();
        // println!("{}", xid_envelope_1.format());
        let expected = indoc! {r#"
        XID(71274df1) [
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(xid_envelope_1.format(), expected);

        // Remove the genesis key from the XIDDocument
        let genesis_key = xid_document_1.genesis_key().unwrap().clone();
        xid_document_1.remove_key(&genesis_key);
        let xid_envelope_1 = xid_document_1.clone().into_envelope();
        println!("{}", xid_envelope_1.format());
        // let public_key_base = private_key_base.schnorr_public_key_base();
        // let xid = XID::new(public_key_base.signing_public_key());
        // let mut xid_document = XIDDocument::from_xid(xid);

        // let mut key = Key::new(public_key_base);
        // key.add_allow(Privilege::All);
        // key.add_deny(Privilege::Verify);
        // xid_document.add_key(key);

        // let mut delegate = Delegate::new(xid_document);
        // delegate.add_allow(Privilege::All);
        // delegate.add_deny(Privilege::Verify);
        // // xid_document.add_delegate(delegate.clone());

        // let envelope = delegate.clone().into_envelope();
        // let delegate2 = Delegate::try_from(&envelope).unwrap();
        // assert_eq!(delegate, delegate2);

        // println!("{}", envelope.format());
        // let expected = indoc! {r#"
        // PublicKeyBase [
        //     'allow': 'All'
        //     'deny': 'Verify'
        //     'endpoint': URI(btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33)
        //     'endpoint': URI(https://resolver.example.com)
        // ]
        // "#}.trim();
        // assert_eq!(envelope.format(), expected);
    }
}
