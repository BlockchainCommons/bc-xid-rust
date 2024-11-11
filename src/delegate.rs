use bc_envelope::prelude::*;
use anyhow::{ Error, Result };

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

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn permissions_mut(&mut self) -> &mut Permissions {
        &mut self.permissions
    }

    pub fn controller(&self) -> &Shared<XIDDocument> {
        &self.controller
    }
}

impl EnvelopeEncodable for Delegate {
    fn into_envelope(self) -> Envelope {
        let doc = self.controller.read();
        let envelope = doc.clone().into_envelope();
        self.permissions.add_to_envelope(envelope)
    }
}

impl TryFrom<Envelope> for Delegate {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        let controller = Shared::new(XIDDocument::try_from(&envelope)?);
        let permissions = Permissions::try_from_envelope(&envelope)?;
        Ok(Self {
            controller,
            permissions,
        })
    }
}
