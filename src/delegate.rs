use bc_components::{Reference, ReferenceProvider, XID, XIDProvider};
use bc_envelope::prelude::*;

use super::{Permissions, Shared, XIDDocument};
use crate::{Error, HasPermissions, Result};

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
