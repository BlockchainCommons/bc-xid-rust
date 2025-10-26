use std::collections::HashSet;

use bc_envelope::prelude::*;
use known_values::{ALLOW, DENY};

use super::Privilege;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    allow: HashSet<Privilege>,
    deny: HashSet<Privilege>,
}

pub trait HasPermissions {
    fn permissions(&self) -> &Permissions;
    fn permissions_mut(&mut self) -> &mut Permissions;

    fn allow(&self) -> &HashSet<Privilege> { &self.permissions().allow }

    fn deny(&self) -> &HashSet<Privilege> { &self.permissions().deny }

    fn allow_mut(&mut self) -> &mut HashSet<Privilege> {
        &mut self.permissions_mut().allow
    }

    fn deny_mut(&mut self) -> &mut HashSet<Privilege> {
        &mut self.permissions_mut().deny
    }

    fn add_allow(&mut self, privilege: Privilege) {
        self.allow_mut().insert(privilege);
    }

    fn add_deny(&mut self, privilege: Privilege) {
        self.deny_mut().insert(privilege);
    }

    fn remove_allow(&mut self, privilege: &Privilege) {
        self.allow_mut().remove(privilege);
    }

    fn remove_deny(&mut self, privilege: &Privilege) {
        self.deny_mut().remove(privilege);
    }

    fn clear_all_permissions(&mut self) {
        self.permissions_mut().allow.clear();
        self.permissions_mut().deny.clear();
    }
}

impl Permissions {
    pub fn new() -> Self {
        Self { allow: HashSet::new(), deny: HashSet::new() }
    }

    pub fn new_allow_all() -> Self {
        let mut allow = HashSet::new();
        allow.insert(Privilege::All);
        Self { allow, deny: HashSet::new() }
    }

    pub fn add_to_envelope(&self, envelope: Envelope) -> Envelope {
        let mut envelope = envelope;
        envelope = self.allow.iter().fold(envelope, |envelope, privilege| {
            envelope.add_assertion(ALLOW, privilege)
        });
        envelope = self.deny.iter().fold(envelope, |envelope, privilege| {
            envelope.add_assertion(DENY, privilege)
        });
        envelope
    }

    pub fn try_from_envelope(envelope: &Envelope) -> Result<Self> {
        let allow = envelope
            .objects_for_predicate(ALLOW)
            .iter()
            .cloned()
            .map(Privilege::try_from)
            .collect::<Result<HashSet<_>>>()?;
        let deny = envelope
            .objects_for_predicate(DENY)
            .iter()
            .cloned()
            .map(Privilege::try_from)
            .collect::<Result<HashSet<_>>>()?;
        Ok(Self { allow, deny })
    }
}

impl HasPermissions for Permissions {
    fn permissions(&self) -> &Permissions { self }

    fn permissions_mut(&mut self) -> &mut Permissions { self }
}

impl Default for Permissions {
    fn default() -> Self { Self::new() }
}
