use std::collections::HashSet;

use anyhow::Result;
use bc_envelope::prelude::*;
use known_values::{ALLOW, DENY};

use super::Function;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    allow: HashSet<Function>,
    deny: HashSet<Function>,
}

impl Permissions {
    pub fn new() -> Self {
        Self {
            allow: HashSet::new(),
            deny: HashSet::new(),
        }
    }

    pub fn new_allow_all() -> Self {
        let mut allow = HashSet::new();
        allow.insert(Function::All);
        Self {
            allow,
            deny: HashSet::new(),
        }
    }

    pub fn allow(&self) -> &HashSet<Function> {
        &self.allow
    }

    pub fn deny(&self) -> &HashSet<Function> {
        &self.deny
    }

    pub fn allow_mut(&mut self) -> &mut HashSet<Function> {
        &mut self.allow
    }

    pub fn deny_mut(&mut self) -> &mut HashSet<Function> {
        &mut self.deny
    }

    pub fn add_to_envelope(&self, envelope: Envelope) -> Envelope {
        let mut envelope = envelope;
        envelope = self.allow.iter().fold(envelope, |envelope, function| envelope.add_assertion(ALLOW, function));
        envelope = self.deny.iter().fold(envelope, |envelope, function| envelope.add_assertion(DENY, function));
        envelope
    }

    pub fn try_from_envelope(envelope: &Envelope) -> Result<Self> {
        let allow = envelope.objects_for_predicate(ALLOW).iter().cloned().map(Function::try_from).collect::<Result<HashSet<_>>>()?;
        let deny = envelope.objects_for_predicate(DENY).iter().cloned().map(Function::try_from).collect::<Result<HashSet<_>>>()?;
        Ok(Self { allow, deny })
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn permissions() {
        let mut permissions = Permissions::new();
        assert!(permissions.allow().is_empty());
        assert!(permissions.deny().is_empty());

        permissions.allow_mut().insert(Function::All);
        permissions.deny_mut().insert(Function::Verify);

        let envelope = permissions.add_to_envelope(Envelope::new("Subject"));
        let permissions2 = Permissions::try_from_envelope(&envelope).unwrap();
        assert_eq!(permissions, permissions2);

        assert_eq!(envelope.format(),
        indoc! {r#"
        "Subject" [
            'allow': 'All'
            'deny': 'Verify'
        ]
        "#}.trim());
    }
}
