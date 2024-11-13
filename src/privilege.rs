use anyhow::{ bail, Error, Result };
use bc_envelope::prelude::*;
use known_values::{ALL, ALL_RAW, VERIFY, VERIFY_RAW};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Privilege {
    All,
    Verify,
}

impl From<&Privilege> for KnownValue {
    fn from(xid_privilege: &Privilege) -> Self {
        match xid_privilege {
            Privilege::All => ALL,
            Privilege::Verify => VERIFY,
        }
    }
}

impl TryFrom<&KnownValue> for Privilege {
    type Error = Error;

    fn try_from(known_value: &KnownValue) -> Result<Self> {
        match known_value.value() {
            ALL_RAW => Ok(Self::All),
            VERIFY_RAW => Ok(Self::Verify),
            _ => bail!("Unknown XID privilege"),
        }
    }
}

impl From<&Privilege> for Envelope {
    fn from(xid_privilege: &Privilege) -> Self {
        Envelope::new(KnownValue::from(xid_privilege))
    }
}

impl TryFrom<Envelope> for Privilege {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        let subject = envelope.subject();
        let known_value = subject.try_known_value()?;
        Privilege::try_from(known_value)
    }
}

impl EnvelopeEncodable for Privilege {
    fn into_envelope(self) -> Envelope {
        Envelope::from(&self)
    }
}
