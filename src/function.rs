use anyhow::{ bail, Error, Result };
use bc_envelope::prelude::*;
use known_values::{ALL, ALL_RAW, VERIFY, VERIFY_RAW};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Function {
    All,
    Verify,
}

impl From<&Function> for KnownValue {
    fn from(xid_function: &Function) -> Self {
        match xid_function {
            Function::All => ALL,
            Function::Verify => VERIFY,
        }
    }
}

impl TryFrom<&KnownValue> for Function {
    type Error = Error;

    fn try_from(known_value: &KnownValue) -> Result<Self> {
        match known_value.value() {
            ALL_RAW => Ok(Self::All),
            VERIFY_RAW => Ok(Self::Verify),
            _ => bail!("Unknown XID function"),
        }
    }
}

impl From<&Function> for Envelope {
    fn from(xid_function: &Function) -> Self {
        Envelope::new(KnownValue::from(xid_function))
    }
}

impl TryFrom<Envelope> for Function {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        let subject = envelope.subject();
        let known_value = subject.try_known_value()?;
        Function::try_from(known_value)
    }
}

impl EnvelopeEncodable for Function {
    fn into_envelope(self) -> Envelope {
        Envelope::from(&self)
    }
}
