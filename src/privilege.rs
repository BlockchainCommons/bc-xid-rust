use anyhow::{Error, Result, bail};
use bc_envelope::prelude::*;
use known_values::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Privilege {
    /// Allow all applicable XID operations
    All,

    //
    // Operational Functions
    /// Authenticate as the subject (e.g., log into services)
    Auth,

    /// Sign digital communications as the subject
    Sign,

    /// Encrypt messages from the subject
    Encrypt,

    /// Elide data under the subject's control
    Elide,

    /// Issue or revoke verifiable credentials on the subject's authority
    Issue,

    /// Access resources under the subject's control
    Access,

    //
    // Management Functions
    /// Delegate priviledges to third parties
    Delegate,

    /// Verify (update) the XID document
    Verify,

    /// Update service endpoints
    Update,

    /// Remove the inception key from the XID document
    Transfer,

    /// Add or remove other verifiers (rotate keys)
    Elect,

    /// Transition to a new provenance mark chain
    Burn,

    /// Revoke the XID entirely
    Revoke,
}

impl From<&Privilege> for KnownValue {
    fn from(xid_privilege: &Privilege) -> Self {
        match xid_privilege {
            Privilege::All => PRIVILEGE_ALL,
            Privilege::Auth => PRIVILEGE_AUTH,
            Privilege::Sign => PRIVILEGE_SIGN,
            Privilege::Encrypt => PRIVILEGE_ENCRYPT,
            Privilege::Elide => PRIVILEGE_ELIDE,
            Privilege::Issue => PRIVILEGE_ISSUE,
            Privilege::Access => PRIVILEGE_ACCESS,

            Privilege::Delegate => PRIVILEGE_DELEGATE,
            Privilege::Verify => PRIVILEGE_VERIFY,
            Privilege::Update => PRIVILEGE_UPDATE,
            Privilege::Transfer => PRIVILEGE_TRANSFER,
            Privilege::Elect => PRIVILEGE_ELECT,
            Privilege::Burn => PRIVILEGE_BURN,
            Privilege::Revoke => PRIVILEGE_REVOKE,
        }
    }
}

impl TryFrom<&KnownValue> for Privilege {
    type Error = Error;

    fn try_from(known_value: &KnownValue) -> Result<Self> {
        match known_value.value() {
            PRIVILEGE_ALL_RAW => Ok(Self::All),
            PRIVILEGE_AUTH_RAW => Ok(Self::Auth),
            PRIVILEGE_SIGN_RAW => Ok(Self::Sign),
            PRIVILEGE_ENCRYPT_RAW => Ok(Self::Encrypt),
            PRIVILEGE_ELIDE_RAW => Ok(Self::Elide),
            PRIVILEGE_ISSUE_RAW => Ok(Self::Issue),
            PRIVILEGE_ACCESS_RAW => Ok(Self::Access),

            PRIVILEGE_DELEGATE_RAW => Ok(Self::Delegate),
            PRIVILEGE_VERIFY_RAW => Ok(Self::Verify),
            PRIVILEGE_UPDATE_RAW => Ok(Self::Update),
            PRIVILEGE_TRANSFER_RAW => Ok(Self::Transfer),
            PRIVILEGE_ELECT_RAW => Ok(Self::Elect),
            PRIVILEGE_BURN_RAW => Ok(Self::Burn),
            PRIVILEGE_REVOKE_RAW => Ok(Self::Revoke),

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
    fn into_envelope(self) -> Envelope { Envelope::from(&self) }
}
