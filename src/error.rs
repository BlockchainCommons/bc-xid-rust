use thiserror::Error;
use dcbor::prelude::CBORError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("duplicate item: {item}")]
    Duplicate { item: String },

    #[error("item not found: {item}")]
    NotFound { item: String },

    #[error("item is still referenced: {item}")]
    StillReferenced { item: String },

    #[error("invalid or empty value: {field}")]
    EmptyValue { field: String },

    #[error("unknown privilege")]
    UnknownPrivilege,

    #[error("invalid XID")]
    InvalidXid,

    #[error("missing inception key")]
    MissingInceptionKey,

    #[error("invalid resolution method")]
    InvalidResolutionMethod,

    #[error("multiple provenance marks")]
    MultipleProvenanceMarks,

    #[error("unexpected predicate: {predicate}")]
    UnexpectedPredicate { predicate: String },

    #[error("unexpected nested assertions")]
    UnexpectedNestedAssertions,

    #[error("no permissions in service '{uri}'")]
    NoPermissions { uri: String },

    #[error("no key or delegate references in service '{uri}'")]
    NoReferences { uri: String },

    #[error("unknown key reference {reference} in service '{uri}'")]
    UnknownKeyReference { reference: String, uri: String },

    #[error("unknown delegate reference {reference} in service '{uri}'")]
    UnknownDelegateReference { reference: String, uri: String },

    #[error("key not found in XID document: {key}")]
    KeyNotFoundInDocument { key: String },

    #[error("delegate not found in XID document: {delegate}")]
    DelegateNotFoundInDocument { delegate: String },

    #[error("envelope parsing error")]
    EnvelopeParsing(#[from] bc_envelope::Error),

    #[error("component error")]
    Component(#[from] bc_components::Error),

    #[error("CBOR error")]
    Cbor(#[from] CBORError),

    #[error("provenance mark error")]
    ProvenanceMark(#[from] provenance_mark::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
