#![doc(html_root_url = "https://docs.rs/bc-xid/0.20.1")]
#![warn(rust_2018_idioms)]

//! # Introduction
//!
//! XIDs (eXtensible IDentity, */zid/*) are unique 32-byte identifier that
//! represent any entities—real or abstract—such as a person, organization, or
//! device. Generated from the SHA-256 hash of a specific public signing key
//! known as the inception key, a XID provides a stable identity throughout its
//! lifecycle, even as associated keys and permissions evolve. Leveraging
//! Gordian Envelope for XID Documents, XIDs are recursively resolvable and
//! extensible, allowing for detailed assertions about the entity, including key
//! declarations, permissions, controllers, and endpoints. The integration of
//! [provenance marks](https://provemark.com) ensures a verifiable chain of
//! document revisions, enhancing security and authenticity in decentralized
//! identity management.
//!
//! # Getting Started
//!
//! ```toml
//! [dependencies]
//! bc-xid = "0.20.1"
//! ```
//!
//! # Examples
//!
//! See the unit tests in the source code for examples of how to use this
//! library.

mod error;
pub use error::{Error, Result};

mod privilege;
pub use privilege::*;

mod xid_document;
pub use xid_document::*;

mod shared;
pub use shared::*;

mod permissions;
pub use permissions::*;

mod key;
pub use key::*;

mod provenance;
pub use provenance::*;

mod service;
pub use service::*;

mod delegate;
pub use delegate::*;

mod name;
pub use name::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_readme_deps() {
        version_sync::assert_markdown_deps_updated!("README.md");
    }

    #[test]
    fn test_html_root_url() {
        version_sync::assert_html_root_url_updated!("src/lib.rs");
    }
}
