use std::collections::HashSet;

use anyhow::{ bail, Error, Result };
use bc_components::{ tags, Encrypter, PrivateKeyBase, PublicKeyBase, Signer, SigningPublicKey, Verifier, URI, XID };
use dcbor::CBOREncodable;
use bc_ur::prelude::*;
use known_values::{DELEGATE, DEREFERENCE_VIA, KEY, PROVENANCE};
use provenance_mark::ProvenanceMark;
use bc_envelope::prelude::*;

use crate::PrivateKeyOptions;

use super::{Delegate, Key};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XIDDocument {
    xid: XID,
    resolution_methods: HashSet<URI>,
    keys: HashSet<Key>,
    delegates: HashSet<Delegate>,
    provenance: Option<ProvenanceMark>,
}

impl XIDDocument {
    pub fn new(inception_public_key: PublicKeyBase) -> Self {
        let xid = XID::new(inception_public_key.signing_public_key());
        let inception_key = Key::new_allow_all(inception_public_key);
        let mut keys = HashSet::new();
        keys.insert(inception_key.clone());
        Self {
            xid,
            resolution_methods: HashSet::new(),
            keys,
            delegates: HashSet::new(),
            provenance: None,
        }
    }

    pub fn new_with_private_key(inception_private_key: PrivateKeyBase) -> Self {
        let inception_public_key = inception_private_key.schnorr_public_key_base();
        let xid = XID::new(inception_public_key.signing_public_key());
        let inception_key = Key::new_with_private_key(inception_private_key);
        let mut keys = HashSet::new();
        keys.insert(inception_key.clone());
        Self {
            xid,
            resolution_methods: HashSet::new(),
            keys,
            delegates: HashSet::new(),
            provenance: None,
        }
    }

    pub fn new_with_provenance(inception_public_key: PublicKeyBase, provenance: ProvenanceMark) -> Self {
        let mut doc = Self::new(inception_public_key);
        doc.provenance = Some(provenance);
        doc
    }

    pub fn from_xid(xid: impl Into<XID>) -> Self {
        Self {
            xid: xid.into(),
            resolution_methods: HashSet::new(),
            keys: HashSet::new(),
            delegates: HashSet::new(),
            provenance: None,
        }
    }

    pub fn xid(&self) -> &XID {
        &self.xid
    }

    pub fn resolution_methods(&self) -> &HashSet<URI> {
        &self.resolution_methods
    }

    pub fn resolution_methods_mut(&mut self) -> &mut HashSet<URI> {
        &mut self.resolution_methods
    }

    pub fn keys(&self) -> &HashSet<Key> {
        &self.keys
    }

    pub fn keys_mut(&mut self) -> &mut HashSet<Key> {
        &mut self.keys
    }

    pub fn add_key(&mut self, key: Key) {
        self.keys.insert(key);
    }

    pub fn find_key_by_public_key_base(&self, key: &PublicKeyBase) -> Option<&Key> {
        self.keys.iter().find(|k| k.public_key_base() == key)
    }

    pub fn remove_key(&mut self, key: &Key) -> Option<Key> {
        let public_key_base = key.public_key_base();
        if let Some(key) = self.find_key_by_public_key_base(public_key_base).cloned() {
            self.keys.take(&key)
        } else {
            None
        }
    }

    pub fn is_inception_signing_key(&self, signing_public_key: &SigningPublicKey) -> bool {
        self.xid.validate(signing_public_key)
    }

    pub fn inception_signing_key(&self) -> Option<&SigningPublicKey> {
        if let Some(key) = self.keys.iter().find(|k| {
            self.is_inception_signing_key(k.public_key_base().signing_public_key())
        }) {
            return Some(key.public_key_base().signing_public_key());
        } else {
            None
        }
    }

    pub fn verification_key(&self) -> Option<&dyn Verifier> {
        self.inception_signing_key().map(|key| key as &dyn Verifier)
    }

    pub fn encryption_key(&self) -> Option<&dyn Encrypter> {
        if let Some(key) = self.keys.iter().find(|k| {
            self.is_inception_signing_key(k.public_key_base().signing_public_key())
        }) {
            return Some(key.public_key_base().agreement_public_key());
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.resolution_methods.is_empty() && self.keys.is_empty() && self.delegates.is_empty() && self.provenance.is_none()
    }

    pub fn delegates(&self) -> &HashSet<Delegate> {
        &self.delegates
    }

    pub fn delegates_mut(&mut self) -> &mut HashSet<Delegate> {
        &mut self.delegates
    }

    pub fn add_delegate(&mut self, delegate: Delegate) {
        self.delegates.insert(delegate);
    }

    pub fn find_delegate(&self, xid: &XID) -> Option<&Delegate> {
        self.delegates.iter().find(|d| d.controller().read().xid() == xid)
    }

    pub fn remove_delegate(&mut self, xid: &XID) -> Option<Delegate> {
        if let Some(delegate) = self.find_delegate(xid).cloned() {
            self.delegates.take(&delegate)
        } else {
            None
        }
    }

    pub fn provenance(&self) -> Option<&ProvenanceMark> {
        self.provenance.as_ref()
    }

    pub fn set_provenance(&mut self, provenance: Option<ProvenanceMark>) {
        self.provenance = provenance;
    }

    fn to_unsigned_envelope(&self) -> Envelope {
        self.to_unsigned_envelope_opt(PrivateKeyOptions::default())
    }

    fn to_unsigned_envelope_opt(&self, private_key_options: PrivateKeyOptions) -> Envelope {
        let mut envelope = Envelope::new(self.xid.clone());

        // Add an assertion for each resolution method.
        envelope = self.resolution_methods.iter().cloned().fold(envelope, |envelope, method| envelope.add_assertion(DEREFERENCE_VIA, method));

        // Add an assertion for each key in the set.
        envelope = self.keys.iter().cloned().fold(envelope, |envelope, key| envelope.add_assertion(KEY, key.into_envelope_opt(private_key_options)));

        // Add an assertion for each delegate.
        envelope = self.delegates.iter().cloned().fold(envelope, |envelope, delegate| envelope.add_assertion(DELEGATE, delegate));

        // Add the provenance mark if any.
        if let Some(provenance) = &self.provenance {
            envelope = envelope.add_assertion(PROVENANCE, provenance.clone());
        }

        envelope
    }

    fn from_unsigned_envelope(envelope: &Envelope) -> Result<Self> {
        let xid: XID = envelope.subject().try_leaf()?.try_into()?;

        let resolution_methods = envelope.extract_objects_for_predicate::<URI>(DEREFERENCE_VIA)?.into_iter().collect::<HashSet<_>>();

        let keys = envelope.objects_for_predicate(KEY).into_iter().map(|key| key.try_into()).collect::<Result<HashSet<_>>>()?;

        let delegates = envelope.object_for_predicate(DELEGATE).into_iter().map(|delegate| delegate.try_into()).collect::<Result<HashSet<_>>>()?;

        let provenance = match envelope.optional_object_for_predicate(PROVENANCE)? {
            Some(p) => Some(ProvenanceMark::try_from(p)?),
            None => None,
        };

        Ok(Self {
            xid,
            resolution_methods,
            keys,
            delegates,
            provenance,
        })
    }

    pub fn to_signed_envelope(&self, signing_key: &impl Signer) -> Envelope {
        self.to_signed_envelope_opt(signing_key, PrivateKeyOptions::default())
    }

    pub fn to_signed_envelope_opt(&self, signing_key: &impl Signer, private_key_options: PrivateKeyOptions) -> Envelope {
        self.to_unsigned_envelope_opt(private_key_options).sign(signing_key)
    }

    pub fn try_from_signed_envelope(signed_envelope: &Envelope) -> Result<Self> {
        // Unwrap the envelope and construct a provisional XIDDocument.
        let xid_document = XIDDocument::try_from(&signed_envelope.unwrap_envelope()?)?;
        // Extract the inception key from the provisional XIDDocument, throwing an error if it is missing.
        let inception_key = xid_document.inception_signing_key().ok_or_else(|| Error::msg("Missing inception key"))?;
        // Verify the signature on the envelope using the inception key.
        signed_envelope.verify(inception_key)?;
        // Extract the XID from the provisional XIDDocument.
        let xid = xid_document.xid();
        // Verify that the inception key is the one that generated the XID.
        if xid.validate(inception_key) {
            // If the inception key is valid return the XIDDocument, now verified.
            Ok(xid_document)
        } else {
            bail!("Invalid XID")
        }
    }
}

impl AsRef<XIDDocument> for XIDDocument {
    fn as_ref(&self) -> &XIDDocument {
        self
    }
}

impl From<XIDDocument> for XID {
    fn from(doc: XIDDocument) -> Self {
        doc.xid
    }
}

impl From<XID> for XIDDocument {
    fn from(xid: XID) -> Self {
        XIDDocument::from_xid(xid)
    }
}

impl From<&XID> for XIDDocument {
    fn from(xid: &XID) -> Self {
        XIDDocument::from_xid(xid.clone())
    }
}

impl From<PublicKeyBase> for XIDDocument {
    fn from(inception_key: PublicKeyBase) -> Self {
        XIDDocument::new(inception_key)
    }
}

impl From<&PrivateKeyBase> for XIDDocument {
    fn from(inception_key: &PrivateKeyBase) -> Self {
        XIDDocument::new(inception_key.schnorr_public_key_base())
    }
}

impl EnvelopeEncodable for XIDDocument {
    fn into_envelope(self) -> Envelope {
        self.to_unsigned_envelope()
    }
}

impl TryFrom<&Envelope> for XIDDocument {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        Self::from_unsigned_envelope(envelope)
    }
}

impl TryFrom<Envelope> for XIDDocument {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        XIDDocument::try_from(&envelope)
    }
}

impl CBORTagged for XIDDocument {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_XID])
    }
}

impl From<XIDDocument> for CBOR {
    fn from(value: XIDDocument) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for XIDDocument {
    fn untagged_cbor(&self) -> CBOR {
        if self.is_empty() {
            return self.xid.untagged_cbor();
        }
        self.to_envelope().to_cbor()
    }
}

impl TryFrom<CBOR> for XIDDocument {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for XIDDocument {
    fn from_untagged_cbor(cbor: CBOR) -> Result<Self> {
        if let Some(byte_string) = cbor.clone().into_byte_string() {
            let xid = XID::from_data_ref(byte_string)?;
            return Ok(Self::from_xid(xid));
        }

        Envelope::try_from(cbor)?.try_into()
    }
}

#[cfg(test)]
mod tests {
    use bc_envelope::prelude::*;
    use bc_rand::make_fake_random_number_generator;
    use indoc::indoc;
    use bc_components::{tags, PrivateKeyBase, XID};
    use provenance_mark::{ProvenanceMarkGenerator, ProvenanceMarkResolution, ProvenanceSeed};

    use crate::{PrivateKeyOptions, XIDDocument};

    #[test]
    fn test_xid_document() {
        // Create a XID document.
        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid_document = XIDDocument::from(&private_key_base);

        // Extract the XID from the XID document.
        let xid = xid_document.xid();

        // Convert the XID document to an Envelope.
        let envelope = xid_document.clone().into_envelope();
        let expected_format = indoc! {r#"
        XID(71274df1) [
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected_format);

        // Convert the Envelope back to a XIDDocument.
        let xid_document2 = XIDDocument::try_from(envelope).unwrap();
        assert_eq!(xid_document, xid_document2);

        // Convert the XID document to a UR
        let xid_document_ur = xid_document.ur_string();
        assert_eq!(xid_document_ur, "ur:xid/tpsplftpsotanshdhdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnoyaylftpsotansgylftanshfhdcxhslkfzemaylrwttynsdlghrydpmdfzvdglndloimaahykorefddtsguogmvlahqztansgrhdcxetlewzvlwyfdtobeytidosbamkswaomwwfyabakssakggegychesmerkcatekpcxoycsfncsfggmplgshd");
        let xid_document2 = XIDDocument::from_ur_string(&xid_document_ur).unwrap();
        assert_eq!(xid_document, xid_document2);

        // Print the document's XID in debug format, which shows the full
        // identifier.
        let xid_debug = format!("{:?}", xid);
        assert_eq!(xid_debug, "XID(71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c)");

        // Print the document's XID in display format, which shows the short
        // identifier (first 4 bytes).
        let xid_display = format!("{}", xid);
        assert_eq!(xid_display, "XID(71274df1)");

        // Print the CBOR diagnostic notation for the XID.
        let xid_cbor_diagnostic = xid.to_cbor().diagnostic();
        assert_eq!(xid_cbor_diagnostic, indoc! {r#"
        40024(
            h'71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c'
        )
        "#}.trim());

        // Print the hex encoding of the XID.
        with_tags!(|tags: &dyn dcbor::TagsStoreTrait| {
            assert_eq!(tags.name_for_value(tags::TAG_XID), "xid");
        });

        let xid_cbor_hex = xid.to_cbor().hex_annotated();
        assert_eq!(xid_cbor_hex, indoc! {r#"
        d9 9c58                                 # tag(40024) xid
            5820                                # bytes(32)
                71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c
        "#}.trim());

        // Print the XID's Bytewords and Bytemoji identifiers.
        let bytewords_identifier = xid.bytewords_identifier(true);
        assert_eq!(bytewords_identifier, "🅧 JUGS DELI GIFT WHEN");
        let bytemoji_identifier = xid.bytemoji_identifier(true);
        assert_eq!(bytemoji_identifier, "🅧 🌊 😹 🌽 🐞");

        // Print the XID's LifeHash fingerprint.
        assert_eq!(format!("{}", xid.lifehash_fingerprint()), "Digest(fc7b562825afa07ee9d49fe99991f767ad4bdad495724c08a918e13ee0eabd5e)");

        // Print the XID's UR.
        let xid_ur = xid.ur_string();
        assert_eq!(xid_ur, "ur:xid/hdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnvsbyrdfw");
        let xid2 = XID::from_ur_string(&xid_ur).unwrap();
        assert_eq!(xid, &xid2);
    }

    #[test]
    fn test_minimal_xid_document() {
        // Create a XID.
        let mut rng = make_fake_random_number_generator();
        let private_key_base = PrivateKeyBase::new_using(&mut rng);
        let xid = XID::from(&private_key_base);

        // Create a XIDDocument directly from the XID.
        let xid_document = XIDDocument::from(&xid);

        // Convert the XIDDocument to an Envelope.
        let envelope = xid_document.clone().into_envelope();

        // The envelope is just the XID as its subject, with no assertions.
        let expected_format = indoc! {r#"
        XID(71274df1)
        "#}.trim();
        assert_eq!(envelope.format(), expected_format);

        // Convert the Envelope back to a XIDDocument.
        let xid_document2 = XIDDocument::try_from(envelope).unwrap();
        assert_eq!(xid_document, xid_document2);

        // The CBOR encoding of the XID and the XIDDocument should be the same.
        let xid_cbor = xid.to_cbor();
        let xid_document_cbor = xid_document.to_cbor();
        assert_eq!(xid_cbor, xid_document_cbor);

        // Either a XID or a XIDDocument can be created from the CBOR encoding.
        let xid2 = XID::try_from(xid_cbor).unwrap();
        assert_eq!(xid, xid2);
        let xid_document2 = XIDDocument::try_from(xid_document_cbor).unwrap();
        assert_eq!(xid_document, xid_document2);

        // The UR of the XID and the XIDDocument should be the same.
        let xid_ur = xid.ur_string();
        let expected_ur = "ur:xid/hdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnvsbyrdfw";
        assert_eq!(xid_ur, expected_ur);
        let xid_document_ur = xid_document.ur_string();
        assert_eq!(xid_document_ur, expected_ur);
    }

    #[test]
    fn test_signed_xid_document() {
        // Generate the inception key.
        let mut rng = make_fake_random_number_generator();
        let private_inception_key = PrivateKeyBase::new_using(&mut rng);

        // Create a XIDDocument for the inception key.
        let xid_document = XIDDocument::from(&private_inception_key);

        let envelope = xid_document.clone().into_envelope();
        let expected_format = indoc! {r#"
        XID(71274df1) [
            'key': PublicKeyBase [
                'allow': 'All'
            ]
        ]
        "#}.trim();
        assert_eq!(envelope.format(), expected_format);

        let signed_envelope = xid_document.to_signed_envelope(&private_inception_key);
        // println!("{}", signed_envelope.format());
        let expected_format = indoc! {r#"
        {
            XID(71274df1) [
                'key': PublicKeyBase [
                    'allow': 'All'
                ]
            ]
        } [
            'signed': Signature
        ]
        "#}.trim();
        assert_eq!(signed_envelope.format(), expected_format);

        let self_certified_xid_document = XIDDocument::try_from_signed_envelope(&signed_envelope).unwrap();
        assert_eq!(xid_document, self_certified_xid_document);
    }

    #[test]
    fn test_with_provenance() {
        provenance_mark::register_tags();

        let mut rng = make_fake_random_number_generator();
        let private_inception_key = PrivateKeyBase::new_using(&mut rng);
        let inception_key = private_inception_key.schnorr_public_key_base();

        let genesis_seed = ProvenanceSeed::new_using(&mut rng);

        let mut generator = ProvenanceMarkGenerator::new_with_seed(ProvenanceMarkResolution::Quartile, genesis_seed);
        let date = dcbor::Date::from_string("2025-01-01").unwrap();
        let provenance = generator.next(date, None::<String>);
        let xid_document = XIDDocument::new_with_provenance(inception_key, provenance);
        let signed_envelope = xid_document.to_signed_envelope(&private_inception_key);
        let expected_format = indoc! {r#"
            {
                XID(71274df1) [
                    'key': PublicKeyBase [
                        'allow': 'All'
                    ]
                    'provenance': ProvenanceMark(4bf5c551)
                ]
            } [
                'signed': Signature
            ]
        "#}.trim();
        assert_eq!(signed_envelope.format(), expected_format);

        let self_certified_xid_document = XIDDocument::try_from_signed_envelope(&signed_envelope).unwrap();
        assert_eq!(xid_document, self_certified_xid_document);
    }

    #[test]
    fn test_with_private_key() {
        let mut rng = make_fake_random_number_generator();
        let private_inception_key = PrivateKeyBase::new_using(&mut rng);
        let public_inception_key = private_inception_key.schnorr_public_key_base();

        //
        // A `XIDDocument` can be created from a private key, in which case it
        // will include the private key.
        //

        let xid_document_including_private_key = XIDDocument::new_with_private_key(private_inception_key.clone());

        //
        // By default, the `Envelope` representation of a `XIDDocument` will
        // omit the private key.
        //

        let signed_envelope_omitting_private_key = xid_document_including_private_key.to_signed_envelope(&private_inception_key);
        let expected_format = indoc! {r#"
            {
                XID(71274df1) [
                    'key': PublicKeyBase [
                        'allow': 'All'
                    ]
                ]
            } [
                'signed': Signature
            ]
        "#}.trim();
        assert_eq!(signed_envelope_omitting_private_key.format(), expected_format);
        let xid_document2 = XIDDocument::try_from_signed_envelope(&signed_envelope_omitting_private_key).unwrap();

        //
        // A `XIDDocument` can be created from a public key, in which case its
        // `Envelope` representation is identical to the default representation.
        //

        let xid_document_excluding_private_key = XIDDocument::new(public_inception_key);
        assert_eq!(xid_document_excluding_private_key, xid_document2);

        //
        // The private key can be included in the `Envelope` by explicitly
        // specifying that it should be included.
        //
        // The 'privateKey' assertion is salted to decorrelate the the private key.
        //

        let signed_envelope_including_private_key = xid_document_including_private_key.to_signed_envelope_opt(&private_inception_key, PrivateKeyOptions::Include);
        let expected_format = indoc! {r#"
            {
                XID(71274df1) [
                    'key': PublicKeyBase [
                        {
                            'privateKey': PrivateKeyBase
                        } [
                            'salt': Salt
                        ]
                        'allow': 'All'
                    ]
                ]
            } [
                'signed': Signature
            ]
        "#}.trim();
        assert_eq!(signed_envelope_including_private_key.format(), expected_format);

        //
        // If the private key is included, the `XIDDocument` is reconstructed
        // with it and is exactly the same as the original.
        //

        let xid_document2 = XIDDocument::try_from_signed_envelope(&signed_envelope_including_private_key).unwrap();
        assert_eq!(xid_document_including_private_key, xid_document2);

        //
        // The private key assertion can be elided.
        //

        let signed_document_eliding_private_key = xid_document_including_private_key.to_signed_envelope_opt(&private_inception_key, PrivateKeyOptions::Elide);
        let expected_format = indoc! {r#"
            {
                XID(71274df1) [
                    'key': PublicKeyBase [
                        'allow': 'All'
                        ELIDED
                    ]
                ]
            } [
                'signed': Signature
            ]
        "#}.trim();
        assert_eq!(signed_document_eliding_private_key.format(), expected_format);

        //
        // A `XIDDocument` reconstructed from an envelope with the private key
        // elided is the same as the `XIDDocument` created from only the public key.
        //

        let xid_document2 = XIDDocument::try_from_signed_envelope(&signed_document_eliding_private_key).unwrap();
        assert_eq!(xid_document_excluding_private_key, xid_document2);
    }
}
