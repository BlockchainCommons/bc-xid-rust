use bc_components::{KeyDerivationMethod, Salt};
use bc_envelope::prelude::*;
use known_values::PROVENANCE_GENERATOR;
use provenance_mark::{ProvenanceMark, ProvenanceMarkGenerator};

use crate::{Error, Result};

/// Provenance mark generator data that can be either decrypted or encrypted.
#[derive(Debug, Clone)]
pub enum GeneratorData {
    /// Decrypted generator that can be used for mark generation.
    Decrypted(ProvenanceMarkGenerator),

    /// Encrypted generator envelope that cannot be used without decryption.
    /// This preserves the encrypted assertion when a document is loaded
    /// without the decryption password.
    ///
    /// Note: Envelope uses internal reference counting (Rc/Arc) so cloning
    /// is cheap - no need for additional wrapper.
    Encrypted(Envelope),
}

impl PartialEq for GeneratorData {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Decrypted(a), Self::Decrypted(b)) => a == b,
            (Self::Encrypted(a), Self::Encrypted(b)) => {
                // Compare envelopes by their UR string representation
                a.ur_string() == b.ur_string()
            }
            _ => false,
        }
    }
}

impl Eq for GeneratorData {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    mark: ProvenanceMark,
    generator: Option<(GeneratorData, Salt)>,
}

impl Provenance {
    pub fn new(mark: ProvenanceMark) -> Self { Self { mark, generator: None } }

    pub fn new_with_generator(
        generator: ProvenanceMarkGenerator,
        mark: ProvenanceMark,
    ) -> Self {
        let salt = Salt::new_with_len(32).unwrap();
        Self {
            mark,
            generator: Some((GeneratorData::Decrypted(generator), salt)),
        }
    }

    pub fn mark(&self) -> &ProvenanceMark { &self.mark }

    pub fn generator(&self) -> Option<&ProvenanceMarkGenerator> {
        self.generator.as_ref().and_then(|(data, _)| match data {
            GeneratorData::Decrypted(generator) => Some(generator),
            GeneratorData::Encrypted(_) => None,
        })
    }

    pub fn has_generator(&self) -> bool {
        matches!(
            self.generator.as_ref(),
            Some((GeneratorData::Decrypted(_), _))
        )
    }

    pub fn has_encrypted_generator(&self) -> bool {
        matches!(
            self.generator.as_ref(),
            Some((GeneratorData::Encrypted(_), _))
        )
    }

    pub fn generator_salt(&self) -> Option<&Salt> {
        self.generator.as_ref().map(|(_, salt)| salt)
    }

    /// Extract the generator data as an Envelope, optionally decrypting it.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if no generator is present
    /// - `Ok(Some(Envelope))` containing:
    ///   - Decrypted `ProvenanceMarkGenerator` if unencrypted
    ///   - Decrypted `ProvenanceMarkGenerator` if encrypted and correct
    ///     password provided
    ///   - Encrypted envelope if encrypted and no password provided
    /// - `Err(...)` if encrypted and wrong password provided
    pub fn generator_envelope(
        &self,
        password: Option<&str>,
    ) -> Result<Option<Envelope>> {
        match &self.generator {
            None => Ok(None),
            Some((GeneratorData::Decrypted(generator), _)) => {
                // Unencrypted generator - return as envelope
                Ok(Some(Envelope::new(generator.clone())))
            }
            Some((GeneratorData::Encrypted(encrypted_envelope), _)) => {
                if let Some(pwd) = password {
                    // Try to decrypt with provided password
                    match encrypted_envelope.clone().unlock_subject(pwd) {
                        Ok(decrypted) => {
                            // Successfully decrypted and unwrapped
                            let unwrapped = decrypted.try_unwrap()?;
                            Ok(Some(unwrapped))
                        }
                        Err(_) => {
                            // Wrong password
                            Err(Error::InvalidPassword)
                        }
                    }
                } else {
                    // No password provided, return encrypted envelope as-is
                    Ok(Some(encrypted_envelope.clone()))
                }
            }
        }
    }
}

/// Options for handling generators in envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum MarkGeneratorOptions {
    /// Omit the generator from the envelope (default).
    #[default]
    Omit,

    /// Include the generator in plaintext (with salt for decorrelation).
    Include,

    /// Include the generator assertion but elide it (maintains digest tree).
    Elide,

    /// Include the generator encrypted with a password using the specified
    /// key derivation method.
    Encrypt {
        method: KeyDerivationMethod,
        password: Vec<u8>,
    },
}

impl Provenance {
    fn generator_assertion_envelope(&self) -> Envelope {
        let (generator_data, salt) = self.generator.clone().unwrap();
        match generator_data {
            GeneratorData::Decrypted(generator) => {
                Envelope::new_assertion(PROVENANCE_GENERATOR, generator)
                    .add_salt_instance(salt)
            }
            GeneratorData::Encrypted(encrypted_envelope) => {
                // Already encrypted, just wrap with provenanceGenerator
                // predicate and salt
                Envelope::new_assertion(
                    PROVENANCE_GENERATOR,
                    encrypted_envelope,
                )
                .add_salt_instance(salt)
            }
        }
    }

    fn extract_optional_generator_with_password(
        envelope: &Envelope,
        password: Option<&[u8]>,
    ) -> Result<Option<(GeneratorData, Salt)>> {
        if let Some(generator_assertion) =
            envelope.optional_assertion_with_predicate(PROVENANCE_GENERATOR)?
        {
            let generator_object =
                generator_assertion.subject().try_object()?;

            // Extract the salt (always present)
            let salt = generator_assertion
                .extract_object_for_predicate::<Salt>(known_values::SALT)?;

            // Check if the generator object is locked with a password
            if generator_object.is_locked_with_password() {
                // Need a password to decrypt
                if let Some(pwd) = password {
                    // Try to unlock with the password
                    match generator_object.unlock_subject(pwd) {
                        Ok(decrypted) => {
                            // Successfully decrypted, unwrap and extract the
                            // generator
                            let unwrapped = decrypted.try_unwrap()?;
                            let generator =
                                ProvenanceMarkGenerator::try_from(unwrapped)?;
                            return Ok(Some((
                                GeneratorData::Decrypted(generator),
                                salt,
                            )));
                        }
                        Err(_) => {
                            // Wrong password or decryption failed
                            // Store the encrypted envelope for later
                            return Ok(Some((
                                GeneratorData::Encrypted(
                                    generator_object.clone(),
                                ),
                                salt,
                            )));
                        }
                    }
                } else {
                    // No password provided, store encrypted envelope
                    return Ok(Some((
                        GeneratorData::Encrypted(generator_object.clone()),
                        salt,
                    )));
                }
            }

            // Extract plaintext generator
            let generator =
                ProvenanceMarkGenerator::try_from(generator_object.clone())?;
            return Ok(Some((GeneratorData::Decrypted(generator), salt)));
        }
        Ok(None)
    }

    pub fn into_envelope_opt(
        self,
        generator_options: MarkGeneratorOptions,
    ) -> Envelope {
        let mut envelope = Envelope::new(self.mark().clone());
        if let Some((generator_data, _)) = &self.generator {
            match generator_data {
                GeneratorData::Encrypted(_) => {
                    // Always preserve encrypted generators, regardless of
                    // options
                    let assertion_envelope =
                        self.generator_assertion_envelope();
                    envelope = envelope
                        .add_assertion_envelope(assertion_envelope)
                        .unwrap();
                }
                GeneratorData::Decrypted(_) => {
                    // For decrypted generators, respect the generator_options
                    match generator_options {
                        MarkGeneratorOptions::Include => {
                            let assertion_envelope =
                                self.generator_assertion_envelope();
                            envelope = envelope
                                .add_assertion_envelope(assertion_envelope)
                                .unwrap();
                        }
                        MarkGeneratorOptions::Elide => {
                            let assertion_envelope =
                                self.generator_assertion_envelope().elide();
                            envelope = envelope
                                .add_assertion_envelope(assertion_envelope)
                                .unwrap();
                        }
                        MarkGeneratorOptions::Encrypt { method, password } => {
                            let (generator, salt) =
                                self.generator.clone().unwrap();

                            match generator {
                                GeneratorData::Decrypted(generator) => {
                                    // Create an envelope with the generator
                                    let generator_envelope =
                                        Envelope::new(generator);

                                    // Wrap and encrypt it using lock_subject
                                    let encrypted = generator_envelope
                                        .wrap()
                                        .lock_subject(method, password)
                                        .expect("Failed to encrypt generator");

                                    // Create the provenanceGenerator assertion
                                    // with the encrypted envelope
                                    let assertion_envelope =
                                        Envelope::new_assertion(
                                            PROVENANCE_GENERATOR,
                                            encrypted,
                                        )
                                        .add_salt_instance(salt);

                                    envelope = envelope
                                        .add_assertion_envelope(
                                            assertion_envelope,
                                        )
                                        .unwrap();
                                }
                                GeneratorData::Encrypted(
                                    encrypted_envelope,
                                ) => {
                                    // Already encrypted - we can't re-encrypt
                                    // without decrypting first. Just preserve
                                    // the
                                    // existing encrypted envelope.
                                    let assertion_envelope =
                                        Envelope::new_assertion(
                                            PROVENANCE_GENERATOR,
                                            encrypted_envelope,
                                        )
                                        .add_salt_instance(salt);

                                    envelope = envelope
                                        .add_assertion_envelope(
                                            assertion_envelope,
                                        )
                                        .unwrap();
                                }
                            }
                        }
                        MarkGeneratorOptions::Omit => {
                            // Omit decrypted generators
                        }
                    }
                }
            }
        }

        envelope
    }
}

impl EnvelopeEncodable for Provenance {
    fn into_envelope(self) -> Envelope {
        self.into_envelope_opt(MarkGeneratorOptions::Omit)
    }
}

impl TryFrom<&Envelope> for Provenance {
    type Error = Error;

    fn try_from(envelope: &Envelope) -> Result<Self> {
        Self::try_from_envelope(envelope, None)
    }
}

impl TryFrom<Envelope> for Provenance {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        Provenance::try_from(&envelope)
    }
}

impl Provenance {
    /// Try to extract a `Provenance` from an envelope, optionally providing a
    /// password to decrypt an encrypted generator.
    ///
    /// If the generator is encrypted and no password is provided, the
    /// `Provenance` will be created without the generator (it will be
    /// `None`).
    pub fn try_from_envelope(
        envelope: &Envelope,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let mark = ProvenanceMark::try_from(envelope.subject().try_leaf()?)?;
        let generator = Provenance::extract_optional_generator_with_password(
            envelope, password,
        )?;

        Ok(Self { mark, generator })
    }
}
