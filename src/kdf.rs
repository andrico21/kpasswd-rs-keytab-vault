//! The Argon2id key derivation: its parameters, the band an unlock honours,
//! the backend trait, and the one place a `argon2::Params` is built.
//!
//! The band check lives here because this is the one place a serialized block
//! becomes `argon2::Params`, and it runs before that construction and before
//! any derivation - an attacker-supplied block must cost a comparison, not an
//! allocation.

use zeroize::Zeroizing;

use crate::format::{
    ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN, ARGON2_PARALLELISM, ARGON2_VERSION,
    EnvelopeError, KDF_BLOCK_LEN, KDF_SALT_END, KDF_SALT_START, KEK_LEN, Malformed, SALT_LEN,
};

/// Argon2id cost parameters for a passphrase slot.
///
/// [`Argon2idParams::defaults`] is RFC 9106 §4's SECOND RECOMMENDED set:
/// 64 MiB, t=3, p=4. The FIRST RECOMMENDED set (2 GiB, t=1, p=4) has no
/// constructor, because 2 GiB per unlock is a decision for the deployment;
/// pass the numbers to [`Argon2idParams::new`] if you want it.
///
/// [`Argon2idParams::new`] refuses anything below a floor of 8 MiB, t=1, p=1,
/// so a weak setting can't be reached by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Argon2idParams {
    /// Memory cost, in Kib.
    memory_kib: u32,
    /// Iterations.
    iterations: u32,
    /// Parallelism.
    parallelism: u32,
}

impl Argon2idParams {
    /// RFC 9106 §4's SECOND RECOMMENDED set: 64 MiB, t=3, p=4.
    ///
    /// The default cost of a passphrase slot, and what `Kdf::default()` uses.
    #[must_use]
    #[inline]
    pub const fn defaults() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        }
    }

    /// The weakest parameters a seal will write.
    ///
    /// A floor rather than a guideline: an envelope is a secret's wrapper, and
    /// a caller that wants something cheaper than this is asking for a weaker
    /// one, which this crate does not offer by accident.
    #[must_use]
    pub(crate) const fn floor() -> Self {
        Self {
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Parameters from their parts: memory in KiB, iterations and lanes.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::DerivationFailed` when the values are below the floor of
    /// 8 MiB, t=1, p=1, or outside what Argon2 accepts.
    #[inline]
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, EnvelopeError> {
        let candidate = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        if !candidate.is_at_or_above_floor() {
            return Err(EnvelopeError::DerivationFailed);
        }
        // Argon2's own rules decide the rest: the floor is the crate's, the
        // validity is the algorithm's.
        let _: argon2::Params =
            argon2::Params::new(memory_kib, iterations, parallelism, Some(ARGON2_OUTPUT_LEN))
                .map_err(|_parameter_error| EnvelopeError::DerivationFailed)?;
        Ok(candidate)
    }

    /// Memory cost, in Kib.
    #[must_use]
    pub(crate) const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Iterations.
    #[must_use]
    pub(crate) const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Parallelism.
    #[must_use]
    pub(crate) const fn parallelism(self) -> u32 {
        self.parallelism
    }

    /// Whether every value is at or above the floor.
    #[must_use]
    pub(crate) const fn is_at_or_above_floor(self) -> bool {
        let floor = Self::floor();
        self.memory_kib >= floor.memory_kib
            && self.iterations >= floor.iterations
            && self.parallelism >= floor.parallelism
    }

    /// Whether these are exactly the format's constants.
    ///
    /// One format has no version to choose, so this is now only what
    /// [`KdfLimits::is_defaults`] asks it: whether a band is the exact band.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn is_defaults(self) -> bool {
        self.memory_kib == ARGON2_MEMORY_KIB
            && self.iterations == ARGON2_ITERATIONS
            && self.parallelism == ARGON2_PARALLELISM
    }
}

/// The KDF an envelope slot uses. One variant today; non-exhaustive so a second
/// is additive - adding one touches this enum, the seal path and the block
/// encoder, and nothing that calls them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kdf {
    /// Argon2id, with the parameters the caller names.
    Argon2id(Argon2idParams),
}

impl Kdf {
    /// The parameters this KDF carries.
    #[must_use]
    pub(crate) const fn params(self) -> Argon2idParams {
        match self {
            Self::Argon2id(params) => params,
        }
    }
}

impl Default for Kdf {
    #[inline]
    fn default() -> Self {
        Self::Argon2id(Argon2idParams::defaults())
    }
}

/// The band an *unlock* will honour from an envelope's own parameter block.
///
/// A resource guard over untrusted input in one direction and a strength guard
/// in the other - not a preference. `defaults()` accepts exactly the format's
/// constants and nothing else, which is the behaviour this format has always
/// had; a wider band is something a caller asks for by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct KdfLimits {
    /// The weakest parameters an envelope may declare.
    minimum: Argon2idParams,
    /// The strongest parameters an envelope may declare.
    maximum: Argon2idParams,
}

impl KdfLimits {
    /// Accepts exactly the format's parameters, and nothing else.
    #[must_use]
    #[inline]
    pub const fn defaults() -> Self {
        Self {
            minimum: Argon2idParams::defaults(),
            maximum: Argon2idParams::defaults(),
        }
    }

    /// A band, not a ceiling.
    ///
    /// A ceiling alone would be a hole: an envelope declaring one iteration and
    /// 8 KiB sits comfortably under any ceiling, so a passphrase slot could be
    /// presented for derivation at negligible cost. The **floor** is the half
    /// that protects the secret; the ceiling is the half that protects the host.
    /// # Errors
    ///
    /// `EnvelopeError::DerivationFailed` when `minimum` is above `maximum`, which
    /// is not a band, or when either is below `Argon2idParams::floor`.
    #[inline]
    pub const fn between(
        minimum: Argon2idParams,
        maximum: Argon2idParams,
    ) -> Result<Self, EnvelopeError> {
        if !minimum.is_at_or_above_floor() || !maximum.is_at_or_above_floor() {
            return Err(EnvelopeError::DerivationFailed);
        }
        if minimum.memory_kib > maximum.memory_kib
            || minimum.iterations > maximum.iterations
            || minimum.parallelism > maximum.parallelism
        {
            return Err(EnvelopeError::DerivationFailed);
        }
        Ok(Self { minimum, maximum })
    }

    /// Whether `params` is inside the band.
    #[must_use]
    pub(crate) const fn admits(self, params: Argon2idParams) -> bool {
        params.memory_kib >= self.minimum.memory_kib
            && params.memory_kib <= self.maximum.memory_kib
            && params.iterations >= self.minimum.iterations
            && params.iterations <= self.maximum.iterations
            && params.parallelism >= self.minimum.parallelism
            && params.parallelism <= self.maximum.parallelism
    }

    /// Whether this band is exactly the default band.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn is_defaults(self) -> bool {
        self.minimum.is_defaults() && self.maximum.is_defaults()
    }
}

/// Derives a KEK from a passphrase.
///
/// A trait, not a free function, so a test can inject a backend that fails
/// loudly if it is ever reached: that turns "a raw-key unlock never derives"
/// from a timing observation into an assertion. Fallible and named for the
/// one algorithm it performs, because a narrower signature could only panic
/// on Argon2's own parameter errors.
pub trait KdfBackend {
    /// Derive a 32-byte KEK from `passphrase`, using the Argon2id parameters
    /// carried in `block`.
    /// # Errors
    ///
    /// `EnvelopeError::DerivationFailed` when the block's parameters cannot be
    /// constructed or the derivation fails. Fallible rather than panicking so
    /// that a test backend can fail loudly; the format's parameters do not
    /// fail in practice.
    fn derive_argon2id(
        &self,
        passphrase: &[u8],
        block: &[u8; KDF_BLOCK_LEN],
        limits: &KdfLimits,
    ) -> Result<Zeroizing<[u8; KEK_LEN]>, EnvelopeError>;
}

/// The real backend: Argon2id at the parameters the selected slot carries.
///
/// Exhaustive on purpose: it is a zero-field handle, so there is nothing for a
/// future version to add without changing what it *is* - a unit struct with
/// `#[non_exhaustive]` would be unconstructible instead.
#[expect(
    clippy::exhaustive_structs,
    reason = "zero fields: there is no future field to add, and a non-exhaustive unit struct cannot be constructed at all"
)]
#[derive(Clone, Copy, Debug)]
pub struct Argon2Kdf;

impl KdfBackend for Argon2Kdf {
    #[inline]
    fn derive_argon2id(
        &self,
        passphrase: &[u8],
        block: &[u8; KDF_BLOCK_LEN],
        limits: &KdfLimits,
    ) -> Result<Zeroizing<[u8; KEK_LEN]>, EnvelopeError> {
        // The band is checked here, before Argon2 is constructed: an
        // out-of-band block costs a comparison rather than an allocation.
        let params = decode_argon2_block(block, limits)?;
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut kek = Zeroizing::new([0; KEK_LEN]);
        argon2
            .hash_password_into(passphrase, salt_from_block(block), &mut *kek)
            .map_err(|_derivation_error| EnvelopeError::DerivationFailed)?;
        Ok(kek)
    }
}

/// The salt carried by a serialized Argon2 block.
pub(crate) fn salt_from_block(block: &[u8; KDF_BLOCK_LEN]) -> &[u8] {
    block
        .get(KDF_SALT_START..KDF_SALT_END)
        .unwrap_or(&block[..SALT_LEN])
}

/// Decode and validate a serialized Argon2 block into parameters.
///
/// Reached only for a *selected* passphrase slot, or when sealing: an
/// unselected slot's parameter values are never inspected, so another
/// slot's parameters cannot cost a derivation or a parameter check.
/// Read a slot's parameter block, applying the band the caller allows.
///
/// **The band check precedes the derivation**: an envelope is attacker-supplied
/// input, and a block declaring 4 GiB of memory cost must cost a comparison
/// rather than an allocation. The floor half is the one that protects the
/// secret - a slot declaring one iteration would otherwise be presented for
/// derivation at negligible cost - and the ceiling half protects the host.
///
/// The version this checks is the **Argon2** algorithm version (`0x13`), not
/// the envelope's: the block's layout - version, memory, iterations,
/// parallelism and output length at their fixed offsets - is the format's, and
/// with one format there is no other to tell apart here.
///
/// The band check lives here because this is the one place a block becomes
/// `argon2::Params`, and it runs before that construction and before any
/// derivation. The envelope calls it too, before it reaches the injected
/// backend, so the refusal does not depend on which backend a caller passes.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::Argon2Parameters)` when the block has the wrong Argon2
/// version or output length, declares parameters outside `limits`, or cannot form Argon2 params.
pub(crate) fn decode_argon2_block(
    block: &[u8; KDF_BLOCK_LEN],
    limits: &KdfLimits,
) -> Result<argon2::Params, EnvelopeError> {
    let invalid = || EnvelopeError::Malformed(Malformed::Argon2Parameters);
    let version = read_u32(block, 0).ok_or_else(invalid)?;
    let memory = read_u32(block, 20).ok_or_else(invalid)?;
    let iterations = read_u32(block, 24).ok_or_else(invalid)?;
    let parallelism = read_u32(block, 28).ok_or_else(invalid)?;
    let output_len = read_u32(block, 32).ok_or_else(invalid)?;
    if version != ARGON2_VERSION
        || output_len != u32::try_from(ARGON2_OUTPUT_LEN).unwrap_or_default()
    {
        return Err(invalid());
    }
    let declared = Argon2idParams {
        memory_kib: memory,
        iterations,
        parallelism,
    };
    if !limits.admits(declared) {
        return Err(invalid());
    }
    let output = usize::try_from(output_len).map_err(|_conversion| invalid())?;
    argon2::Params::new(memory, iterations, parallelism, Some(output))
        .map_err(|_parameter_error| invalid())
}

/// Read a little-endian `u32` at `offset`, or `None` when it runs past the
/// end.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let array: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::*;
    use crate::{seal::argon2_block_from_salt, test_support::*, *};

    /// The version field: magic is 14 bytes, then a little-endian `u16`.
    #[expect(
        clippy::panic,
        reason = "a header shorter than the fixed magic is a broken fixture, which must abort the test"
    )]
    fn version_of(blob: &[u8]) -> u16 {
        let Some(bytes) = blob.get(14..16) else {
            panic!("the header is long enough for a version");
        };
        let Ok(pair) = <[u8; 2]>::try_from(bytes) else {
            panic!("two bytes are a u16");
        };
        u16::from_le_bytes(pair)
    }

    /// The one passphrase slot's serialized KDF block, with its salt blanked.
    ///
    /// The salt is drawn fresh by every seal, so two independent seals can only
    /// be compared on the parameters around it.
    #[expect(
        clippy::panic,
        reason = "the fixture is a sealed envelope this module produced"
    )]
    fn block_without_salt(blob: &[u8]) -> [u8; KDF_BLOCK_LEN] {
        let envelope =
            KeytabEnvelope::parse(blob).unwrap_or_else(|error| panic!("parse failed: {error}"));
        let mut block = envelope
            .slots
            .first()
            .and_then(|slot| slot.kdf)
            .unwrap_or_else(|| panic!("the passphrase slot must carry a KDF block"));
        if let Some(salt) = block.get_mut(KDF_SALT_START..KDF_SALT_END) {
            salt.fill(0);
        }
        block
    }

    /// Byte offset of the passphrase slot's KDF block in the fixture below:
    /// header 70, `slot_id` 4, `slot_type` 1, `slot_label_len` 1, the label
    /// "operator" 8, `kek_alg` 1.
    const KDF_BLOCK_OFFSET: usize = 85;

    /// Offset of `memory_kib` inside the serialized Argon2 block.
    const KDF_MEMORY_OFFSET: usize = 20;

    /// 4 MiB: below the crate's 8 MiB floor, and so below the default band.
    const BELOW_FLOOR_KIB: u32 = 0x0000_1000;

    /// 2 GiB: far above the default band's 64 MiB ceiling.
    const ABOVE_CEILING_KIB: u32 = 0x0020_0000;

    /// Seal one passphrase envelope, then overwrite the slot's declared memory
    /// cost. Every other byte of the block stays the format's, so only the
    /// caller's band can refuse the file.
    #[expect(
        clippy::panic,
        reason = "the fixture is a sealed envelope this module produced"
    )]
    fn sealed_declaring_memory(memory_kib: u32) -> Vec<u8> {
        let mut blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::default(),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
        let start = KDF_BLOCK_OFFSET + KDF_MEMORY_OFFSET;
        let Some(field) = blob.get_mut(start..start + 4) else {
            panic!("the KDF block is inside the header");
        };
        field.copy_from_slice(&memory_kib.to_le_bytes());
        blob
    }

    /// A selected passphrase slot whose serialized Argon2 parameters fall
    /// outside the band is rejected, field by field. This is the only place
    /// those values are checked, so a loosened comparison would accept a file
    /// sealed under parameters the caller did not allow.
    #[test]
    #[expect(
        clippy::panic,
        reason = "an envelope operation failing means the format is broken"
    )]
    fn argon2_parameter_fields_outside_the_band_are_rejected() {
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::default(),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
        // The single passphrase slot's KDF block starts at byte 85: the
        // 70-byte header, then slot_id (4), slot_type (1), slot_label_len
        // (1), the 8-byte label, and kek_alg (1). Each parameter sits at a
        // known offset inside that block.
        let block: usize = 85;
        let fields: [(usize, &str); 5] = [
            (0, "argon2_version"),
            (20, "memory_kib"),
            (24, "iterations"),
            (28, "parallelism"),
            (32, "output_len"),
        ];
        // Every field is corrupted in turn: a comparison chain that has been
        // loosened at one site still rejects most corruptions, so each field
        // needs its own case to pin its own check.
        for (offset, name) in fields {
            let mut corrupted = blob.clone();
            if let Some(byte) = corrupted.get_mut(block.saturating_add(offset)) {
                // XOR, not assignment: `output_len`'s low byte is already
                // 0x20, so writing a constant would leave that case corrupting
                // nothing.
                *byte ^= 0x11;
            }
            let envelope = KeytabEnvelope::parse(&corrupted)
                .unwrap_or_else(|error| panic!("parse failed: {error}"));
            let credential = SlotCredential::Passphrase(PASSPHRASE);
            let selected = envelope
                .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
                .unwrap_or_else(|error| panic!("select failed: {error}"));
            assert!(
                matches!(
                    selected.unlock(&credential, &Argon2Kdf),
                    Err(EnvelopeError::Malformed(Malformed::Argon2Parameters))
                ),
                "a slot whose {name} is not the v1 value must be rejected"
            );
        }
    }

    /// A raw-key unlock never reaches the KDF backend, and never validates
    /// another slot's Argon2 parameters.
    #[test]
    #[expect(
        clippy::panic,
        reason = "an envelope operation failing means the format is broken"
    )]
    fn raw_key_path_performs_no_argon2_derivation() {
        // Two slots: the passphrase slot is *not* selected, and its
        // parameters are never inspected.
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
        let envelope =
            KeytabEnvelope::parse(&blob).unwrap_or_else(|error| panic!("parse failed: {error}"));
        let credential = SlotCredential::RawKey(&RAW_KEY);
        let selected = envelope
            .select_slot(
                SlotSelector::Label("pod"),
                &KdfLimits::defaults(),
                &credential,
            )
            .unwrap_or_else(|error| panic!("select failed: {error}"));
        let plaintext = selected
            .unlock(&credential, &PanickingKdf)
            .unwrap_or_else(|error| panic!("unlock failed: {error}"));
        assert_eq!(plaintext.as_slice(), PLAINTEXT);
    }

    /// No Argon2 *derivation* outside the concrete backend: the injected
    /// backend proves the raw-key path never calls the trait, and this guard
    /// proves nobody bypassed the trait.
    ///
    /// The guard pins the two calls that derive - `Argon2::new` and
    /// `hash_password_into` - rather than every mention of the `argon2`
    /// path. Constructing `argon2::Params` from the serialized block is
    /// parameter decoding, not derivation, and belongs with the block
    /// readers; what must not move is the derivation itself.
    #[test]
    #[expect(
        clippy::panic,
        reason = "the source file must be readable for the guard to mean anything"
    )]
    fn argon2_use_is_confined_to_the_backend() {
        use std::fs::read_to_string;
        let source = read_to_string(format!("{}/src/kdf.rs", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|error| panic!("the module source must be readable: {error}"));
        let production = production_text(&source);
        let impl_start = production
            .find("impl KdfBackend for Argon2Kdf")
            .unwrap_or_else(|| panic!("the concrete backend must exist"));
        let after = production.split_at(impl_start).1;
        let impl_offset = impl_start.saturating_add(
            after
                .find("\n}\n")
                .unwrap_or_else(|| panic!("the backend impl must close")),
        );
        // Compare line indices: the byte offsets above cannot be compared to
        // the enumerate index directly.
        let impl_first_line = production.split_at(impl_start).0.lines().count();
        let impl_last_line = production.split_at(impl_offset).0.lines().count();
        for (line_number, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let derives = line.contains("Argon2::new") || line.contains("hash_password_into");
            if !derives {
                continue;
            }
            assert!(
                line_number >= impl_first_line && line_number <= impl_last_line,
                "line {} derives with Argon2 outside the backend impl: {line}",
                line_number.saturating_add(1)
            );
        }
    }

    /// KRP-90/A6: the default seal and an explicit `Argon2idParams::defaults()`
    /// write the same parameter block, and that block is the format's canonical
    /// one.
    ///
    /// Replaces `the_default_parameters_write_a_v1_file`, which asserted the
    /// same rule through the old `v1()` name. No version constant is named here:
    /// what this pins is the *block*, which is what the golden vectors carry
    /// byte for byte.
    #[test]
    #[expect(clippy::panic, reason = "a wrong-side test result must abort the test")]
    fn default_kdf_writes_default_argon2id_parameters() {
        let by_default = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::default(),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
        let by_hand = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::Argon2id(Argon2idParams::defaults()),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
        let expected = argon2_block_from_salt(&[0; SALT_LEN], Argon2idParams::defaults())
            .unwrap_or_else(|error| panic!("the canonical block must build: {error}"));
        assert_eq!(
            block_without_salt(&by_default),
            expected,
            "Kdf::default() writes the format's canonical parameter block"
        );
        assert_eq!(
            block_without_salt(&by_hand),
            expected,
            "and an explicit Argon2idParams::defaults() writes the same one"
        );
    }

    /// KRP-93: a non-default parameter set stays in the format's one version,
    /// and the band the caller passes - not the file's version - is what decides
    /// whether it opens.
    ///
    /// Replaces `non_default_parameters_are_written_as_v2_and_round_trip`: there
    /// is no v2 to write a variable parameter set as, and no version for a reader
    /// to agree or disagree about.
    #[test]
    #[expect(clippy::panic, reason = "a wrong-side test result must abort the test")]
    fn non_default_parameters_stay_in_the_single_format_and_round_trip() {
        let stronger = Argon2idParams::new(Argon2idParams::floor().memory_kib(), 2, 2)
            .unwrap_or_else(|error| panic!("a stronger set must be accepted: {error}"));
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::Argon2id(stronger),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
        assert_eq!(
            version_of(&blob),
            format::FORMAT_VERSION,
            "one format writes the format's version for every parameter set"
        );
        let envelope = KeytabEnvelope::parse(&blob)
            .unwrap_or_else(|error| panic!("the file must parse: {error}"));
        let credential = SlotCredential::Passphrase(b"correct horse battery staple");
        // The caller's band decides: the default one does not admit the file's
        // parameters, so this needs a band that does.
        let limits = KdfLimits::between(Argon2idParams::floor(), stronger)
            .unwrap_or_else(|error| panic!("a valid band: {error}"));
        let selection = envelope
            .select_slot(SlotSelector::Label("operator"), &limits, &credential)
            .unwrap_or_else(|error| panic!("select failed: {error}"));
        assert!(
            selection.unlock(&credential, &Argon2Kdf).is_ok(),
            "the file opens with a band that admits its parameters"
        );
        // And the default band refuses it, which is the resource guard.
        let narrowed = envelope
            .select_slot(
                SlotSelector::Label("operator"),
                &KdfLimits::defaults(),
                &credential,
            )
            .unwrap_or_else(|error| panic!("select failed: {error}"));
        assert!(
            matches!(
                narrowed.unlock(&credential, &Argon2Kdf),
                Err(EnvelopeError::Malformed(Malformed::Argon2Parameters))
            ),
            "a band of exactly the default parameters refuses the file's stronger set"
        );
    }

    /// The floor half of the band: weakening must be deliberate, so the
    /// constructor refuses parameters below it.
    #[test]
    fn parameters_below_the_floor_are_refused() {
        let floor = Argon2idParams::floor();
        assert!(
            Argon2idParams::new(floor.memory_kib(), floor.iterations(), floor.parallelism())
                .is_ok(),
            "the floor itself is accepted"
        );
        assert!(
            Argon2idParams::new(
                floor.memory_kib() - 1,
                floor.iterations(),
                floor.parallelism()
            )
            .is_err(),
            "one Kib below the floor is refused"
        );
        assert!(
            Argon2idParams::new(floor.memory_kib(), 0, floor.parallelism()).is_err(),
            "zero iterations is refused"
        );
    }

    /// A band whose minimum is above its maximum is not a band.
    #[test]
    #[expect(clippy::panic, reason = "a wrong-side test result must abort the test")]
    fn an_inverted_band_is_refused() {
        let low =
            Argon2idParams::new(8_192, 1, 1).unwrap_or_else(|error| panic!("fixture: {error}"));
        let high =
            Argon2idParams::new(0x1_0000, 3, 4).unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(
            KdfLimits::between(low, high).is_ok(),
            "a real band is accepted"
        );
        assert!(
            KdfLimits::between(high, low).is_err(),
            "minimum above maximum is refused"
        );
        assert!(
            KdfLimits::between(Argon2idParams::floor(), Argon2idParams::defaults()).is_ok(),
            "the floor may be the minimum: that is what a floor is for"
        );
    }

    /// KRP-90/A6: the default band accepts exactly the format's parameters and
    /// nothing else.
    ///
    /// Replaces `the_scaffold_is_band_shaped`, whose subject was the old `v1()`
    /// name for the same rule.
    #[test]
    fn default_kdf_limits_accept_only_the_default_parameters() {
        let limits = KdfLimits::defaults();
        assert!(
            limits.admits(Argon2idParams::defaults()),
            "the format's own parameters are inside its band"
        );
        let weaker = Argon2idParams {
            memory_kib: Argon2idParams::defaults().memory_kib(),
            iterations: Argon2idParams::defaults().iterations() - 1,
            parallelism: Argon2idParams::defaults().parallelism(),
        };
        assert!(
            !limits.admits(weaker),
            "an envelope declaring fewer iterations is outside the default band"
        );
        let stronger = Argon2idParams {
            memory_kib: Argon2idParams::defaults().memory_kib(),
            iterations: Argon2idParams::defaults().iterations() + 1,
            parallelism: Argon2idParams::defaults().parallelism(),
        };
        assert!(
            !limits.admits(stronger),
            "and so is one declaring more: the default band is exact, not a ceiling"
        );
        assert!(
            limits.is_defaults()
                && KdfLimits::between(weaker, stronger).is_ok_and(|band| !band.is_defaults()),
            "`is_defaults` reports exactly the exact band, and a real band is not it"
        );
    }

    /// SOW B6c/KRP-93: a block outside the caller's band is refused before a
    /// derivation is attempted, in both directions - below the floor and above
    /// the ceiling.
    ///
    /// `PanickingKdf` fails loudly if it is ever reached, so asserting the error
    /// is `Malformed::Argon2Parameters` is also the proof that no derivation
    /// ran. The refusal is in the envelope rather than in the backend, so it
    /// holds for whatever backend a caller injects.
    #[test]
    #[expect(clippy::panic, reason = "a wrong-side test result must abort the test")]
    fn out_of_band_parameters_are_refused_before_derivation() {
        let credential = SlotCredential::Passphrase(b"correct horse battery staple");
        for memory_kib in [BELOW_FLOOR_KIB, ABOVE_CEILING_KIB] {
            let blob = sealed_declaring_memory(memory_kib);
            let envelope = KeytabEnvelope::parse(&blob)
                .unwrap_or_else(|error| panic!("the corrupted file still parses: {error}"));
            let selection = envelope
                .select_slot(
                    SlotSelector::Label("operator"),
                    &KdfLimits::defaults(),
                    &credential,
                )
                .unwrap_or_else(|error| panic!("select failed: {error}"));
            assert!(
                matches!(
                    selection.unlock(&credential, &PanickingKdf),
                    Err(EnvelopeError::Malformed(Malformed::Argon2Parameters))
                ),
                "a block declaring {memory_kib} KiB is refused before the backend is reached"
            );
        }
    }

    /// KRP-90/SOW B6c: the docs name both RFC 9106 section 4 recommended sets
    /// and the crate offers no preset for the FIRST one.
    ///
    /// A source guard, because the row is a documentation requirement: the
    /// SECOND set is what the default names, the FIRST set is prose, and the
    /// absence of a constructor is what "no FIRST preset" means.
    #[test]
    fn kdf_docs_name_rfc_9106_defaults_without_a_first_preset() {
        let source = include_str!("lib.rs");
        let production = production_text(source);
        for named in [
            "SECOND RECOMMENDED",
            "64 MiB",
            "t=3",
            "p=4",
            "FIRST RECOMMENDED",
            "2 GiB",
        ] {
            assert!(
                production.contains(named),
                "the KDF docs must name {named} (RFC 9106 section 4)"
            );
        }
        for forbidden in [
            "first_recommended",
            "FirstRecommended",
            "Argon2idParams::first",
        ] {
            assert!(
                !production.contains(forbidden),
                "no FIRST RECOMMENDED preset may exist, yet the sources name {forbidden}"
            );
        }
    }
}
