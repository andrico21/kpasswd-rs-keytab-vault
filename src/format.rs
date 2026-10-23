//! The envelope's wire format: its constants, its structural reject rules and
//! the parser that applies them.
//!
//! Nothing here touches a cipher or a key: a slot is parsed structurally -
//! lengths, labels, duplicates, the `slot_type`/`kek_alg` pairing - and the
//! Argon2id parameter *values* are checked against the caller's band only for
//! the slot actually selected, which is why that check lives with the KDF.
#![expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/format.rs::format the format's constants and its `Slot`/`Cursor` fields are crate-visible so the sibling modules can parse with them, and none of them is on the crate's flat surface."
)]
use core::str::from_utf8;

/// Magic bytes opening every envelope.
pub(crate) const MAGIC: &[u8] = b"KRBRESETKEYTAB";

/// The version this build writes and the only one it reads (KRP-93).
///
/// One value, for every parameter set: a non-default Argon2id block is a
/// property of the slot, not of a second format, so there is nothing for a
/// reader to disagree about and no migration path to describe.
pub(crate) const FORMAT_VERSION: u16 = 1;

/// Length of the per-file identifier, random at seal and never changed
/// afterwards.
///
/// It sits in the wrap AAD, so a slot cannot be spliced from another file, and
/// it stays out of the payload AAD's way during a rotation, so the slots a
/// rotation does not touch keep authenticating.
pub(crate) const FILE_ID_LEN: usize = 16;

/// Offset of `payload_nonce` in the fixed header: magic, version, `header_len`
/// and `payload_alg` precede it.
///
/// A rotation rewrites the nonce in place, which is why its offset is named
/// rather than only its position in the serialization order.
pub(crate) const PAYLOAD_NONCE_OFFSET: usize = MAGIC.len() + 2 + 4 + 1;

/// `payload_alg` for XChaCha20-Poly1305: the v1 payload AEAD, mandatory and
/// not negotiable.
pub(crate) const PAYLOAD_ALG_XCHACHA20_POLY1305: u8 = 1;

/// `slot_type` for a slot unlocked by 32 raw bytes.
pub(crate) const SLOT_TYPE_RAW_KEY: u8 = 1;

/// `slot_type` for a slot unlocked by a passphrase.
pub(crate) const SLOT_TYPE_PASSPHRASE: u8 = 2;

/// `kek_alg` for a KEK used directly, with no derivation.
pub(crate) const KEK_ALG_DIRECT_256: u8 = 1;

/// `kek_alg` for a KEK derived with Argon2id.
pub(crate) const KEK_ALG_ARGON2ID: u8 = 2;

/// `wrap_alg` for XChaCha20-Poly1305: the only v1 DEK-wrap AEAD.
pub(crate) const WRAP_ALG_XCHACHA20_POLY1305: u8 = 1;

/// The serialized Argon2 version (`0x13`, Argon2 v19).
pub(crate) const ARGON2_VERSION: u32 = 0x13;

/// Argon2id memory cost in KiB: RFC 9106's second recommended profile, for
/// memory-constrained environments.
pub(crate) const ARGON2_MEMORY_KIB: u32 = 0x0001_0000;

/// Argon2id iteration count for the format's default parameter set.
pub(crate) const ARGON2_ITERATIONS: u32 = 3;

/// Argon2id parallelism for the format's default parameter set.
pub(crate) const ARGON2_PARALLELISM: u32 = 4;

/// Derived material length in bytes, fixed by the format's parameter set.
pub(crate) const ARGON2_OUTPUT_LEN: usize = 32;

/// Salt length in bytes.
pub(crate) const SALT_LEN: usize = 16;

/// Offset of the salt inside the serialized Argon2 block.
pub(crate) const KDF_SALT_START: usize = 4;

/// One past the salt inside the serialized Argon2 block.
pub(crate) const KDF_SALT_END: usize = 20;

/// Smallest possible wrap AAD: the 41-byte wrap identity plus the 32-byte
/// prefix of a label-less raw-key slot.
pub(crate) const WRAP_AAD_MIN_LEN: usize = 73;

/// Serialized width of the Argon2 parameter block.
pub(crate) const KDF_BLOCK_LEN: usize = 36;

/// XChaCha20-Poly1305 nonce length in bytes, for the payload and for every
/// wrap.
pub(crate) const NONCE_LEN: usize = 24;

/// Poly1305 tag length in bytes.
pub(crate) const TAG_LEN: usize = 16;

/// DEK length in bytes: one 256-bit payload key.
pub(crate) const DEK_LEN: usize = 32;

/// Length of a raw KEK in bytes: one 256-bit wrapping key.
///
/// `SlotCredential::RawKey` carries this length as part of its type, so a raw
/// key of any other length cannot be constructed at all.
pub(crate) const KEK_LEN: usize = 32;

/// Bytes of a wrapped DEK: the DEK plus its tag.
pub(crate) const WRAPPED_DEK_LEN: usize = DEK_LEN + TAG_LEN;

/// Fixed header size: magic, version, `header_len`, `payload_alg`,
/// `payload_nonce`, `payload_len`, `file_id`, `slot_count`.
pub(crate) const FIXED_HEADER_LEN: usize = 70;

/// Widest accepted `header_len`, bounding the header a parser will walk.
pub(crate) const MAX_HEADER_LEN: usize = 0x0001_0000;

/// Widest accepted `payload_len`, bounding the plaintext a blob may claim.
pub(crate) const MAX_PAYLOAD_LEN: usize = 0x0010_0000;

/// Widest accepted slot label, in bytes.
pub(crate) const MAX_SLOT_LABEL_LEN: usize = 64;

/// Whether a character would be hidden or reorder the text around it when a
/// label is rendered.
///
/// C0/C1 controls and the line and paragraph separators (U+2028, U+2029) can
/// forge a line; the Unicode bidirectional controls (U+061C, U+200E, U+200F,
/// U+202A..=U+202E, U+2066..=U+2069) can reorder one, Trojan-Source style, with
/// no terminal feature at all. A label is an operator-facing display name that
/// this crate interpolates verbatim into its diagnostics, so the character
/// class is part of the wire rule. Zero-width joiners and the other formatting
/// characters stay legal: real scripts and emoji sequences use them.
#[must_use]
pub(crate) const fn is_unrenderable_in_a_label(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Most slots one blob may carry: a v1 product limit (an operator plus a
/// pod is two, a rotation window wants at most four), not a Kerberos or
/// crypto limit, and raisable in v2.
pub(crate) const MAX_SLOTS: usize = 8;

/// Fewest slots one blob may carry: a blob nobody can unlock is not a keytab
/// wrapper.
pub(crate) const MIN_SLOTS: usize = 1;

/// Length of a raw KEK in bytes, the length-first rule's first branch.
pub(crate) const RAW_KEY_LEN: usize = 32;

/// Length of a hex-encoded KEK in characters, the rule's second branch.
pub(crate) const HEX_KEY_LEN: usize = 64;

/// A structural violation found while parsing an envelope header.
///
/// Variants are typed rather than prose so that a test asserts the *kind* of
/// failure: rewording a `Display` must not be able to break a security
/// regression test, and a wrong classification must fail loudly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Malformed {
    /// The file is shorter than the envelope requires.
    #[error("the file is shorter than the envelope header")]
    TooShort,
    /// The leading bytes are not the envelope magic.
    #[error("the file does not start with the keytab-envelope magic")]
    Magic,
    /// The version is not one this build understands.
    #[error("the envelope version is not supported")]
    Version,
    /// `header_len` is below the fixed header size, above the header cap, or
    /// past the end of the file.
    #[error("the envelope header length is out of range")]
    HeaderLength,
    /// Slot parsing did not consume exactly `header_len` bytes, or a slot
    /// field runs past it.
    #[error("the envelope slots do not fill the header exactly")]
    HeaderBoundary,
    /// `slot_count` is outside `1..=8`.
    #[error("the envelope slot count is out of range")]
    SlotCount,
    /// A `slot_type` byte is neither raw-key nor passphrase.
    #[error("an envelope slot type is not one v1 defines")]
    SlotType,
    /// A slot label is longer than 64 bytes, is not UTF-8, or carries a
    /// character that cannot be rendered (a control, a line or paragraph
    /// separator, or a bidirectional control).
    #[error(
        "an envelope slot label is too long, not UTF-8, or carries a character that cannot be rendered"
    )]
    SlotLabel,
    /// A slot violates the `slot_type`/`kek_alg` pairing.
    #[error("an envelope slot pairs a slot type with the wrong key algorithm")]
    SlotPairing,
    /// A label is spelled exactly like a slot's decimal id, so one name could
    /// mean two slots.
    #[error(
        "an envelope slot label is spelled like another slot's id, so a selection token is ambiguous"
    )]
    SlotIdentifier,
    /// Two slots share a `slot_id`, or two slots share a label.
    #[error("two envelope slots share an id or a label")]
    DuplicateSlot,
    /// An algorithm byte names something v1 does not define.
    #[error("the envelope names an algorithm v1 does not define")]
    Algorithm,
    /// A selected passphrase slot's Argon2 parameters are outside the band this
    /// unlock honours.
    #[error("the selected slot's Argon2 parameters are outside the accepted band")]
    Argon2Parameters,
    /// `payload_len` is above the payload cap.
    #[error("the envelope payload length is out of range")]
    PayloadLength,
    /// `header_len + payload_len + 16` is not the file length, so bytes are
    /// missing or trailing.
    #[error("the envelope length fields do not match the file size (truncated or trailing bytes)")]
    LengthIdentity,
}

/// Why an envelope could not be parsed, unlocked, or sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The header violated a structural rule.
    #[error("{0}")]
    Malformed(Malformed),
    /// The AEAD tag did not verify: wrong key, altered header, altered
    /// ciphertext, or a swapped slot.
    #[error(
        "the keytab envelope did not authenticate: wrong key, altered bytes, or a tampered header"
    )]
    AuthenticationFailed,
    /// Argon2id refused the fixed parameters, or derivation otherwise
    /// failed.
    #[error("the passphrase could not be derived into a key")]
    DerivationFailed,
    /// The operating system's random number generator could not produce the
    /// bytes a seal or a rotation needs.
    #[error("the system random number generator is unavailable")]
    EntropyUnavailable,
    /// A rotation's replacement does not fit the slot it replaces: it is a
    /// different kind, its label has a different length in bytes, or its label
    /// is not allowed in this file (a duplicate, a spelling of a slot id, or a
    /// character that cannot be rendered).
    ///
    /// **Caller error on a valid file, not corruption.** The file parsed and
    /// unlocked; the replacement is what does not fit. A different kind or label
    /// length would change the file's layout, which takes a fresh seal rather
    /// than a rotation. Reporting it as [`Malformed`] would send the caller
    /// hunting for a corrupt file.
    #[error("the rotation's replacement does not fit the slot it replaces")]
    RotationMismatch,
}

/// What unlocks a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotType {
    /// Thirty-two raw bytes, used directly as the KEK.
    RawKey,
    /// A passphrase, run through Argon2id at the parameters the slot carries.
    Passphrase,
}

impl SlotType {
    /// The `slot_type` a serialized byte names, or `None` when v1 defines no
    /// such type.
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            SLOT_TYPE_RAW_KEY => Some(Self::RawKey),
            SLOT_TYPE_PASSPHRASE => Some(Self::Passphrase),
            _ => None,
        }
    }

    /// The `kek_alg` byte this slot type pairs with. Read by the sealing
    /// half, which v1 ships (KRP-88).
    pub(crate) const fn kek_alg(self) -> u8 {
        match self {
            Self::RawKey => KEK_ALG_DIRECT_256,
            Self::Passphrase => KEK_ALG_ARGON2ID,
        }
    }

    /// The `slot_type` a `kek_alg` byte implies, or `None` when v1 defines
    /// no such algorithm.
    const fn from_kek_alg(kek_alg: u8) -> Option<Self> {
        match kek_alg {
            KEK_ALG_DIRECT_256 => Some(Self::RawKey),
            KEK_ALG_ARGON2ID => Some(Self::Passphrase),
            _ => None,
        }
    }

    /// Whether a slot of this type carries a serialized Argon2 block.
    pub(crate) const fn has_kdf_block(self) -> bool {
        matches!(self, Self::Passphrase)
    }

    /// How a diagnostic names this type.
    #[inline]
    #[must_use]
    pub(crate) const fn describe(self) -> &'static str {
        match self {
            Self::RawKey => "raw key",
            Self::Passphrase => "passphrase",
        }
    }
}

/// One slot as the file declares it: what a caller needs to choose a
/// [`crate::SlotSelector`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SlotInfo {
    /// Serialized slot id, unique within the file.
    pub id: u32,
    /// Operator-facing label, unique within the file and free of characters
    /// that cannot be rendered.
    pub label: String,
    /// What unlocks this slot.
    pub kind: SlotType,
}

/// One keyslot, as parsed from a header.
pub(crate) struct Slot {
    /// Serialized slot id, unique within the file.
    pub(crate) id: u32,
    /// What unlocks this slot.
    pub(crate) kind: SlotType,
    /// Operator-facing label, unique within the file and free of characters
    /// that cannot be rendered.
    pub(crate) label: String,
    /// The raw serialized Argon2 block, present exactly for passphrase slots.
    ///
    /// Held as bytes: its *values* are validated only when this slot is the
    /// selected one, so an unselected slot never costs a derivation or a
    /// parameter check.
    pub(crate) kdf: Option<[u8; KDF_BLOCK_LEN]>,
    /// Wrap nonce.
    pub(crate) wrap_nonce: [u8; NONCE_LEN],
    /// The wrapped DEK with its tag.
    pub(crate) wrapped_dek: [u8; WRAPPED_DEK_LEN],
    /// The slot's serialized prefix, `slot_id` through `wrap_nonce`, kept
    /// verbatim: the wrap AAD is assembled from exactly these bytes, so the
    /// two can never disagree.
    pub(crate) wrap_prefix: Vec<u8>,
    /// Where the wrapped DEK starts in the file. A rotation rewrites this
    /// slot's serialized prefix and these bytes - same lengths, so every other
    /// slot stays where it is - and then the payload under a fresh nonce.
    pub(crate) dek_offset: usize,
}

impl Slot {
    /// How a diagnostic names this slot.
    pub(crate) fn describe(&self) -> String {
        format!("{}: {} ({})", self.id, self.label, self.kind.describe())
    }
}

/// A bounds-checked read cursor over the file.
pub(crate) struct Cursor<'bytes> {
    /// The whole file.
    pub(crate) bytes: &'bytes [u8],
    /// How many bytes have been consumed.
    pub(crate) position: usize,
}

impl<'bytes> Cursor<'bytes> {
    /// A cursor at the start of `bytes`.
    pub(crate) const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// How many bytes have been consumed.
    pub(crate) const fn offset(&self) -> usize {
        self.position
    }

    /// The whole buffer, for spans a slot keeps verbatim.
    pub(crate) const fn bytes(&self) -> &'bytes [u8] {
        self.bytes
    }

    /// Consume `count` bytes, or fail when the file is too short.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::TooShort)` when `count` overflows the cursor position or
    /// extends past the file.
    pub(crate) fn take(&mut self, count: usize) -> Result<&'bytes [u8], EnvelopeError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(EnvelopeError::Malformed(Malformed::TooShort))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(EnvelopeError::Malformed(Malformed::TooShort))?;
        self.position = end;
        Ok(slice)
    }

    /// Consume one byte.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::TooShort)` when the file has no byte at the cursor.
    pub(crate) fn take_u8(&mut self) -> Result<u8, EnvelopeError> {
        let slice = self.take(1)?;
        slice
            .first()
            .copied()
            .ok_or(EnvelopeError::Malformed(Malformed::TooShort))
    }

    /// Consume a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::TooShort)` when fewer than two bytes remain.
    pub(crate) fn take_u16(&mut self) -> Result<u16, EnvelopeError> {
        let array: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::TooShort))?;
        Ok(u16::from_le_bytes(array))
    }

    /// Consume a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::TooShort)` when fewer than four bytes remain.
    pub(crate) fn take_u32(&mut self) -> Result<u32, EnvelopeError> {
        let array: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::TooShort))?;
        Ok(u32::from_le_bytes(array))
    }

    /// Consume a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::TooShort)` when fewer than eight bytes remain.
    pub(crate) fn take_u64(&mut self) -> Result<u64, EnvelopeError> {
        let array: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::TooShort))?;
        Ok(u64::from_le_bytes(array))
    }

    /// How many bytes this cursor has consumed: a file offset.
    pub(crate) const fn file_offset(&self) -> usize {
        self.position
    }

    /// Consume exactly `LEN` bytes as an array.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::TooShort)` when fewer than `LEN` bytes remain.
    pub(crate) fn take_array<const LEN: usize>(&mut self) -> Result<[u8; LEN], EnvelopeError> {
        self.take(LEN)?
            .try_into()
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::TooShort))
    }
}

/// Parse one slot, validating its length fields and its pairing.
///
/// The KDF block is consumed by `slot_type`, never by `kek_alg`: a raw-key
/// slot carrying stray KDF bytes is detected because the byte at the
/// `wrap_alg` offset is then the block's first byte, which is not a defined
/// `wrap_alg` (or because the slot then under-runs `header_len`).
///
/// # Errors
///
/// `EnvelopeError::Malformed` when the slot is truncated, crosses `header_len`, has an unknown
/// slot type or wrap algorithm, carries a label that is not UTF-8, is oversized or
/// holds a character that cannot be rendered, or pairs the slot type with the wrong
/// KEK algorithm.
pub(crate) fn parse_slot(
    cursor: &mut Cursor<'_>,
    header_len: usize,
) -> Result<Slot, EnvelopeError> {
    let slot_start = cursor.offset();
    let id = cursor.take_u32()?;
    let kind = SlotType::from_code(cursor.take_u8()?)
        .ok_or(EnvelopeError::Malformed(Malformed::SlotType))?;
    let label_len = usize::from(cursor.take_u8()?);
    if label_len > MAX_SLOT_LABEL_LEN {
        return Err(EnvelopeError::Malformed(Malformed::SlotLabel));
    }
    let label_end = cursor
        .offset()
        .checked_add(label_len)
        .ok_or(EnvelopeError::Malformed(Malformed::TooShort))?;
    if label_end > header_len {
        return Err(EnvelopeError::Malformed(Malformed::HeaderBoundary));
    }
    let label_bytes = cursor.take(label_len)?;
    let label = from_utf8(label_bytes)
        .map_err(|_encoding_error| EnvelopeError::Malformed(Malformed::SlotLabel))?
        .to_owned();
    // A label is an operator-facing display name, and the crate renders it
    // verbatim in a one-line-per-slot diagnostic: a control character would let
    // a file forge a summary line, and a bidi control could reorder one, so the
    // character class is part of the wire rule.
    if label.chars().any(is_unrenderable_in_a_label) {
        return Err(EnvelopeError::Malformed(Malformed::SlotLabel));
    }
    let kek_alg = cursor.take_u8()?;
    let paired = SlotType::from_kek_alg(kek_alg)
        .filter(|implied| *implied == kind)
        .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
    let kdf = if paired.has_kdf_block() {
        Some(cursor.take_array::<KDF_BLOCK_LEN>()?)
    } else {
        None
    };
    if cursor.take_u8()? != WRAP_ALG_XCHACHA20_POLY1305 {
        return Err(EnvelopeError::Malformed(Malformed::Algorithm));
    }
    let wrap_nonce = cursor.take_array::<NONCE_LEN>()?;
    let wrap_aad_end = cursor.offset();
    let dek_offset = cursor.file_offset();
    let wrapped_dek = cursor.take_array::<WRAPPED_DEK_LEN>()?;
    if cursor.offset() > header_len {
        return Err(EnvelopeError::Malformed(Malformed::HeaderBoundary));
    }
    let wrap_prefix = cursor
        .bytes()
        .get(slot_start..wrap_aad_end)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?
        .to_vec();
    Ok(Slot {
        id,
        kind,
        label,
        kdf,
        wrap_nonce,
        wrapped_dek,
        wrap_prefix,
        dek_offset,
    })
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;
    use crate::{test_support::*, *};

    /// A file that is not an envelope at all is rejected on the magic.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/format.rs::magic_rejected keeps the uniform test signature while it only asserts"
    )]
    fn magic_rejected() -> TestResult {
        assert!(
            matches!(
                KeytabEnvelope::parse(b"not an envelope at all, far too short"),
                Err(EnvelopeError::Malformed(Malformed::Magic))
            ),
            "a file without the magic must be rejected"
        );
        assert!(
            !kpasswd_rs::is_envelope(b"plain keytab bytes"),
            "a plain keytab is not an envelope"
        );
        Ok(())
    }

    /// A truncated file is rejected on the length identity, before any
    /// cryptographic work.
    #[test]
    fn truncated_blob_rejected() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let cut = blob.len().saturating_sub(1);
        let truncated = blob.get(..cut).unwrap_or_default();
        assert!(
            matches!(
                KeytabEnvelope::parse(truncated),
                Err(EnvelopeError::Malformed(Malformed::LengthIdentity))
            ),
            "a truncated file must fail the length identity"
        );
        Ok(())
    }

    /// A file whose declared length does not match its size is rejected:
    /// this is what rejects trailing bytes after the tag.
    #[test]
    fn trailing_bytes_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        blob.push(0);
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::LengthIdentity))
            ),
            "trailing bytes must fail the length identity"
        );
        Ok(())
    }

    /// An unknown algorithm byte is rejected: v1 defines no forward-compatible
    /// skipping.
    #[test]
    fn unknown_alg_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        // Byte 20 is `payload_alg`: magic 14, version 2, header_len 4.
        if let Some(byte) = blob.get_mut(20) {
            *byte = 0x7f;
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::Algorithm))
            ),
            "an undefined payload algorithm must be rejected"
        );
        Ok(())
    }

    /// A version this build does not speak is rejected immediately after the
    /// magic. There is one accepted value (KRP-93): any other version is
    /// refused here, on the version, and no second version parses.
    #[test]
    fn unsupported_envelope_version_is_refused_on_version() -> TestResult {
        for unsupported in [u16::MIN, 2, u16::MAX] {
            let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
                .map_err(|error| format!("seal failed: {error}"))?;
            if let Some(field) = blob.get_mut(14..16) {
                field.copy_from_slice(&unsupported.to_le_bytes());
            }
            assert!(
                matches!(
                    KeytabEnvelope::parse(&blob),
                    Err(EnvelopeError::Malformed(Malformed::Version))
                ),
                "version {unsupported} must be refused on the version"
            );
        }
        Ok(())
    }

    /// `slot_count` of zero is rejected: a blob nobody can unlock is not a
    /// keytab wrapper.
    #[test]
    fn slot_count_zero_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        // Byte 69 is `slot_count`: magic 14, version 2, header_len 4,
        // payload_alg 1, payload_nonce 24, payload_len 8, file_id 16.
        if let Some(byte) = blob.get_mut(69) {
            *byte = 0;
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::SlotCount))
            ),
            "a slot count of zero must be rejected"
        );
        Ok(())
    }

    /// `u8` admits 9-255 slots; the v1 cap is 8, and 255 is rejected
    /// explicitly.
    #[test]
    fn slot_count_255_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        if let Some(byte) = blob.get_mut(69) {
            *byte = 0xff;
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::SlotCount))
            ),
            "255 slots must be rejected"
        );
        Ok(())
    }

    /// The slots must fill `header_len` exactly: no padding, no shortfall.
    #[test]
    fn header_padding_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        // Claim three more header bytes than the slots consumed *and* three
        // fewer payload bytes, so the length identity still holds and only
        // the exact-fill rule can reject this file.
        let padding: u8 = 3;
        if let Some(byte) = blob.get_mut(16) {
            *byte = byte.saturating_add(padding);
        }
        if let Some(byte) = blob.get_mut(45) {
            *byte = byte.saturating_sub(padding);
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::HeaderBoundary))
            ),
            "a header that is not exactly filled must be rejected"
        );
        Ok(())
    }

    /// A slot whose `slot_type` and `kek_alg` disagree is rejected: the
    /// pairing is structural, checked for every slot.
    #[test]
    fn type_alg_mismatch_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        // The raw-key slot's `kek_alg` byte: header 70, slot_id 4,
        // slot_type 1, slot_label_len 1, label "operator" 8.
        if let Some(byte) = blob.get_mut(84) {
            *byte = KEK_ALG_ARGON2ID;
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::SlotPairing))
            ),
            "a raw-key slot naming Argon2id must be rejected"
        );
        Ok(())
    }

    /// A raw-key slot carrying KDF bytes is rejected: the stray block shifts
    /// the `wrap_alg` byte, which is then not a defined algorithm.
    #[test]
    fn raw_key_slot_with_kdf_bytes_rejected() -> TestResult {
        let base = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let with_block = seal(
            PLAINTEXT,
            &[passphrase_recipient(7, "operator")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        // Build the corrupt shape: the raw-key slot's prefix with the
        // passphrase slot's 36 KDF bytes spliced in after `kek_alg`. The
        // declared header length grows with it, so only the shifted
        // `wrap_alg` can be the rejection.
        let block = with_block.get(85..85 + KDF_BLOCK_LEN).unwrap_or_default();
        let mut corrupt = Vec::new();
        corrupt.extend_from_slice(base.get(..85).unwrap_or_default());
        corrupt.extend_from_slice(block);
        corrupt.extend_from_slice(base.get(85..).unwrap_or_default());
        if let Some(byte) = corrupt.get_mut(16) {
            *byte = byte.saturating_add(u8::try_from(KDF_BLOCK_LEN).unwrap_or_default());
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&corrupt),
                Err(EnvelopeError::Malformed(Malformed::Algorithm))
            ),
            "a raw-key slot carrying KDF bytes must be rejected"
        );
        Ok(())
    }

    /// Where one slot's serialized bytes start in the file: the wrapped DEK's
    /// offset minus the prefix the slot keeps verbatim.
    #[expect(
        clippy::panic,
        reason = "deliberate: src/format.rs::slot_start a slot that cannot be located means the fixture is broken"
    )]
    fn slot_start(blob: &[u8], position: usize) -> usize {
        let parsed =
            KeytabEnvelope::parse(blob).unwrap_or_else(|error| panic!("parse failed: {error}"));
        let slot = parsed
            .slots
            .get(position)
            .unwrap_or_else(|| panic!("slot {position} exists"));
        slot.dek_offset.saturating_sub(slot.wrap_prefix.len())
    }

    /// Byte offset of a slot's label from that slot's start: `slot_id` (4),
    /// `slot_type` (1), `slot_label_len` (1).
    const LABEL_OFFSET: usize = 6;

    /// Overwrite one field in place. The replacement keeps the field's byte
    /// length, so only the value can be the rejection - and `seal` refuses to
    /// produce these shapes, so the reader's own rules are what the tests pin.
    #[expect(
        clippy::panic,
        reason = "deliberate: src/format.rs::overwrite_bytes a field that cannot be written means the fixture is broken"
    )]
    fn overwrite_bytes(blob: &mut [u8], start: usize, bytes: &[u8]) {
        blob.get_mut(start..start.saturating_add(bytes.len()))
            .unwrap_or_else(|| panic!("the field range must be inside the file"))
            .copy_from_slice(bytes);
    }

    /// Two slots with the same id are rejected: an id must name one slot.
    #[test]
    fn duplicate_slot_id_rejected() -> TestResult {
        let mut blob = seal(
            PLAINTEXT,
            &[raw_recipient(3, "one"), raw_recipient(4, "two")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let second = slot_start(&blob, 1);
        overwrite_bytes(&mut blob, second, &3_u32.to_le_bytes());
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::DuplicateSlot))
            ),
            "two slots sharing an id must be rejected"
        );
        Ok(())
    }

    /// Two slots with the same label are rejected: a label is selectable, so
    /// a duplicate is a selection ambiguity.
    #[test]
    fn duplicate_slot_label_rejected() -> TestResult {
        let mut blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "aaaa"), raw_recipient(2, "bbbb")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let second_label = slot_start(&blob, 1).saturating_add(LABEL_OFFSET);
        overwrite_bytes(&mut blob, second_label, b"aaaa");
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::DuplicateSlot))
            ),
            "two slots sharing a label must be rejected"
        );
        Ok(())
    }

    /// A label spelled like an *earlier* slot's decimal id is rejected, so one
    /// name can never mean two slots.
    #[test]
    fn label_spelled_like_an_earlier_slots_id_rejected() -> TestResult {
        let mut blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "x"), raw_recipient(2, "y")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let second_label = slot_start(&blob, 1).saturating_add(LABEL_OFFSET);
        overwrite_bytes(&mut blob, second_label, b"1");
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::SlotIdentifier))
            ),
            "a label spelled like an earlier slot's id must be rejected"
        );
        Ok(())
    }

    /// A label spelled like a *later* slot's decimal id is rejected too: the
    /// rule is symmetric, so neither file order can smuggle a collision in.
    #[test]
    fn label_spelled_like_a_later_slots_id_rejected() -> TestResult {
        let mut blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "x"), raw_recipient(2, "y")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let first_label = slot_start(&blob, 0).saturating_add(LABEL_OFFSET);
        overwrite_bytes(&mut blob, first_label, b"2");
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::SlotIdentifier))
            ),
            "a label spelled like a later slot's id must be rejected"
        );
        Ok(())
    }

    /// A label spelled like its own slot's decimal id is rejected: even a
    /// single-slot file would otherwise carry two spellings of one token.
    #[test]
    fn label_spelled_like_its_own_id_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "q")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let label = slot_start(&blob, 0).saturating_add(LABEL_OFFSET);
        overwrite_bytes(&mut blob, label, b"7");
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::SlotIdentifier))
            ),
            "a label spelled like its own slot's id must be rejected"
        );
        Ok(())
    }

    /// A label carrying a character that cannot be rendered is rejected: the
    /// diagnostics interpolate a label verbatim, so LF, DEL or a C1 byte would
    /// let a file forge a summary line, and a bidirectional control would let
    /// it reorder one.
    #[test]
    fn unrenderable_label_rejected() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(7, "abc")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let label = slot_start(&blob, 0).saturating_add(LABEL_OFFSET);
        // Every case is three bytes, the fixture label's length: LF, DEL, a C1
        // control, the line and paragraph separators, and the three
        // bidirectional controls with distinct roles (LRM, RLO, LRI).
        for bytes in [
            [0x0a, b'b', b'c'],
            [0x7f, b'b', b'c'],
            [0xc2, 0x85, b'c'],
            [0xe2, 0x80, 0x8e],
            [0xe2, 0x80, 0xae],
            [0xe2, 0x81, 0xa6],
            [0xe2, 0x80, 0xa8],
            [0xe2, 0x80, 0xa9],
        ] {
            let mut mutated = blob.clone();
            overwrite_bytes(&mut mutated, label, &bytes);
            assert!(
                matches!(
                    KeytabEnvelope::parse(&mutated),
                    Err(EnvelopeError::Malformed(Malformed::SlotLabel))
                ),
                "a label carrying {bytes:?} must be rejected"
            );
        }
        Ok(())
    }

    /// A label of exactly the cap is accepted: 64 bytes is the longest legal
    /// label, and `>=` there would refuse it.
    #[test]
    fn label_at_the_cap_is_accepted() -> TestResult {
        let label = "a".repeat(MAX_SLOT_LABEL_LEN);
        let blob = seal(PLAINTEXT, &[raw_recipient(7, &label)], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let summaries = envelope.slot_summaries();
        let first = summaries.first().cloned().unwrap_or_default();
        assert!(
            first.contains(&label),
            "a 64-byte label is legal and must survive parsing"
        );
        Ok(())
    }

    /// A header claiming to run to the end of the file is rejected on the
    /// length identity, not on the header bound: the two checks are ordered,
    /// and the variant says which rule caught the file.
    #[test]
    fn header_length_equal_to_the_file_is_a_length_identity_failure() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let file_len = u32::try_from(blob.len()).unwrap_or_default();
        for (index, byte) in file_len.to_le_bytes().iter().enumerate() {
            if let Some(cell) = blob.get_mut(16 + index) {
                *cell = *byte;
            }
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::LengthIdentity))
            ),
            "a header reaching the end of the file must fail the length identity"
        );
        Ok(())
    }

    /// A payload longer than the cap is rejected on its own rule, before any
    /// length identity or cryptographic work - and `seal` refuses to write such
    /// a file in the first place.
    #[test]
    fn payload_over_the_cap_rejected() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        // Bytes 45..53 are `payload_len`: magic 14, version 2, `header_len` 4,
        // `payload_alg` 1, `payload_nonce` 24.
        let over = u64::try_from(MAX_PAYLOAD_LEN.saturating_add(1)).unwrap_or(u64::MAX);
        if let Some(field) = blob.get_mut(45..53) {
            field.copy_from_slice(&over.to_le_bytes());
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&blob),
                Err(EnvelopeError::Malformed(Malformed::PayloadLength))
            ),
            "a declared payload over the cap must be rejected on its length rule"
        );
        Ok(())
    }

    /// A payload of exactly the cap is accepted: the length check bounds the
    /// allocation, and an off-by-one there would refuse a legitimate
    /// maximum-size blob.
    #[test]
    fn payload_at_the_cap_is_accepted() -> TestResult {
        let plaintext = vec![0x41; MAX_PAYLOAD_LEN];
        let blob = seal(&plaintext, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        let selected = envelope
            .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
            .map_err(|error| format!("select failed: {error}"))?;
        let opened = selected
            .unlock(&credential, &Argon2Kdf)
            .map_err(|error| format!("unlock failed: {error}"))?;
        assert_eq!(
            opened.len(),
            MAX_PAYLOAD_LEN,
            "the whole payload round-trips"
        );
        Ok(())
    }

    /// The slot summaries name every slot: a caller shows them when it has to
    /// ask which slot to use, and an empty or constant list would leave nothing
    /// to choose from.
    #[test]
    fn slot_summaries_name_every_slot() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(7, "operator"), passphrase_recipient(8, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let summaries = envelope.slot_summaries();
        assert_eq!(summaries.len(), 2, "both slots are described");
        let first = summaries.first().cloned().unwrap_or_default();
        assert!(
            first.contains('7') && first.contains("operator") && first.contains("raw key"),
            "the first summary names id, label and kind, got {first}"
        );
        let second = summaries.get(1).cloned().unwrap_or_default();
        assert!(
            second.contains('8') && second.contains("pod") && second.contains("passphrase"),
            "the second summary names id, label and kind, got {second}"
        );
        Ok(())
    }

    /// The two error types render a message, and the rendering is stable
    /// enough to show an operator.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/format.rs::errors_render_messages keeps the uniform test signature while it only asserts"
    )]
    fn errors_render_messages() -> TestResult {
        let malformed = EnvelopeError::Malformed(Malformed::SlotCount);
        assert!(
            malformed.to_string().contains("slot count"),
            "the malformed rendering names the violation, got {malformed}"
        );
        Ok(())
    }
}
