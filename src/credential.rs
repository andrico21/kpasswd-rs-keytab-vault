//! The credential material: what a caller names to select and open a slot, and
//! the raw-key rule that turns bytes into a 32-byte KEK.
//!
//! Every variant that carries a secret has a manual `Debug` that names the
//! shape and never the bytes, because a derived one would put a KEK or a
//! passphrase into any log line that formats the caller's input.
use core::fmt;
use core::str::from_utf8;

use zeroize::Zeroizing;

use crate::format::{EnvelopeError, HEX_KEY_LEN, KEK_LEN, Malformed, RAW_KEY_LEN, SlotType};

/// Which slot to unlock with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotSelector<'selector> {
    /// The slot at this position in the file, counted from zero.
    Index(u8),
    /// The slot with this label.
    Label(&'selector str),
}

/// A credential presented to a slot.
///
/// The variants are not interchangeable, which is why they are a type rather
/// than a bare byte slice: a passphrase passed as a raw key would skip Argon2
/// entirely. The raw key's length is part of its type, so a key of another
/// length cannot be constructed at all.
///
/// The two passphrase variants differ in ownership, not meaning. `Passphrase`
/// borrows text the caller holds, and the crate copies it into a buffer of its
/// own that is wiped on drop. [`SlotCredential::PassphraseOwned`] takes a
/// `Zeroizing` buffer the caller already has, such as a passphrase read from a
/// file, and moves it in without a second copy.
#[non_exhaustive]
pub enum SlotCredential<'bytes> {
    /// A KEK used directly: exactly `KEK_LEN` bytes, never derived.
    RawKey(&'bytes [u8; KEK_LEN]),
    /// Passphrase text, derived with Argon2id.
    Passphrase(&'bytes [u8]),
    /// Passphrase text the caller already owns: moved in, never copied, and
    /// zeroized when this value is dropped.
    PassphraseOwned(Zeroizing<Vec<u8>>),
}

impl SlotCredential<'_> {
    /// Which slot kind this credential can open. A raw key opens raw-key slots,
    /// a passphrase opens passphrase slots; nothing else is possible, which is
    /// what makes "no selector given" resolvable.
    #[must_use]
    #[inline]
    pub const fn kind(&self) -> SlotType {
        match self {
            Self::RawKey(_) => SlotType::RawKey,
            // Wildcards, not bindings: or-patterns cannot bind a name to the
            // two differently borrowed payloads, and only the kind is wanted.
            Self::Passphrase(_) | Self::PassphraseOwned(_) => SlotType::Passphrase,
        }
    }

    /// The passphrase text, whichever variant carries it; `None` for a raw key.
    ///
    /// One accessor rather than one match arm per variant: the unlock, the
    /// rewrap and the seal all want the bytes and none of them may care which
    /// variant the caller handed over, and a caller that owns the text must not
    /// be a second code path anywhere below this.
    #[must_use]
    #[inline]
    pub(crate) fn passphrase(&self) -> Option<&[u8]> {
        match self {
            Self::RawKey(_key) => None,
            Self::Passphrase(text) => Some(text),
            Self::PassphraseOwned(text) => Some(text),
        }
    }
}

impl fmt::Debug for SlotCredential<'_> {
    /// Every variant is secret: a raw slot key and a passphrase alike. A raw
    /// key's length is its type, so naming it discloses nothing; a passphrase's
    /// length is caller information, so it is not named. The bytes are never
    /// printed, and the variants still name themselves, so a caller reading a
    /// dump can tell which one it built.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawKey(bytes) => write!(
                f,
                "SlotCredential::RawKey(<redacted>, {} bytes)",
                bytes.len()
            ),
            Self::Passphrase(_text) => f.write_str("SlotCredential::Passphrase(<redacted>)"),
            Self::PassphraseOwned(_text) => {
                f.write_str("SlotCredential::PassphraseOwned(<redacted>)")
            }
        }
    }
}

/// What one recipient contributes when sealing an envelope.
#[non_exhaustive]
pub struct Recipient<'text> {
    /// Slot id.
    pub id: u32,
    /// Slot label.
    pub label: &'text str,
    /// What unlocks the slot.
    pub credential: SlotCredential<'text>,
}

impl<'text> Recipient<'text> {
    /// One keyslot's recipient: who can unlock, and with what.
    #[must_use]
    #[inline]
    pub const fn new(id: u32, label: &'text str, credential: SlotCredential<'text>) -> Self {
        Self {
            id,
            label,
            credential,
        }
    }
}

impl fmt::Debug for Recipient<'_> {
    /// The id and label are the caller's own; the credential redacts.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recipient")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("credential", &self.credential)
            .finish()
    }
}

/// The raw-key rule: exactly 32 bytes are the key, unchanged and never trimmed.
///
/// Otherwise one trailing line ending is removed and exactly 64 ASCII hex
/// characters decode to the key; anything else is an error.
///
/// Length-first is deliberate. Trimming a newline before measuring would
/// silently truncate any random 32-byte key whose final byte happens to be
/// `0x0a` - an intermittent failure of roughly one in 256 keys. Two
/// consequences follow and are intentional: a 32-byte input that happens to
/// spell ASCII hex is used as raw bytes, and a 64-byte *binary* input is not
/// a raw key unless every byte is ASCII hex.
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::SlotPairing)` when the input is
/// neither exactly 32 raw bytes nor one trailing line ending followed by
/// exactly 64 ASCII hex characters.
#[inline]
pub fn raw_key_from_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; KEK_LEN]>, EnvelopeError> {
    if bytes.len() == RAW_KEY_LEN {
        let key: [u8; KEK_LEN] = bytes
            .try_into()
            .map_err(|_length_error| EnvelopeError::Malformed(Malformed::SlotPairing))?;
        return Ok(Zeroizing::new(key));
    }
    let trimmed = strip_one_line_ending(bytes);
    if trimmed.len() != HEX_KEY_LEN {
        return Err(EnvelopeError::Malformed(Malformed::SlotPairing));
    }
    decode_hex_key(trimmed)
}

/// Remove at most one trailing line ending: `\r\n`, else `\n`, else nothing.
#[inline]
#[must_use]
pub fn strip_one_line_ending(bytes: &[u8]) -> &[u8] {
    if let Some(stripped) = bytes.strip_suffix(b"\r\n") {
        return stripped;
    }
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

/// Decode exactly 64 ASCII hex characters into 32 bytes.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::SlotPairing)` when any byte pair is not UTF-8
/// ASCII hex.
fn decode_hex_key(text: &[u8]) -> Result<Zeroizing<[u8; KEK_LEN]>, EnvelopeError> {
    let mut key = Zeroizing::new([0; KEK_LEN]);
    for (index, pair) in text.chunks(2).enumerate() {
        let pair_text = from_utf8(pair)
            .map_err(|_encoding_error| EnvelopeError::Malformed(Malformed::SlotPairing))?;
        // The character class is checked before the decode: `u8::from_str_radix`
        // also accepts a leading `+`, which would make the accepted input wider
        // than the documented "64 ASCII hex characters".
        if !pair_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(EnvelopeError::Malformed(Malformed::SlotPairing));
        }
        let byte = u8::from_str_radix(pair_text, 16)
            .map_err(|_digit_error| EnvelopeError::Malformed(Malformed::SlotPairing))?;
        if let Some(cell) = key.get_mut(index) {
            *cell = byte;
        }
    }
    Ok(key)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::*;
    use crate::test_support::*;

    /// The raw key's length is its type (B10): `SlotCredential::RawKey` takes
    /// `&[u8; KEK_LEN]`, so a raw key of any other length is not a value this
    /// code can receive and no runtime length check survives on any path. This
    /// is the positive half - the typed credential seals and opens a raw-key
    /// slot - and the signature is the negative half: the wrong length does not
    /// type-check, which is a stronger statement than a test can make.
    #[test]
    fn slot_credential_raw_key_is_exact_length_by_type() {
        let credential = SlotCredential::RawKey(&RAW_KEY);
        assert_eq!(
            credential.kind(),
            SlotType::RawKey,
            "a raw key opens raw-key slots and nothing else"
        );
        assert_eq!(
            roundtrip(&[raw_recipient(7, "operator")], &credential),
            PLAINTEXT,
            "the typed credential is what the seal path took"
        );
        let rendered = format!("{credential:?}");
        assert!(
            rendered.contains(&KEK_LEN.to_string()),
            "the redacting rendering still names the type's length, got {rendered}"
        );
    }

    /// The raw-key rule's regression test: exactly 32 bytes are the key,
    /// even when the last byte is `0x0a`.
    #[test]
    #[expect(clippy::panic, reason = "key parsing failing means the rule is broken")]
    fn raw_key_32_bytes_ending_in_0x0a_accepted() {
        let mut bytes = RAW_KEY;
        if let Some(last) = bytes.last_mut() {
            *last = 0x0a;
        }
        let parsed = raw_key_from_bytes(&bytes)
            .unwrap_or_else(|error| panic!("a 32-byte key must be accepted: {error}"));
        assert_eq!(
            parsed.as_slice(),
            bytes.as_slice(),
            "a 32-byte key is used unchanged, never trimmed"
        );
        // The hex branch: 64 characters plus one trailing newline decode.
        let hex_text = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        let decoded = raw_key_from_bytes(hex_text)
            .unwrap_or_else(|error| panic!("64 hex characters must decode: {error}"));
        assert_eq!(
            decoded.as_slice(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff,
            ],
            "hex decodes in order"
        );
        assert!(
            raw_key_from_bytes(b"too short").is_err(),
            "a short input is not a raw key"
        );
    }

    /// The hex branch accepts exactly ASCII hex: `u8::from_str_radix` alone also
    /// takes a leading `+`, so the character class is checked first and the
    /// accepted set is literal.
    #[test]
    fn hex_key_accepts_only_ascii_hex_characters() {
        let mut with_plus = [b'0'; HEX_KEY_LEN];
        with_plus[0] = b'+';
        with_plus[1] = b'a';
        assert!(
            raw_key_from_bytes(&with_plus).is_err(),
            "a leading `+` is not a hex character"
        );
        let mut both_spellings = [b'0'; HEX_KEY_LEN];
        both_spellings[0] = b'A';
        both_spellings[1] = b'f';
        assert!(
            raw_key_from_bytes(&both_spellings).is_ok(),
            "both hex spellings decode"
        );
    }

    /// A passphrase's length is caller information, so the redacting rendering
    /// does not name it; a raw key's length is its type, so that one does.
    #[test]
    fn passphrase_debug_does_not_name_its_length() {
        let rendered = format!("{:?}", SlotCredential::Passphrase(PASSPHRASE));
        assert!(
            rendered.contains("<redacted>"),
            "the rendering still says what it is, got {rendered}"
        );
        assert!(
            !rendered.contains(&PASSPHRASE.len().to_string()),
            "a passphrase's length is not named, got {rendered}"
        );
        let owned = SlotCredential::PassphraseOwned(Zeroizing::new(PASSPHRASE.to_vec()));
        let rendered_owned = format!("{owned:?}");
        assert!(
            !rendered_owned.contains(&PASSPHRASE.len().to_string()),
            "the owned variant does not name the length either, got {rendered_owned}"
        );
    }
}
