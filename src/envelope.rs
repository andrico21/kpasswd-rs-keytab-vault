//! The parsed envelope, a resolved selection, and the AEAD operations that
//! open them.
//!
//! This is the only module that holds a cipher: the payload and every DEK wrap
//! are XChaCha20-Poly1305, and both take associated data assembled here - the
//! header for the payload, the slot's own prefix plus the file identity for a
//! wrap.
#![expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/envelope.rs::envelope the envelope's crate-visible helpers and the fields a rotation reads are shared with the sibling modules and are not on the crate's flat surface."
)]

use core::fmt;

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::{
    credential::{SlotCredential, SlotSelector},
    format::{
        Cursor, DEK_LEN, EnvelopeError, FILE_ID_LEN, FIXED_HEADER_LEN, FORMAT_VERSION,
        KDF_BLOCK_LEN, KEK_LEN, MAGIC, MAX_HEADER_LEN, MAX_PAYLOAD_LEN, MAX_SLOTS, MIN_SLOTS,
        Malformed, NONCE_LEN, PAYLOAD_ALG_XCHACHA20_POLY1305, Slot, SlotInfo, SlotType, TAG_LEN,
        WRAP_AAD_MIN_LEN, WRAPPED_DEK_LEN, parse_slot,
    },
    kdf::{KdfBackend, KdfLimits, decode_argon2_block},
};

/// A parsed envelope, ready to select a slot from.
#[non_exhaustive]
pub struct KeytabEnvelope<'file> {
    /// The file's version: the one value this build accepts.
    pub(crate) version: u16,
    /// The file's first `header_len` bytes: the payload AEAD's AAD.
    pub(crate) header: &'file [u8],
    /// The payload ciphertext with its tag.
    pub(crate) ciphertext: &'file [u8],
    /// Payload nonce.
    pub(crate) payload_nonce: [u8; NONCE_LEN],
    /// Plaintext length the header declares.
    pub(crate) payload_len: u64,
    /// The file's identifier: random at seal, and unchanged by every rotation.
    pub(crate) file_id: [u8; FILE_ID_LEN],
    /// The slots, in file order.
    pub(crate) slots: Vec<Slot>,
}

impl<'file> KeytabEnvelope<'file> {
    /// Parse the header, applying every reject rule v1 defines in the order
    /// the format specifies, and keeping the file bytes for the payload AAD.
    /// # Errors
    ///
    /// `EnvelopeError::Malformed` for every structural rule v1 defines, with the
    /// variant naming which one - `Magic`, `Version`, `HeaderLength`,
    /// `HeaderBoundary`, `SlotCount`, `SlotLabel`, `SlotType`, `SlotPairing`,
    /// `SlotIdentifier`, `DuplicateSlot`, `Algorithm`, `PayloadLength` or
    /// `LengthIdentity`, plus `TooShort` from the cursor reads. The variant is
    /// the assertion target; `Display` is prose.
    #[inline]
    pub fn parse(file: &'file [u8]) -> Result<Self, EnvelopeError> {
        let mut cursor = Cursor::new(file);
        let magic = cursor.take(MAGIC.len())?;
        if magic != MAGIC {
            return Err(EnvelopeError::Malformed(Malformed::Magic));
        }
        let version = cursor.take_u16()?;
        // One format, one accepted value: a file from any other format is
        // refused here, on the version, rather than later on a parameter.
        if version != FORMAT_VERSION {
            return Err(EnvelopeError::Malformed(Malformed::Version));
        }
        let raw_header_len = cursor.take_u32()?;
        let payload_alg = cursor.take_u8()?;
        let payload_nonce = cursor.take_array::<NONCE_LEN>()?;
        let raw_payload_len = cursor.take_u64()?;
        let file_id = cursor.take_array::<FILE_ID_LEN>()?;
        let slot_count = cursor.take_u8()?;
        // `header_len` is bounded as an integer before it becomes an index.
        let header_len = usize::try_from(raw_header_len)
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::HeaderLength))?;
        if !(FIXED_HEADER_LEN..=MAX_HEADER_LEN).contains(&header_len) {
            return Err(EnvelopeError::Malformed(Malformed::HeaderLength));
        }
        if header_len > file.len() {
            return Err(EnvelopeError::Malformed(Malformed::HeaderLength));
        }
        if payload_alg != PAYLOAD_ALG_XCHACHA20_POLY1305 {
            return Err(EnvelopeError::Malformed(Malformed::Algorithm));
        }
        let payload_len = usize::try_from(raw_payload_len)
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::PayloadLength))?;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::Malformed(Malformed::PayloadLength));
        }
        let expected_len = header_len
            .checked_add(payload_len)
            .and_then(|sum| sum.checked_add(TAG_LEN))
            .ok_or(EnvelopeError::Malformed(Malformed::LengthIdentity))?;
        if expected_len != file.len() {
            return Err(EnvelopeError::Malformed(Malformed::LengthIdentity));
        }
        let slots_total = usize::from(slot_count);
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots_total) {
            return Err(EnvelopeError::Malformed(Malformed::SlotCount));
        }
        let mut slots: Vec<Slot> = Vec::with_capacity(slots_total);
        for _index in 0..slots_total {
            let slot = parse_slot(&mut cursor, header_len)?;
            if slots
                .iter()
                .any(|parsed| parsed.id == slot.id || parsed.label == slot.label)
            {
                return Err(EnvelopeError::Malformed(Malformed::DuplicateSlot));
            }
            // One selection token must never name two slots: a label spelled
            // exactly like any id would do exactly that.
            if slots
                .iter()
                .any(|parsed| parsed.label == slot.id.to_string())
                || slots
                    .iter()
                    .any(|parsed| slot.label == parsed.id.to_string())
                || slot.label == slot.id.to_string()
            {
                return Err(EnvelopeError::Malformed(Malformed::SlotIdentifier));
            }
            slots.push(slot);
        }
        if cursor.offset() != header_len {
            return Err(EnvelopeError::Malformed(Malformed::HeaderBoundary));
        }
        let header = file
            .get(..header_len)
            .ok_or(EnvelopeError::Malformed(Malformed::HeaderLength))?;
        let ciphertext = file
            .get(header_len..)
            .ok_or(EnvelopeError::Malformed(Malformed::LengthIdentity))?;
        Ok(Self {
            version,
            header,
            ciphertext,
            payload_nonce,
            payload_len: raw_payload_len,
            file_id,
            slots,
        })
    }

    /// One line per slot, naming its id, label and kind, for diagnostics.
    #[inline]
    pub fn slot_summaries(&self) -> Vec<String> {
        self.slots.iter().map(Slot::describe).collect()
    }

    /// Every slot in the file, in file order: id, label and kind.
    ///
    /// Use it to choose the [`SlotSelector`] to unlock with. Ids and labels are
    /// unique within a file and no label is spelled like an id, so an id or a
    /// label names at most one slot.
    #[must_use]
    #[inline]
    pub fn slots(&self) -> Vec<SlotInfo> {
        self.slots
            .iter()
            .map(|slot| SlotInfo {
                id: slot.id,
                label: slot.label.clone(),
                kind: slot.kind,
            })
            .collect()
    }

    /// Resolve a selector to a position in the file.
    /// # Errors
    ///
    /// `Malformed(SlotIdentifier)` when an index names no slot,
    /// `Malformed(SlotLabel)` when a label names none or - impossibly for a
    /// parsed file - more than one.
    pub(crate) fn select_position(
        &self,
        selector: SlotSelector<'_>,
    ) -> Result<usize, EnvelopeError> {
        match selector {
            SlotSelector::Index(position) => {
                let index = usize::from(position);
                if index >= self.slots.len() {
                    return Err(EnvelopeError::Malformed(Malformed::SlotIdentifier));
                }
                Ok(index)
            }
            SlotSelector::Label(label) => {
                let mut matched = self
                    .slots
                    .iter()
                    .enumerate()
                    .filter(|(_position, slot)| slot.label == label)
                    .map(|(position, _slot)| position);
                match (matched.next(), matched.next()) {
                    (Some(position), None) => Ok(position),
                    (None, _) | (Some(_), Some(_)) => {
                        Err(EnvelopeError::Malformed(Malformed::SlotLabel))
                    }
                }
            }
        }
    }

    /// Locate a slot in the file and gather what unlocking it needs.
    ///
    /// A selector cannot be ambiguous: an index either exists or does not, and a
    /// label either names exactly one slot or the file violates its own
    /// uniqueness rule. A selector that matches nothing is
    /// `Malformed(SlotIdentifier)` for an index and `Malformed(SlotLabel)` for a
    /// label.
    ///
    /// # Errors
    ///
    /// `Malformed(SlotIdentifier)` when the index names no slot and
    /// `Malformed(SlotLabel)` when the label names none. The credential and the
    /// Argon2id parameters are not checked here; [`Selection::unlock`] does that.
    #[inline]
    pub fn select_slot(
        &self,
        selector: SlotSelector<'_>,
        limits: &KdfLimits,
        // Not consulted: a selector is explicit, and the credential's kind is
        // checked when the slot is unlocked. It stays in the signature because
        // every caller has it and the pairing is what it means.
        _credential: &SlotCredential<'_>,
    ) -> Result<Selection<'file>, EnvelopeError> {
        let index = self.select_position(selector)?;
        let slot = self
            .slots
            .get(index)
            .ok_or(EnvelopeError::Malformed(Malformed::SlotIdentifier))?;
        let identity = wrap_identity(self.version, self.payload_len, &self.file_id);
        let wrap_aad = wrap_aad_for(&identity, &slot.wrap_prefix);
        Ok(Selection {
            header: self.header,
            ciphertext: self.ciphertext,
            payload_nonce: self.payload_nonce,
            wrap_nonce: slot.wrap_nonce,
            wrapped_dek: slot.wrapped_dek,
            wrap_aad,
            kind: slot.kind,
            kdf: slot.kdf,
            limits: *limits,
        })
    }
}

/// The wrap identity every wrap AAD begins with: magic, version,
/// `payload_alg`, `payload_len`, `file_id`.
///
/// Assembled rather than sliced because `header_len`, `payload_nonce` and
/// `slot_count` sit among these fields on the wire. Leaving `payload_nonce` out
/// is what lets a rotation re-encrypt the payload under a fresh nonce while the
/// slots it does not touch keep authenticating; carrying `file_id` is what stops
/// a slot being spliced in from another file (KRP-93).
pub(crate) fn wrap_identity(
    version: u16,
    payload_len: u64,
    file_id: &[u8; FILE_ID_LEN],
) -> Vec<u8> {
    let mut identity = Vec::with_capacity(41);
    identity.extend_from_slice(MAGIC);
    identity.extend_from_slice(&version.to_le_bytes());
    identity.push(PAYLOAD_ALG_XCHACHA20_POLY1305);
    identity.extend_from_slice(&payload_len.to_le_bytes());
    identity.extend_from_slice(file_id);
    identity
}

/// One slot's wrap AAD: the wrap identity, then that slot's prefix.
pub(crate) fn wrap_aad_for(identity: &[u8], prefix: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_MIN_LEN);
    aad.extend_from_slice(identity);
    aad.extend_from_slice(prefix);
    aad
}

/// A slot chosen for unlocking: the slot's own material and the payload's.
///
/// [`KeytabEnvelope::select_slot`] produces it, and [`Selection::unlock`] is
/// where the credential's kind is checked against the slot's: this type carries
/// what an unlock needs, not a decision that one may proceed.
#[non_exhaustive]
pub struct Selection<'file> {
    /// The file's first `header_len` bytes: the payload AEAD's AAD.
    pub(crate) header: &'file [u8],
    /// The payload ciphertext with its tag.
    pub(crate) ciphertext: &'file [u8],
    /// Payload nonce.
    pub(crate) payload_nonce: [u8; NONCE_LEN],
    /// The selected slot's wrap nonce.
    pub(crate) wrap_nonce: [u8; NONCE_LEN],
    /// The selected slot's wrapped DEK.
    pub(crate) wrapped_dek: [u8; WRAPPED_DEK_LEN],
    /// The selected slot's wrap AAD.
    pub(crate) wrap_aad: Vec<u8>,
    /// Which kind of credential this slot needs.
    pub(crate) kind: SlotType,
    /// The selected slot's raw Argon2 block, for passphrase slots.
    pub(crate) kdf: Option<[u8; KDF_BLOCK_LEN]>,
    /// The band this selection honours: exactly the caller's.
    ///
    /// The format pins no parameter set, so the band the caller passes is the
    /// only guard over what an attacker-supplied file may ask for.
    pub(crate) limits: KdfLimits,
}

impl Selection<'_> {
    /// Unwrap the DEK with `credential`, then decrypt the payload.
    ///
    /// `kdf` is reached exactly once, and only for a passphrase slot: a
    /// raw-key selection never touches the trait.
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::SlotPairing)` when the credential is
    /// not the kind this slot needs, `EnvelopeError::AuthenticationFailed` when
    /// either AEAD tag fails to verify - a wrong key, an altered header, an
    /// altered ciphertext and a swapped slot all land there - and whatever the
    /// injected [`KdfBackend`] returns for a passphrase slot.
    #[inline]
    pub fn unlock(
        &self,
        credential: &SlotCredential<'_>,
        kdf: &dyn KdfBackend,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let (_dek, plaintext) = self.open(credential, kdf)?;
        Ok(plaintext)
    }

    /// Unwrap the data key **and** decrypt the payload: the whole unlock, in one
    /// AEAD operation per step.
    ///
    /// Rotation needs both halves - the unchanged key to rewrap the slot and
    /// re-encrypt the payload, and the plaintext to re-encrypt - and it needs
    /// them from a single unwrap, so the wrap is opened once rather than twice
    /// under the same nonce.
    /// # Errors
    ///
    /// The same failures [`Selection::unlock`] reports, plus the wrap's own.
    #[expect(
        clippy::type_complexity,
        reason = "deliberate: src/envelope.rs::open the pair *is* the unlock's result: the key a rotation rewraps and the plaintext it re-encrypts"
    )]
    pub(crate) fn open(
        &self,
        credential: &SlotCredential<'_>,
        kdf: &dyn KdfBackend,
    ) -> Result<(Zeroizing<[u8; DEK_LEN]>, Zeroizing<Vec<u8>>), EnvelopeError> {
        let dek = self.unwrap_dek(credential, kdf)?;
        let cipher = cipher_from_key(&dek);
        let payload_nonce = nonce_from_bytes(&self.payload_nonce)?;
        let plaintext = Aead::decrypt(
            &cipher,
            &payload_nonce,
            Payload {
                msg: self.ciphertext,
                aad: self.header,
            },
        )
        .map_err(|_authentication_error| EnvelopeError::AuthenticationFailed)?;
        Ok((dek, Zeroizing::new(plaintext)))
    }

    /// Checks this slot's Argon2id parameters against the selection's limits,
    /// without deriving or decrypting anything.
    ///
    /// It is the same check the unlock runs before any derivation. A raw-key
    /// slot has no parameters, so it always passes. Use it to report a refusal
    /// with the format's own error before an exchange begins; skipping it
    /// weakens nothing, because the unlock checks again.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::Argon2Parameters)` when the block is
    /// outside the band or cannot be decoded, and
    /// `EnvelopeError::Malformed(Malformed::SlotPairing)` when a passphrase slot
    /// carries no block at all.
    #[inline]
    pub fn check_cost_band(&self) -> Result<(), EnvelopeError> {
        match self.kind {
            SlotType::RawKey => Ok(()),
            SlotType::Passphrase => {
                let block = self
                    .kdf
                    .as_ref()
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                decode_argon2_block(block, &self.limits).map(|_params| ())
            }
        }
    }

    /// Unwrap this slot's data-encryption key.
    ///
    /// `kdf` is reached exactly once, and only for a passphrase slot: a raw-key
    /// selection never touches the trait.
    ///
    /// # Errors
    ///
    /// `EnvelopeError::Malformed(Malformed::SlotPairing)` when the credential is
    /// not the kind this slot needs, `EnvelopeError::AuthenticationFailed` when
    /// the wrap's tag fails to verify, and whatever the injected
    /// [`KdfBackend`] returns for a passphrase slot.
    pub(crate) fn unwrap_dek(
        &self,
        credential: &SlotCredential<'_>,
        kdf: &dyn KdfBackend,
    ) -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
        let kek: Zeroizing<[u8; KEK_LEN]> = match (self.kind, credential) {
            // No length check: the variant's type is the check (B10). The array
            // is copied into an owned, zeroizing KEK.
            (SlotType::RawKey, SlotCredential::RawKey(key)) => Zeroizing::new(**key),
            (
                SlotType::Passphrase,
                candidate @ (SlotCredential::Passphrase(_) | SlotCredential::PassphraseOwned(_)),
            ) => {
                // Both passphrase variants carry the same text, borrowed; a raw
                // key is not among them, and the wildcard arm says so.
                let text = candidate
                    .passphrase()
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                let block = self
                    .kdf
                    .as_ref()
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                // The band is checked here, before the backend is reached: the
                // block is attacker-supplied input, so one outside the band must
                // cost a comparison rather than a call into a KDF - and that has
                // to hold for whatever backend a caller injects, not only for
                // `Argon2Kdf` (SOW B6c). `Argon2Kdf` re-decodes the same block,
                // so this decode exists to keep the refusal independent of it.
                let _: argon2::Params = decode_argon2_block(block, &self.limits)?;
                kdf.derive_argon2id(text, block, &self.limits)?
            }
            (_mismatch, _credential) => {
                return Err(EnvelopeError::Malformed(Malformed::SlotPairing));
            }
        };
        unwrap_dek(&kek, &self.wrap_nonce, &self.wrapped_dek, &self.wrap_aad)
    }
}

/// Wrap a DEK under a KEK: the sealing half's operation (KRP-88 ships it).
///
/// # Errors
///
/// `EnvelopeError::AuthenticationFailed` when XChaCha20-Poly1305 cannot produce the
/// fixed-size wrapped DEK.
pub(crate) fn wrap_dek(
    kek: &[u8; KEK_LEN],
    nonce: &[u8; NONCE_LEN],
    dek: &[u8; DEK_LEN],
    aad: &[u8],
) -> Result<[u8; WRAPPED_DEK_LEN], EnvelopeError> {
    let cipher = cipher_from_key(kek);
    let wrap_nonce = nonce_from_bytes(nonce)?;
    let wrapped = Aead::encrypt(
        &cipher,
        &wrap_nonce,
        Payload {
            msg: dek.as_slice(),
            aad,
        },
    )
    .map_err(|_encryption_error| EnvelopeError::AuthenticationFailed)?;
    wrapped
        .try_into()
        .map_err(|_length_error| EnvelopeError::AuthenticationFailed)
}

/// Unwrap a DEK under a KEK, requiring the slot's AAD to match.
///
/// The `Vec<u8>` `Aead::decrypt` returns **is** the DEK, so it is bound inside
/// the `Zeroizing` that wipes it; only the typed copy is taken out of it, which
/// is what keeps every owned DEK in a wiping buffer for its whole lifetime (B6).
///
/// # Errors
///
/// `EnvelopeError::AuthenticationFailed` when the wrapped DEK does not authenticate with the
/// supplied KEK, nonce, and AAD, or does not decrypt to one DEK.
fn unwrap_dek(
    kek: &[u8; KEK_LEN],
    nonce: &[u8; NONCE_LEN],
    wrapped: &[u8; WRAPPED_DEK_LEN],
    aad: &[u8],
) -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
    let cipher = cipher_from_key(kek);
    let wrap_nonce = nonce_from_bytes(nonce)?;
    // The decrypt's `Vec<u8>` **is** the DEK, so it is bound inside the
    // `Zeroizing` that wipes it: copying the bytes into a second buffer and
    // dropping the decrypt's own unwiped would leave the key in memory however
    // carefully the copy is handled (B6).
    let dek = Zeroizing::new(
        Aead::decrypt(
            &cipher,
            &wrap_nonce,
            Payload {
                msg: wrapped.as_slice(),
                aad,
            },
        )
        .map_err(|_authentication_error| EnvelopeError::AuthenticationFailed)?,
    );
    let unwrapped: Zeroizing<[u8; DEK_LEN]> = Zeroizing::new(
        dek.as_slice()
            .try_into()
            .map_err(|_length_error| EnvelopeError::AuthenticationFailed)?,
    );
    Ok(unwrapped)
}

/// Build an XChaCha20-Poly1305 cipher from 32 bytes of key material.
///
/// The caller's array is handed to the cipher by reference - `&[u8; 32]`
/// converts to `&chacha20poly1305::Key` without a copy - so this function
/// holds no copy of the key that could outlive it. The cipher keeps its own
/// copy and wipes it on drop (`chacha20poly1305`'s `zeroize` feature).
pub(crate) fn cipher_from_key(key: &[u8; KEK_LEN]) -> XChaCha20Poly1305 {
    <XChaCha20Poly1305 as KeyInit>::new(key.into())
}

/// Build an XChaCha20-Poly1305 nonce from 24 bytes.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::SlotPairing)` if the fixed-size nonce material is not
/// accepted by the nonce constructor.
pub(crate) fn nonce_from_bytes(
    bytes: &[u8; NONCE_LEN],
) -> Result<chacha20poly1305::XNonce, EnvelopeError> {
    chacha20poly1305::XNonce::try_from(bytes.as_slice())
        .map_err(|_length_error| EnvelopeError::Malformed(Malformed::SlotPairing))
}

impl fmt::Debug for KeytabEnvelope<'_> {
    /// The envelope is sealed, so no plaintext is at risk, but its bytes are
    /// noise rather than information: lengths identify it for a reader.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeytabEnvelope")
            .field("version", &self.version)
            .field("header_len", &self.header.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .field("payload_nonce", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Selection<'_> {
    /// Same reasoning as `KeytabEnvelope`: the selection is what the unlock
    /// chose, and its lengths are what a reader needs.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Selection")
            .field("header_len", &self.header.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
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
    use crate::{
        seal::{seal_with, tests::deterministic_material},
        test_support::*,
        *,
    };

    /// The pinned bytes of [`golden_passphrase_vector_matches`]: slot 9,
    /// label `operator`, sealed with [`PASSPHRASE`].
    const GOLDEN_PASSPHRASE_FILE: &str = "4b524252455345544b45595441420100c20000000122232425262728292a2b2c2d2e2f30313233343536373839140000000000000052535455565758595a5b5c5d5e5f6061010900000002086f70657261746f72021300000042434445464748494a4b4c4d4e4f5051000001000300000004000000200000000132333435363738393a3b3c3d3e3f40414243444546474849563086b1ecc1d3c208b72505af635e696b299c64943d59cf9ef855090fccd6e600ce449d2e824e08a9233f863558f6c3d99682d97e459a4645dc0b5c4a25c2cdff5c999060d3a8a446805fcc436f74f09cc4ccb6";

    /// The pinned bytes of [`golden_raw_key_vector_matches`], regenerated
    /// only when the format changes deliberately.
    const GOLDEN_RAW_KEY_FILE: &str = "4b524252455345544b455954414201009e000000012122232425262728292a2b2c2d2e2f30313233343536373814000000000000005152535455565758595a5b5c5d5e5f60010700000001086f70657261746f7201013132333435363738393a3b3c3d3e3f4041424344454647481f81af35c1b542b80c6a55fc6520e6de18baee9f864196f52934a1eb89b5470a28d515281b74e80e79c7b6ce08e7d67a4e9794b98ee0ced6be79bec45d99dded1c21a56aa40f2f5174fc1890241d8353327ecc96";

    /// `cipher_from_key` holds no copy of the key: the caller's array goes into
    /// the cipher by reference, so nothing is left behind for a wipe to miss.
    #[test]
    fn cipher_from_key_binds_no_copy_of_the_key() -> TestResult {
        let source = production_text(include_str!("envelope.rs"));
        let start = source
            .find("pub(crate) fn cipher_from_key(")
            .ok_or("`cipher_from_key` must still exist")?;
        let body = source.get(start..).unwrap_or_default();
        let end = body.find("\n}").unwrap_or(body.len());
        let window = body.get(..end).unwrap_or_default();
        for copy in ["let ", "Key::", ".clone()", "to_vec(", "copy_from_slice("] {
            assert!(
                !window.contains(copy),
                "`cipher_from_key` must not hold its own copy of the key (found `{copy}`)"
            );
        }
        Ok(())
    }

    /// The cipher's own copy of the key is wiped when the cipher is dropped.
    ///
    /// `chacha20poly1305`'s `zeroize` feature does the wipe; this pins the
    /// feature. The cipher sits 32 bytes into its heap block, clear of the
    /// free-list bookkeeping the allocator writes at the start of a freed block,
    /// and the block is read back through `/proc/self/mem` after it is freed.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/envelope.rs::a_dropped_cipher_wipes_its_key keeps the uniform test signature while it only asserts"
    )]
    fn a_dropped_cipher_wipes_its_key() -> TestResult {
        use core::ptr;

        /// A cipher at a fixed offset from the start of its heap block.
        #[repr(C)]
        struct Padded {
            /// Keeps the cipher clear of the allocator's bookkeeping.
            _pad: [u8; 32],
            /// The cipher under test.
            cipher: XChaCha20Poly1305,
        }

        /// A byte value a wipe never leaves behind.
        const MARKER: u8 = 0xa5;

        let mut memory = FreedMemory::new(KEK_LEN);
        let boxed = Box::new(Padded {
            _pad: [0; 32],
            cipher: cipher_from_key(&[MARKER; KEK_LEN]),
        });
        let address = ptr::from_ref(&boxed.cipher).addr();
        let before = memory.residue(address, MARKER);
        assert_eq!(
            before, KEK_LEN,
            "the key must be in the block before the drop, or the check below proves nothing; {before} of {KEK_LEN} key bytes found"
        );
        drop(boxed);
        let residue = memory.residue(address, MARKER);
        assert_eq!(
            residue, 0,
            "a dropped cipher must not leave its key in freed memory; {residue} key bytes survived"
        );

        // Instrument control: an unwiped block of the same shape is visible, so
        // the zero above is a wipe rather than a blind spot.
        let plain = Box::new([MARKER; 64]);
        let control_address = plain.as_ptr().addr().saturating_add(32);
        drop(plain);
        let control = memory.residue(control_address, MARKER);
        assert_eq!(
            control, KEK_LEN,
            "the instrument must see an unwiped freed block; it saw {control} of {KEK_LEN} bytes"
        );
        Ok(())
    }

    /// The raw-key path round-trips.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/envelope.rs::roundtrip_raw_key_slot keeps the uniform test signature while it only asserts"
    )]
    fn roundtrip_raw_key_slot() -> TestResult {
        let credential = SlotCredential::RawKey(&RAW_KEY);
        assert_eq!(
            roundtrip(&[raw_recipient(7, "operator")], &credential),
            PLAINTEXT
        );
        Ok(())
    }

    /// The passphrase path round-trips through Argon2id at the format's
    /// parameters.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/envelope.rs::roundtrip_passphrase_slot keeps the uniform test signature while it only asserts"
    )]
    fn roundtrip_passphrase_slot() -> TestResult {
        let credential = SlotCredential::Passphrase(PASSPHRASE);
        assert_eq!(
            roundtrip(&[passphrase_recipient(1, "operator")], &credential),
            PLAINTEXT
        );
        Ok(())
    }

    /// A key that is not the sealing key is rejected, not silently accepted.
    #[test]
    fn wrong_key_rejected() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&OTHER_KEY);
        let selected = envelope
            .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
            .map_err(|error| format!("select failed: {error}"))?;
        let outcome = selected.unlock(&credential, &Argon2Kdf);
        assert!(
            matches!(outcome, Err(EnvelopeError::AuthenticationFailed)),
            "a wrong key must fail the wrap tag"
        );
        Ok(())
    }

    /// A passphrase that is not the sealing one must fail authentication.
    ///
    /// Without this, a backend that returned a *constant* KEK would pass the
    /// round-trip test: sealing and unlocking would agree on the same wrong
    /// key. This is the test that makes the derivation load-bearing.
    #[test]
    fn wrong_passphrase_rejected() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::Passphrase(b"not the sealing passphrase");
        let selected = envelope
            .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
            .map_err(|error| format!("select failed: {error}"))?;
        assert!(
            matches!(
                selected.unlock(&credential, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "a wrong passphrase must fail the wrap tag"
        );
        Ok(())
    }

    /// A single flipped payload bit is caught by the tag.
    #[test]
    fn bitflip_rejected_by_tag() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(7, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let mut corrupted = blob;
        let last = corrupted.len().saturating_sub(1);
        if let Some(byte) = corrupted.get_mut(last) {
            *byte ^= 0x01;
        }
        let envelope =
            KeytabEnvelope::parse(&corrupted).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        let selected = envelope
            .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
            .map_err(|error| format!("select failed: {error}"))?;
        assert!(
            matches!(
                selected.unlock(&credential, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "a flipped ciphertext bit must fail the payload tag"
        );
        Ok(())
    }

    /// A swapped slot cannot authenticate: the wrap AAD binds each slot's
    /// own identity, so slot bytes moved between files fail the tag.
    #[test]
    fn slot_swap_rejected_by_aad() -> TestResult {
        let first = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let second = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        // Replace the pod slot's wrapped DEK with the other file's: same id, same
        // label, different wrap nonce and wrapped key. The range is read off the
        // parsed file rather than hardcoded, so a header change cannot silently
        // make this test stop corrupting anything.
        let parsed =
            KeytabEnvelope::parse(&first).map_err(|error| format!("parse failed: {error}"))?;
        let pod = parsed.slots.get(1).ok_or("the pod slot exists")?;
        let start = pod
            .dek_offset
            .checked_sub(pod.wrap_prefix.len())
            .ok_or("the prefix precedes the wrap")?;
        let end = start
            .checked_add(pod.wrap_prefix.len())
            .and_then(|sum| sum.checked_add(WRAPPED_DEK_LEN))
            .ok_or("the slot fits in the file")?;
        let source = second.get(start..end).unwrap_or_default().to_vec();
        let mut swapped = first.clone();
        if let Some(target) = swapped.get_mut(start..end) {
            target.copy_from_slice(&source);
        }
        let envelope =
            KeytabEnvelope::parse(&swapped).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        let selected = envelope
            .select_slot(
                SlotSelector::Label("pod"),
                &KdfLimits::defaults(),
                &credential,
            )
            .map_err(|error| format!("select failed: {error}"))?;
        assert!(
            matches!(
                selected.unlock(&credential, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "a slot's bytes moved between files must fail the wrap tag"
        );
        Ok(())
    }

    /// A structurally matching slot taken from another file does not
    /// authenticate: the wrap transcript carries this file's `file_id`, so bytes
    /// that came from elsewhere cannot be pasted in (KRP-93).
    #[test]
    fn slot_spliced_from_another_file_fails_authentication() -> TestResult {
        let first = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let second = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let parsed =
            KeytabEnvelope::parse(&first).map_err(|error| format!("parse failed: {error}"))?;
        let pod = parsed.slots.get(1).ok_or("the pod slot exists")?;
        let start = pod
            .dek_offset
            .checked_sub(pod.wrap_prefix.len())
            .ok_or("the prefix precedes the wrap")?;
        let end = pod
            .dek_offset
            .checked_add(WRAPPED_DEK_LEN)
            .ok_or("the wrap fits")?;
        let donor = second.get(start..end).unwrap_or_default().to_vec();
        let mut spliced = first.clone();
        if let Some(target) = spliced.get_mut(start..end) {
            target.copy_from_slice(&donor);
        }
        let envelope =
            KeytabEnvelope::parse(&spliced).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        assert!(
            matches!(
                envelope
                    .select_slot(
                        SlotSelector::Label("pod"),
                        &KdfLimits::defaults(),
                        &credential
                    )
                    .map_err(|error| format!("select failed: {error}"))?
                    .unlock(&credential, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "a slot's bytes taken from another file must fail the wrap tag"
        );
        Ok(())
    }

    /// The old slot and the old payload under the new header do not authenticate:
    /// only the whole old file opens with the old credential.
    ///
    /// This is the guarantee a rotation makes - "no slot can be restored from an
    /// old copy, and only the whole old file still opens" - stated as a test.
    #[test]
    fn old_slot_with_old_payload_ciphertext_and_tag_under_new_header_fails_authentication()
    -> TestResult {
        let original = seal(PLAINTEXT, &[raw_recipient(1, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let old = SlotCredential::RawKey(&RAW_KEY);
        let rotated = rewrap_slot(
            &original,
            &old,
            SlotSelector::Index(0),
            &raw_recipient_with(1, "operator", &OTHER_KEY),
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let before =
            KeytabEnvelope::parse(&original).map_err(|error| format!("parse failed: {error}"))?;
        let after =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        let target = before.slots.first().ok_or("the slot exists")?;
        let start = target
            .dek_offset
            .checked_sub(target.wrap_prefix.len())
            .ok_or("the prefix precedes the wrap")?;
        let header_len = before.header.len();
        let old_prefix = target.wrap_prefix.clone();
        let old_dek = target.wrapped_dek;
        let old_ciphertext = before.ciphertext.to_vec();
        // The new header, with the old slot bytes and the old payload ciphertext
        // and tag put back.
        let mut mixed = rotated.clone();
        if let Some(field) = mixed.get_mut(start..target.dek_offset) {
            field.copy_from_slice(&old_prefix);
        }
        if let Some(field) = mixed.get_mut(target.dek_offset..target.dek_offset + WRAPPED_DEK_LEN) {
            field.copy_from_slice(&old_dek);
        }
        if let Some(field) = mixed.get_mut(header_len..) {
            field.copy_from_slice(&old_ciphertext);
        }
        let envelope =
            KeytabEnvelope::parse(&mixed).map_err(|error| format!("parse failed: {error}"))?;
        assert!(
            before
                .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &old)
                .map_err(|error| format!("select failed: {error}"))?
                .unlock(&old, &Argon2Kdf)
                .is_ok(),
            "the whole old file still opens with the old credential"
        );
        assert!(
            matches!(
                envelope
                    .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &old)
                    .map_err(|error| format!("select failed: {error}"))?
                    .unlock(&old, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "the old slot and payload under the new header must not authenticate"
        );
        let new = SlotCredential::RawKey(&OTHER_KEY);
        assert!(
            matches!(
                after
                    .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &old)
                    .map_err(|error| format!("select failed: {error}"))?
                    .unlock(&old, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "and the old credential does not open the rotated slot either"
        );
        assert!(
            after
                .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &new)
                .map_err(|error| format!("select failed: {error}"))?
                .unlock(&new, &Argon2Kdf)
                .is_ok(),
            "while the replacement does"
        );
        Ok(())
    }

    /// The version sits in both AAD transcripts, so relabelling a file is either
    /// refused on the version (an unsupported value) or fails authentication (a
    /// supported value written back over a header that also moved).
    #[test]
    fn version_relabel_fails_authentication_or_version_check() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(1, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        // An unsupported label is refused on the version, before anything else.
        let mut relabelled = blob.clone();
        if let Some(field) = relabelled.get_mut(14..16) {
            // Version 2, little-endian: a value this format does not define.
            field.copy_from_slice(&[2, 0]);
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&relabelled),
                Err(EnvelopeError::Malformed(Malformed::Version))
            ),
            "an unsupported version must be refused on the version"
        );
        // A header that moved underneath the label is caught by the tag: the
        // label is inside the slot's wrap AAD, and the payload's AAD covers the
        // whole header. The byte here is the first letter of the label
        // `operator`, at 70 + 4 + 1 + 1.
        let mut tampered = blob;
        if let Some(byte) = tampered.get_mut(76) {
            *byte ^= 0x01;
        }
        if let Some(field) = tampered.get_mut(14..16) {
            field.copy_from_slice(&[2, 0]);
        }
        assert!(
            matches!(
                KeytabEnvelope::parse(&tampered),
                Err(EnvelopeError::Malformed(Malformed::Version))
            ),
            "the version check comes first, whatever else moved"
        );
        if let Some(field) = tampered.get_mut(14..16) {
            field.copy_from_slice(&[1, 0]);
        }
        let envelope = KeytabEnvelope::parse(&tampered)
            .map_err(|error| format!("the relabelled file parses: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        assert!(
            matches!(
                envelope
                    .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
                    .map_err(|error| format!("select failed: {error}"))?
                    .unlock(&credential, &Argon2Kdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "writing the version back does not repair a header that moved: the tag says so"
        );
        Ok(())
    }

    /// The byte-exact file for one fixed raw-key seal. "Canonical" is only
    /// meaningful if the serialization is pinned, so this test notices a
    /// field moving, a width changing, or an AAD transcript drifting.
    #[test]
    fn golden_raw_key_vector_matches() -> TestResult {
        let material = deterministic_material(1);
        let blob = seal_with(
            PLAINTEXT,
            &[raw_recipient(7, "operator")],
            &material,
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let rendered = hex(&blob);
        assert_eq!(
            rendered, GOLDEN_RAW_KEY_FILE,
            "the raw-key serialization must match the pinned bytes"
        );
        Ok(())
    }

    /// The byte-exact file for one fixed passphrase seal, for the same reason as
    /// the raw-key vector.
    #[test]
    fn golden_passphrase_vector_matches() -> TestResult {
        let material = deterministic_material(2);
        let blob = seal_with(
            PLAINTEXT,
            &[passphrase_recipient(9, "operator")],
            &material,
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        assert_eq!(
            hex(&blob),
            GOLDEN_PASSPHRASE_FILE,
            "the passphrase serialization must match the pinned bytes"
        );
        Ok(())
    }

    /// D1: the DEK that `Aead::decrypt` returns is bound **inside** the
    /// `Zeroizing` that wipes it.
    ///
    /// B6 says every owned DEK is zeroized. The decrypt hands back a plain
    /// `Vec<u8>`, so a `let dek = <decrypt>(..)?` leaves the key in a buffer
    /// that is dropped unwiped - whatever happens to the copy taken from it -
    /// and no runtime assertion can see where a value was bound, because both
    /// shapes produce the same bytes. The guard reads the source instead:
    /// whitespace is stripped first, since `rustfmt` wraps the call.
    #[test]
    fn unwrapped_dek_is_zeroizing_from_decrypt() -> TestResult {
        let source = include_str!("envelope.rs");
        let production = production_text(source);
        // At column zero, so `Selection::unwrap_dek` - the same name one layer
        // up - cannot be the function this guard reads.
        let start = production
            .find("\nfn unwrap_dek(")
            .ok_or("unwrap_dek must still exist")?;
        let function = production.get(start..).unwrap_or_default();
        let end = function.find("\n}").unwrap_or(function.len());
        let unwrap_dek_text = function.get(..end).unwrap_or_default();
        let squashed: String = unwrap_dek_text.split_whitespace().collect();
        assert!(
            squashed.contains("Zeroizing::new(Aead::decrypt("),
            "the decrypt's result must be bound inside `Zeroizing`: {squashed}"
        );
        assert!(
            !squashed.contains("=Aead::decrypt("),
            "a bare binding of the decrypt's `Vec<u8>` leaves the DEK unwiped: {squashed}"
        );
        assert!(
            squashed.contains("dek.as_slice()"),
            "and the copy must come out of the `Zeroizing` binding: {squashed}"
        );
        Ok(())
    }

    /// Every owned data key in this module is a `Zeroizing`, asserted on the
    /// source because ownership *shape* is what a type can state: a
    /// `[u8; DEK_LEN]` that was never wrapped cannot be made to wipe on drop
    /// after the fact, and no runtime assertion can see a type (finding 15,
    /// SOW B10).
    ///
    /// Four shapes would leave a data key un-wiped, and the guard names each:
    /// the seal material's field, the local the seal path fills from the OS
    /// CSPRNG, and the two fallible returns that produce a key from a file.
    /// The positive half is checked too, so the guard cannot pass by matching
    /// nothing at all.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/envelope.rs::owned_envelope_secrets_are_zeroizing keeps the uniform test signature while it only asserts"
    )]
    fn owned_envelope_secrets_are_zeroizing() -> TestResult {
        let source = concat!(include_str!("seal.rs"), "\n", include_str!("envelope.rs"));
        let production = production_text(source);
        for (what, shape) in [
            ("the seal material's data key", "dek: [u8; DEK_LEN],"),
            (
                "the seal path's local data key",
                "let mut dek = [0; DEK_LEN]",
            ),
            (
                "the unwrapped data key",
                "-> Result<[u8; DEK_LEN], EnvelopeError>",
            ),
        ] {
            assert!(
                !production.contains(shape),
                "{what} must be owned as a `Zeroizing`, found `{shape}`"
            );
        }
        for shape in [
            "dek: Zeroizing<[u8; DEK_LEN]>,",
            "let mut dek = Zeroizing::new([0; DEK_LEN]);",
            "-> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError>",
        ] {
            assert!(
                production.contains(shape),
                "the guard must still find `{shape}`: it pins the shape that keeps the key wiped"
            );
        }
        Ok(())
    }

    /// A token selects the slot it *names*, not merely some slot: the two
    /// slots are sealed with different keys, so selecting the wrong one
    /// cannot unlock.
    #[test]
    fn a_token_selects_the_slot_it_names() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[
                raw_recipient_with(1, "operator", &RAW_KEY),
                raw_recipient_with(2, "pod", &OTHER_KEY),
            ],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let pod_key = SlotCredential::RawKey(&OTHER_KEY);
        let by_id = envelope
            .select_slot(SlotSelector::Index(1), &KdfLimits::defaults(), &pod_key)
            .map_err(|error| format!("the position must select: {error}"))?;
        assert!(
            by_id.unlock(&pod_key, &Argon2Kdf).is_ok(),
            "selecting the second slot must pick the slot sealed with that key"
        );
        let by_label = envelope
            .select_slot(SlotSelector::Label("pod"), &KdfLimits::defaults(), &pod_key)
            .map_err(|error| format!("the label must select: {error}"))?;
        assert!(
            by_label.unlock(&pod_key, &Argon2Kdf).is_ok(),
            "selecting by label must pick the same slot"
        );
        Ok(())
    }

    /// A selector is never ambiguous: an index or a label names one slot or
    /// none, and naming none is refused at selection, before any derivation.
    #[test]
    fn a_selector_names_one_slot_or_is_refused() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        // An index is a position in the file and a label is unique, so neither
        // can match two slots. Which slot to use when the caller named none is
        // the caller's decision, made from `slots()`.
        assert!(
            envelope
                .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
                .is_ok(),
            "an index selects"
        );
        assert!(
            envelope
                .select_slot(
                    SlotSelector::Label("pod"),
                    &KdfLimits::defaults(),
                    &credential
                )
                .is_ok(),
            "a label selects"
        );
        assert!(
            matches!(
                envelope.select_slot(
                    SlotSelector::Label("absent"),
                    &KdfLimits::defaults(),
                    &credential
                ),
                Err(EnvelopeError::Malformed(Malformed::SlotLabel))
            ),
            "a label that names nothing is refused"
        );
        Ok(())
    }

    /// KRP-78: unlock from bytes, with no path anywhere in the call.
    #[test]
    fn unlocks_from_bytes_without_a_path() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(1, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&RAW_KEY);
        let plaintext = envelope
            .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
            .map_err(|error| format!("select failed: {error}"))?
            .unlock(&credential, &PanickingKdf)
            .map_err(|error| format!("unlock from bytes failed: {error}"))?;
        assert_eq!(plaintext.as_slice(), PLAINTEXT);
        Ok(())
    }
}
