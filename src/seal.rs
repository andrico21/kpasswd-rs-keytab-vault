//! Sealing a plaintext into an envelope, and rotating one slot's wrapping key.
//!
//! Every nonce, salt and the data key are drawn from the operating-system
//! CSPRNG here; the deterministic half (`seal_with`) exists only so a test can
//! pin a file's exact bytes, and it stays crate-private because a public
//! constructor for a nonce is a footgun with no legitimate caller.

use chacha20poly1305::aead::{Aead, Payload};
use zeroize::Zeroizing;

use crate::{
    credential::{Recipient, SlotCredential, SlotSelector},
    envelope::{
        KeytabEnvelope, cipher_from_key, nonce_from_bytes, wrap_aad_for, wrap_dek, wrap_identity,
    },
    format::{
        ARGON2_OUTPUT_LEN, ARGON2_VERSION, DEK_LEN, EnvelopeError, FILE_ID_LEN, FIXED_HEADER_LEN,
        FORMAT_VERSION, KDF_BLOCK_LEN, KDF_SALT_END, KDF_SALT_START, KEK_LEN, MAGIC,
        MAX_PAYLOAD_LEN, MAX_SLOT_LABEL_LEN, MAX_SLOTS, MIN_SLOTS, Malformed, NONCE_LEN,
        PAYLOAD_ALG_XCHACHA20_POLY1305, PAYLOAD_NONCE_OFFSET, SALT_LEN, SLOT_TYPE_PASSPHRASE,
        SLOT_TYPE_RAW_KEY, SlotType, TAG_LEN, WRAP_AAD_MIN_LEN, WRAP_ALG_XCHACHA20_POLY1305,
        WRAPPED_DEK_LEN, is_unrenderable_in_a_label,
    },
    kdf::{Argon2Kdf, Argon2idParams, Kdf, KdfBackend as _, KdfLimits},
};

/// Everything a writer must draw from the CSPRNG, injectable so a test can
/// pin the exact bytes of a file.
pub(crate) struct SealMaterial {
    /// The payload key, owned as a `Zeroizing` from the moment it is drawn: it
    /// is the one secret every envelope holds, and the seal path is where it is
    /// created (finding 15, SOW B10).
    dek: Zeroizing<[u8; DEK_LEN]>,
    /// The payload nonce.
    payload_nonce: [u8; NONCE_LEN],
    /// The file's identifier: drawn once per seal, written once, and never
    /// changed - including by a rotation, which is why every other slot keeps
    /// authenticating across one (KRP-93).
    file_id: [u8; FILE_ID_LEN],
    /// One entry per recipient, in slot order.
    wraps: Vec<WrapMaterial>,
}

/// The per-slot randomness a seal needs. Crate-internal with [`SealMaterial`].
pub(crate) struct WrapMaterial {
    /// The wrap nonce.
    wrap_nonce: [u8; NONCE_LEN],
    /// The Argon2 salt, for passphrase recipients.
    salt: [u8; SALT_LEN],
}

/// Replace the key of one slot and leave every other slot as it is.
///
/// `unlock` is the current credential of the slot named by `slot`, and
/// `replacement` is the new one. The whole file is unlocked and authenticated
/// first, and nothing is returned unless every step succeeds.
///
/// The data key does not change, and every other slot stays byte-for-byte the
/// same. The rotated slot gets a fresh wrap nonce (and a fresh salt, for a
/// passphrase slot) and keeps its Argon2id parameters, and the payload is
/// re-encrypted under a fresh nonce, so no nonce is ever used twice.
///
/// A rotation never changes the file's layout. The replacement must be the
/// same kind of credential, and its label must have the same length in bytes
/// and follow the format's label rules. The slot keeps its `slot_id`, and the
/// replacement's `id` is ignored. Anything else needs a fresh [`seal`].
///
/// This is not revocation: copies of the old file still open with the old key.
///
/// The Argon2id parameters accepted are [`KdfLimits::defaults`]; use
/// [`rewrap_slot_with_limits`] for a file sealed with other parameters.
///
/// # Errors
///
/// `EnvelopeError::RotationMismatch` when the replacement does not fit the
/// slot, reported only for a file that authenticated.
/// `EnvelopeError::AuthenticationFailed` when `unlock` does not open the slot
/// or the file was altered, `Malformed(Argon2Parameters)` when the slot's
/// parameters are outside [`KdfLimits::defaults`], and any other error that
/// parsing the file, selecting the slot or deriving a key reports.
#[inline]
pub fn rewrap_slot(
    envelope: &[u8],
    unlock: &SlotCredential<'_>,
    slot: SlotSelector<'_>,
    replacement: &Recipient<'_>,
) -> Result<Vec<u8>, EnvelopeError> {
    rewrap_slot_with_limits(envelope, unlock, slot, replacement, KdfLimits::defaults())
}

/// Rewrap one slot's key, with the file's parameters admitted by `limits`.
///
/// Exactly [`rewrap_slot`] with the band as an argument. `limits` is the band
/// the file's *own* Argon2 parameters are checked against before any derivation
/// and the band the replacement is derived under - the same band an unlock
/// honours, from the same place - so a caller that seals a stronger set can
/// rotate it instead of falling back to the default band. [`rewrap_slot`] is
/// this call at [`KdfLimits::defaults`].
///
/// # Errors
///
/// Every error [`rewrap_slot`] reports, and
/// `Malformed(Argon2Parameters)` before any derivation when the selected slot's
/// declared parameters are outside `limits`.
#[inline]
pub fn rewrap_slot_with_limits(
    envelope: &[u8],
    unlock: &SlotCredential<'_>,
    slot: SlotSelector<'_>,
    replacement: &Recipient<'_>,
    limits: KdfLimits,
) -> Result<Vec<u8>, EnvelopeError> {
    let parsed = KeytabEnvelope::parse(envelope)?;
    let position = parsed.select_position(slot)?;
    let selection = parsed.select_slot(slot, &limits, unlock)?;
    // **The full unlock first**: a file that does not authenticate in full is
    // refused before anything else is decided - and before a byte is written.
    // The mismatch check below reads header fields, and those are not
    // authenticated until this call returns, so deciding `RotationMismatch`
    // from them first would answer for a *tampered* file with the caller error
    // that belongs to a valid one (D4). One unwrap, so the wrap is opened once.
    let (dek, plaintext) = selection.open(unlock, &Argon2Kdf)?;
    let target = parsed
        .slots
        .get(position)
        .ok_or(EnvelopeError::Malformed(Malformed::SlotIdentifier))?;
    // The rotation rewrites an already-valid file and its result is the next
    // `parse` input: a different shape *or* a label the reader's slot-token
    // rules refuse is caller error on a valid file (D4 ordering keeps both
    // decisions after the full unlock).
    if target.kind != replacement.credential.kind()
        || target.label.len() != replacement.label.len()
        || replacement_label_conflicts(&parsed, position, replacement.label)
    {
        return Err(EnvelopeError::RotationMismatch);
    }
    // The rotated slot's wrap, under material drawn here. Its parameters stay as
    // the file has them - a rotation replaces the credential, not the KDF - so a
    // passphrase slot reuses its block's parameters with a fresh salt.
    let mut wrap_nonce = [0; NONCE_LEN];
    getrandom::fill(&mut wrap_nonce).map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
    let (kek, block): (Zeroizing<[u8; KEK_LEN]>, Option<[u8; KDF_BLOCK_LEN]>) =
        match &replacement.credential {
            // No length check: the variant's type is the check (B10).
            SlotCredential::RawKey(key) => (Zeroizing::new(**key), target.kdf),
            credential @ (SlotCredential::Passphrase(_) | SlotCredential::PassphraseOwned(_)) => {
                // Both passphrase variants, owned or borrowed, are the same text
                // here; one that carries none is a raw key, which the kind check
                // above has already refused for this slot.
                let text = credential
                    .passphrase()
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                let mut block = target
                    .kdf
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                let mut salt = [0; SALT_LEN];
                getrandom::fill(&mut salt)
                    .map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
                block
                    .get_mut(KDF_SALT_START..KDF_SALT_END)
                    .ok_or(EnvelopeError::Malformed(Malformed::Argon2Parameters))?
                    .copy_from_slice(&salt);
                let kek = Argon2Kdf.derive_argon2id(text, &block, &limits)?;
                (kek, Some(block))
            }
        };
    let prefix = slot_prefix(
        target.id,
        replacement.label,
        target.kind,
        &wrap_nonce,
        block.as_ref(),
    )?;
    let wrap_aad = wrap_aad_for(
        &wrap_identity(parsed.version, parsed.payload_len, &parsed.file_id),
        &prefix,
    );
    let rewrapped = wrap_dek(&kek, &wrap_nonce, &dek, &wrap_aad)?;
    // The rotated file: the same bytes, with this slot's prefix and wrapped DEK
    // written in place. The prefix has the same serialized length as the one it
    // replaces - same id width, same label byte length, same kind - so every
    // other slot stays exactly where it was.
    let prefix_start = target
        .dek_offset
        .checked_sub(target.wrap_prefix.len())
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?;
    let dek_end = target
        .dek_offset
        .checked_add(WRAPPED_DEK_LEN)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?;
    let mut rotated = envelope.to_vec();
    rotated
        .get_mut(prefix_start..target.dek_offset)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?
        .copy_from_slice(&prefix);
    rotated
        .get_mut(target.dek_offset..dek_end)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?
        .copy_from_slice(&rewrapped);
    // The payload is re-encrypted under the *unchanged* DEK and a nonce drawn
    // here. The nonce lives in the fixed header, so it is written before the
    // header becomes the payload's AAD: the tag must cover the bytes the file
    // actually has.
    let mut payload_nonce = [0; NONCE_LEN];
    getrandom::fill(&mut payload_nonce)
        .map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
    let header_len = parsed.header.len();
    let nonce_end = PAYLOAD_NONCE_OFFSET
        .checked_add(NONCE_LEN)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?;
    rotated
        .get_mut(PAYLOAD_NONCE_OFFSET..nonce_end)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderBoundary))?
        .copy_from_slice(&payload_nonce);
    let header = rotated
        .get(..header_len)
        .ok_or(EnvelopeError::Malformed(Malformed::HeaderLength))?;
    let cipher = cipher_from_key(&dek);
    let nonce = nonce_from_bytes(&payload_nonce)?;
    let ciphertext = Aead::encrypt(
        &cipher,
        &nonce,
        Payload {
            msg: &plaintext,
            aad: header,
        },
    )
    .map_err(|_authentication_error| EnvelopeError::AuthenticationFailed)?;
    let payload_end = header_len
        .checked_add(plaintext.len())
        .and_then(|end| end.checked_add(TAG_LEN))
        .ok_or(EnvelopeError::Malformed(Malformed::PayloadLength))?;
    rotated
        .get_mut(header_len..payload_end)
        .ok_or(EnvelopeError::Malformed(Malformed::LengthIdentity))?
        .copy_from_slice(&ciphertext);
    Ok(rotated)
}

/// Seal `plaintext` into an envelope, drawing every nonce, salt and the DEK
/// from the operating-system CSPRNG.
///
/// # Errors
///
/// `EnvelopeError::EntropyUnavailable` when the operating-system CSPRNG
/// fails. `Malformed(SlotCount)` for no recipients or more than eight,
/// `Malformed(DuplicateSlot)` when two recipients share an id or a label,
/// `Malformed(SlotIdentifier)` when a label is spelled like a slot id,
/// `Malformed(SlotLabel)` for a label longer than 64 bytes or with a character
/// that cannot be rendered, and `Malformed(PayloadLength)` when the plaintext
/// is over 1 MiB. `EnvelopeError::DerivationFailed` when a passphrase cannot be
/// derived into a key.
#[inline]
pub fn seal(
    plaintext: &[u8],
    recipients: &[Recipient<'_>],
    kdf: &Kdf,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut dek = Zeroizing::new([0; DEK_LEN]);
    let mut payload_nonce = [0; NONCE_LEN];
    let mut file_id = [0; FILE_ID_LEN];
    getrandom::fill(&mut *dek).map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
    getrandom::fill(&mut payload_nonce)
        .map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
    getrandom::fill(&mut file_id).map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
    let mut wraps = Vec::with_capacity(recipients.len());
    for _recipient_index in 0..recipients.len() {
        let mut wrap_nonce = [0; NONCE_LEN];
        let mut salt = [0; SALT_LEN];
        getrandom::fill(&mut wrap_nonce)
            .map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
        getrandom::fill(&mut salt).map_err(|_entropy_error| EnvelopeError::EntropyUnavailable)?;
        wraps.push(WrapMaterial { wrap_nonce, salt });
    }
    seal_with(
        plaintext,
        recipients,
        &SealMaterial {
            dek,
            payload_nonce,
            file_id,
            wraps,
        },
        kdf,
    )
}

/// Seal `plaintext` with caller-supplied randomness: the deterministic half the
/// tests use to pin a file's exact bytes.
///
/// Module-private, with the material types above (KRP-88): a public constructor
/// for the nonces and the data key is a footgun with no legitimate caller, so
/// neither this nor [`SealMaterial`] is reachable from outside the crate.
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::SlotCount)` when the recipient count
/// is outside <code>1..=[MAX_SLOTS]</code> or does not match `material.wraps`,
/// `Malformed(DuplicateSlot)` when two recipients share an id or a label,
/// `Malformed(SlotIdentifier)` when a label is spelled like a slot's decimal
/// id, `Malformed(PayloadLength)` when the plaintext is longer than the
/// reader's [`MAX_PAYLOAD_LEN`] cap, plus the `Malformed` rules the builder
/// applies to the assembled envelope (`SlotLabel`, `SlotPairing`,
/// `HeaderLength`) and `EnvelopeError::AuthenticationFailed` when a wrap fails
/// to verify.
#[inline]
pub(crate) fn seal_with(
    plaintext: &[u8],
    recipients: &[Recipient<'_>],
    material: &SealMaterial,
    kdf: &Kdf,
) -> Result<Vec<u8>, EnvelopeError> {
    // One format writes one version, whatever parameters the caller chose: the
    // block a passphrase slot carries is the caller's, and no reader has to
    // agree with another about a second format (KRP-93).
    let version = FORMAT_VERSION;
    if recipients.len() != material.wraps.len() {
        return Err(EnvelopeError::Malformed(Malformed::SlotCount));
    }
    let slot_total = recipients.len();
    if !(MIN_SLOTS..=MAX_SLOTS).contains(&slot_total) {
        return Err(EnvelopeError::Malformed(Malformed::SlotCount));
    }
    // The reader caps the declared payload (`KeytabEnvelope::parse`), so the
    // writer refuses a longer one: a successful seal must parse, and the cap is
    // the last reader rule the writer path would otherwise not apply.
    if plaintext.len() > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::Malformed(Malformed::PayloadLength));
    }
    let payload_len = u64::try_from(plaintext.len())
        .map_err(|_length_error| EnvelopeError::Malformed(Malformed::PayloadLength))?;
    let identity = wrap_identity(version, payload_len, &material.file_id);
    // Serialize each slot's prefix first: the wrap AAD is that prefix, and
    // only the payload AAD needs the finished header.
    let mut prefixes: Vec<Vec<u8>> = Vec::with_capacity(slot_total);
    let mut wrapped: Vec<[u8; WRAPPED_DEK_LEN]> = Vec::with_capacity(slot_total);
    // A writer must not emit a file its own reader refuses: the recipient set
    // must satisfy the reader's slot-token rules before any wrap is produced.
    check_recipient_tokens(recipients)?;
    for (position, recipient) in recipients.iter().enumerate() {
        let wrap = material
            .wraps
            .get(position)
            .ok_or(EnvelopeError::Malformed(Malformed::SlotCount))?;
        let kind = recipient.credential.kind();
        let block = if kind.has_kdf_block() {
            Some(argon2_block_from_salt(&wrap.salt, kdf.params())?)
        } else {
            None
        };
        let prefix = slot_prefix(
            recipient.id,
            recipient.label,
            kind,
            &wrap.wrap_nonce,
            block.as_ref(),
        )?;
        let kek = match &recipient.credential {
            // No length check: the variant's type is the check (B10).
            SlotCredential::RawKey(key) => Zeroizing::new(**key),
            credential @ (SlotCredential::Passphrase(_) | SlotCredential::PassphraseOwned(_)) => {
                // Both passphrase variants, owned or borrowed, are the same
                // text here: sealing derives from whichever the caller handed
                // over, and never keeps it.
                let text = credential
                    .passphrase()
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                let block_bytes = block
                    .as_ref()
                    .ok_or(EnvelopeError::Malformed(Malformed::SlotPairing))?;
                // Sealing is the direction that *chooses* the parameters, so the
                // band is the caller's own: a band of exactly v1 would refuse
                // the file this call is writing.
                let chosen = kdf.params();
                Argon2Kdf.derive_argon2id(
                    text,
                    block_bytes,
                    &KdfLimits::between(chosen, chosen)?,
                )?
            }
        };
        let slot_aad = wrap_aad_for(&identity, &prefix);
        wrapped.push(wrap_dek(&kek, &wrap.wrap_nonce, &material.dek, &slot_aad)?);
        prefixes.push(prefix);
    }
    let header_len = header_len_for(&prefixes)?;
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&version.to_le_bytes());
    header.extend_from_slice(
        &u32::try_from(header_len)
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::HeaderLength))?
            .to_le_bytes(),
    );
    header.push(PAYLOAD_ALG_XCHACHA20_POLY1305);
    header.extend_from_slice(&material.payload_nonce);
    header.extend_from_slice(&payload_len.to_le_bytes());
    header.extend_from_slice(&material.file_id);
    header.extend_from_slice(
        &u8::try_from(slot_total)
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::SlotCount))?
            .to_le_bytes(),
    );
    for (position, prefix) in prefixes.iter().enumerate() {
        header.extend_from_slice(prefix);
        let dek = wrapped
            .get(position)
            .ok_or(EnvelopeError::Malformed(Malformed::SlotCount))?;
        header.extend_from_slice(dek.as_slice());
    }
    let cipher = cipher_from_key(&material.dek);
    let payload_nonce = nonce_from_bytes(&material.payload_nonce)?;
    let ciphertext = Aead::encrypt(
        &cipher,
        &payload_nonce,
        Payload {
            msg: plaintext,
            aad: header.as_slice(),
        },
    )
    .map_err(|_encryption_error| EnvelopeError::AuthenticationFailed)?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// The canonical serialized Argon2 block for a salt.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::Argon2Parameters)` if a fixed KDF field cannot be written
/// into the canonical block.
pub(crate) fn argon2_block_from_salt(
    salt: &[u8; SALT_LEN],
    params: Argon2idParams,
) -> Result<[u8; KDF_BLOCK_LEN], EnvelopeError> {
    let mut block = [0; KDF_BLOCK_LEN];
    write_u32_at(&mut block, 0, ARGON2_VERSION)?;
    block
        .get_mut(KDF_SALT_START..KDF_SALT_END)
        .ok_or(EnvelopeError::Malformed(Malformed::Argon2Parameters))?
        .copy_from_slice(salt);
    write_u32_at(&mut block, 20, params.memory_kib())?;
    write_u32_at(&mut block, 24, params.iterations())?;
    write_u32_at(&mut block, 28, params.parallelism())?;
    write_u32_at(
        &mut block,
        32,
        u32::try_from(ARGON2_OUTPUT_LEN)
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::Argon2Parameters))?,
    )?;
    Ok(block)
}

/// One slot's serialized prefix: `slot_id` through `wrap_nonce`.
///
/// Takes the id and the label rather than a [`Recipient`] because a rotation
/// rebuilds the prefix of a slot whose id is the file's - the slot keeps its
/// identity, only its wrap (and, for a passphrase slot, its salt) changes.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::SlotLabel)` when the label is longer than the envelope
/// format's one-byte label field or carries a character that cannot be rendered.
fn slot_prefix(
    id: u32,
    label: &str,
    kind: SlotType,
    wrap_nonce: &[u8; NONCE_LEN],
    kdf: Option<&[u8; KDF_BLOCK_LEN]>,
) -> Result<Vec<u8>, EnvelopeError> {
    let label_bytes = label.as_bytes();
    if label_bytes.len() > MAX_SLOT_LABEL_LEN {
        return Err(EnvelopeError::Malformed(Malformed::SlotLabel));
    }
    // The reader refuses a character it cannot render (`parse_slot`), so the
    // writer must too: `seal` may not emit a file `parse` refuses.
    if label.chars().any(is_unrenderable_in_a_label) {
        return Err(EnvelopeError::Malformed(Malformed::SlotLabel));
    }
    let mut prefix = Vec::with_capacity(WRAP_AAD_MIN_LEN);
    prefix.extend_from_slice(&id.to_le_bytes());
    prefix.push(match kind {
        SlotType::RawKey => SLOT_TYPE_RAW_KEY,
        SlotType::Passphrase => SLOT_TYPE_PASSPHRASE,
    });
    prefix.push(
        u8::try_from(label_bytes.len())
            .map_err(|_conversion| EnvelopeError::Malformed(Malformed::SlotLabel))?,
    );
    prefix.extend_from_slice(label_bytes);
    prefix.push(kind.kek_alg());
    if let Some(block) = kdf {
        prefix.extend_from_slice(block.as_slice());
    }
    prefix.push(WRAP_ALG_XCHACHA20_POLY1305);
    prefix.extend_from_slice(wrap_nonce);
    Ok(prefix)
}

/// The reader's slot-token rules, applied to a recipient set: a writer may not
/// emit a file [`KeytabEnvelope::parse`] refuses.
///
/// The checks are `parse`'s own, in its order: a shared id or label is
/// [`Malformed::DuplicateSlot`], a label spelled like any slot's decimal id -
/// including its own - is [`Malformed::SlotIdentifier`].
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::DuplicateSlot)` when two recipients
/// share an id or a label, `Malformed(SlotIdentifier)` when a label is spelled
/// like any recipient's decimal id.
fn check_recipient_tokens(recipients: &[Recipient<'_>]) -> Result<(), EnvelopeError> {
    for (position, recipient) in recipients.iter().enumerate() {
        let id_token = recipient.id.to_string();
        if recipients
            .iter()
            .take(position)
            .any(|earlier| earlier.id == recipient.id || earlier.label == recipient.label)
        {
            return Err(EnvelopeError::Malformed(Malformed::DuplicateSlot));
        }
        if recipients
            .iter()
            .take(position)
            .any(|earlier| earlier.label == id_token)
            || recipients
                .iter()
                .take(position)
                .any(|earlier| recipient.label == earlier.id.to_string())
            || recipient.label == id_token
        {
            return Err(EnvelopeError::Malformed(Malformed::SlotIdentifier));
        }
    }
    Ok(())
}

/// Whether a rotation's replacement label would break the reader's slot-token
/// rules.
///
/// The rules are a character that cannot be rendered, a spelling of the rotated
/// slot's own decimal id, a duplicate of another slot's label, or a spelling of
/// another slot's decimal id. The other slots already satisfy them - the file
/// parsed - so only the value the rotation writes can break them.
fn replacement_label_conflicts(
    parsed: &KeytabEnvelope<'_>,
    position: usize,
    replacement: &str,
) -> bool {
    replacement.chars().any(is_unrenderable_in_a_label)
        || parsed
            .slots
            .get(position)
            .is_some_and(|slot| slot.id.to_string() == replacement)
        || parsed.slots.iter().enumerate().any(|(index, other)| {
            index != position && (other.label == replacement || other.id.to_string() == replacement)
        })
}

/// Write a little-endian `u32` at `offset` in a KDF block.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::Argon2Parameters)` when `offset` does not leave four bytes
/// inside the KDF block.
fn write_u32_at(
    block: &mut [u8; KDF_BLOCK_LEN],
    offset: usize,
    value: u32,
) -> Result<(), EnvelopeError> {
    block
        .get_mut(offset..offset.saturating_add(4))
        .ok_or(EnvelopeError::Malformed(Malformed::Argon2Parameters))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// The header length implied by the serialized slot prefixes.
///
/// # Errors
///
/// `EnvelopeError::Malformed(Malformed::HeaderLength)` when adding a prefix or wrapped DEK length
/// overflows `usize`.
fn header_len_for(prefixes: &[Vec<u8>]) -> Result<usize, EnvelopeError> {
    let mut total = FIXED_HEADER_LEN;
    for prefix in prefixes {
        total = total
            .checked_add(prefix.len())
            .and_then(|sum| sum.checked_add(WRAPPED_DEK_LEN))
            .ok_or(EnvelopeError::Malformed(Malformed::HeaderLength))?;
    }
    Ok(total)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
pub(crate) mod tests {
    use super::*;
    use crate::{format::KEK_ALG_DIRECT_256, kdf::salt_from_block, test_support::*, *};

    /// How many rotations the nonce-reuse tests perform after the seal. Five is
    /// the row's number, and a named bound keeps the loop's integer type a
    /// decision rather than a fallback.
    const ROTATIONS: usize = 5;

    /// Deterministic sealing material for one recipient, for the golden
    /// vector.
    pub(crate) fn deterministic_material(seed: u8) -> SealMaterial {
        SealMaterial {
            dek: Zeroizing::new(fill::<DEK_LEN>(seed, 0x10)),
            payload_nonce: fill::<NONCE_LEN>(seed, 0x20),
            file_id: fill::<FILE_ID_LEN>(seed, 0x50),
            wraps: vec![WrapMaterial {
                wrap_nonce: fill::<NONCE_LEN>(seed, 0x30),
                salt: fill::<SALT_LEN>(seed, 0x40),
            }],
        }
    }

    /// KRP-88: sealing is ordinary API in a shipped build, and a sealed
    /// envelope round-trips through parse and unlock. `seal` exists without
    /// `cfg(test)` - this test calls it exactly as a consumer would.
    #[test]
    fn sealing_round_trips_in_a_shipped_build() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[
                raw_recipient(3, "operator"),
                passphrase_recipient(4, "human"),
            ],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        assert_eq!(envelope.slots().len(), 2, "both recipients become slots");
        let by_key = envelope
            .select_slot(
                SlotSelector::Label("operator"),
                &KdfLimits::defaults(),
                &SlotCredential::RawKey(&RAW_KEY),
            )
            .map_err(|error| format!("select failed: {error}"))?
            .unlock(&SlotCredential::RawKey(&RAW_KEY), &PanickingKdf)
            .map_err(|error| format!("unlock failed: {error}"))?;
        assert_eq!(by_key.as_slice(), PLAINTEXT);
        let by_passphrase = envelope
            .select_slot(
                SlotSelector::Label("human"),
                &KdfLimits::defaults(),
                &SlotCredential::Passphrase(PASSPHRASE),
            )
            .map_err(|error| format!("select failed: {error}"))?
            .unlock(&SlotCredential::Passphrase(PASSPHRASE), &Argon2Kdf)
            .map_err(|error| format!("unlock failed: {error}"))?;
        assert_eq!(by_passphrase.as_slice(), PLAINTEXT);
        Ok(())
    }

    /// KRP-88's headline claim: rotation rewraps one slot and does not
    /// re-encrypt the payload. The payload ciphertext is byte-identical across
    /// the rotation, the data key is the same key, and the new credential opens
    /// the slot while the old one no longer does.
    /// KRP-93: a rotation keeps the data key and leaves every slot it does not
    /// touch byte-identical, while the payload is re-encrypted under a fresh
    /// nonce.
    ///
    /// Replaces `rotation_preserves_the_payload_and_the_data_key`, which asserted
    /// the opposite for the payload: the old shape could not re-encrypt without
    /// reusing the payload nonce, and reusing it is the defect KRP-93 names.
    #[test]
    fn rotation_keeps_the_data_key_and_other_slots_byte_identical() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let before =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let operator = SlotCredential::RawKey(&RAW_KEY);
        let selection = before
            .select_slot(
                SlotSelector::Label("operator"),
                &KdfLimits::defaults(),
                &operator,
            )
            .map_err(|error| format!("select failed: {error}"))?;
        let dek_before = selection
            .unwrap_dek(&operator, &PanickingKdf)
            .map_err(|error| format!("unwrap failed: {error}"))?;
        let rotated = rewrap_slot(
            &blob,
            &operator,
            SlotSelector::Label("operator"),
            &raw_recipient_with(1, "operator", &OTHER_KEY),
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let after =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        let new = SlotCredential::RawKey(&OTHER_KEY);
        let selection_after = after
            .select_slot(
                SlotSelector::Label("operator"),
                &KdfLimits::defaults(),
                &new,
            )
            .map_err(|error| format!("select failed: {error}"))?;
        let dek_after = selection_after
            .unwrap_dek(&new, &PanickingKdf)
            .map_err(|error| format!("unwrap failed: {error}"))?;
        assert_eq!(
            &*dek_before, &*dek_after,
            "the data key is unchanged: rotation is not re-keying"
        );
        // The slot the rotation does not touch is the *same bytes*: same prefix,
        // same wrap nonce, same wrapped DEK. That is what a caller reading the
        // file sees, and it is why its credential goes on working.
        let untouched_before = before.slots.get(1).ok_or("the pod slot exists")?;
        let untouched_after = after.slots.get(1).ok_or("the pod slot exists")?;
        assert_eq!(
            untouched_before.wrap_prefix, untouched_after.wrap_prefix,
            "the non-rotated slot's serialized prefix is byte-identical"
        );
        assert_eq!(
            untouched_before.wrapped_dek, untouched_after.wrapped_dek,
            "and so is its wrapped DEK"
        );
        assert_eq!(
            untouched_before.wrap_nonce, untouched_after.wrap_nonce,
            "its wrap nonce is not redrawn"
        );
        let pod = SlotCredential::RawKey(&RAW_KEY);
        assert!(
            after
                .select_slot(SlotSelector::Label("pod"), &KdfLimits::defaults(), &pod)
                .map_err(|error| format!("select failed: {error}"))?
                .unlock(&pod, &PanickingKdf)
                .is_ok(),
            "the untouched pod slot still opens with its own credential"
        );
        assert!(
            selection_after.unlock(&new, &PanickingKdf).is_ok(),
            "and the rotated slot opens with its replacement"
        );
        assert_ne!(
            selection.ciphertext, selection_after.ciphertext,
            "the payload was re-encrypted under a fresh nonce, so its ciphertext and tag changed"
        );
        assert!(
            matches!(
                after
                    .select_slot(
                        SlotSelector::Label("operator"),
                        &KdfLimits::defaults(),
                        &operator
                    )
                    .map_err(|error| format!("select failed: {error}"))?
                    .unlock(&operator, &PanickingKdf),
                Err(EnvelopeError::AuthenticationFailed)
            ),
            "the replaced credential must no longer open the rotated slot"
        );
        Ok(())
    }

    /// **The defect this row exists for**: a rotation must re-encrypt the
    /// payload under a *fresh* nonce.
    ///
    /// Today's `rewrap_slot` rewraps the slot and re-authenticates the payload
    /// under the nonce the file already carries, so one Poly1305 key is used for
    /// two AEAD operations on the same key (KRP-93, review finding 16). The
    /// property is therefore: after a rotation the payload nonce differs, the
    /// ciphertext differs, and the plaintext and the data key do not.
    #[test]
    fn rotation_reencrypts_payload_with_a_fresh_nonce() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(9, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let before =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let old = SlotCredential::RawKey(&RAW_KEY);
        let selection = before
            .select_slot(
                SlotSelector::Label("operator"),
                &KdfLimits::defaults(),
                &old,
            )
            .map_err(|error| format!("select failed: {error}"))?;
        let dek_before = selection
            .unwrap_dek(&old, &PanickingKdf)
            .map_err(|error| format!("unwrap failed: {error}"))?;
        let rotated = rewrap_slot(
            &blob,
            &old,
            SlotSelector::Label("operator"),
            &raw_recipient_with(9, "operator", &OTHER_KEY),
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let after =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        assert_ne!(
            before.payload_nonce, after.payload_nonce,
            "a rotation must draw a fresh payload nonce, or the payload AEAD runs twice under one nonce"
        );
        assert_ne!(
            before.ciphertext, after.ciphertext,
            "and re-encrypt the payload under it, so the ciphertext changes too"
        );
        let new = SlotCredential::RawKey(&OTHER_KEY);
        let selection_after = after
            .select_slot(
                SlotSelector::Label("operator"),
                &KdfLimits::defaults(),
                &new,
            )
            .map_err(|error| format!("select failed: {error}"))?;
        let dek_after = selection_after
            .unwrap_dek(&new, &PanickingKdf)
            .map_err(|error| format!("unwrap failed: {error}"))?;
        assert_eq!(
            &*dek_before, &*dek_after,
            "the data key is unchanged: rotation is not re-keying"
        );
        assert_eq!(
            selection_after
                .unlock(&new, &PanickingKdf)
                .map_err(|error| format!("unlock failed: {error}"))?
                .as_slice(),
            PLAINTEXT,
            "and the payload still opens under the same key"
        );
        Ok(())
    }

    /// A raw-key rotation draws a fresh wrap nonce for the slot it rotates, while
    /// every slot it does not touch keeps its bytes.
    #[test]
    fn rotated_raw_key_slot_gets_a_fresh_wrap_nonce() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "operator"), raw_recipient(2, "pod")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let before =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let rotated = rewrap_slot(
            &blob,
            &SlotCredential::RawKey(&RAW_KEY),
            SlotSelector::Label("pod"),
            &raw_recipient_with(2, "pod", &OTHER_KEY),
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let after =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        let before_pod = before.slots.get(1).ok_or("the pod slot exists")?;
        let after_pod = after.slots.get(1).ok_or("the pod slot exists")?;
        assert_ne!(
            before_pod.wrap_nonce, after_pod.wrap_nonce,
            "the rotated slot's wrap nonce must be freshly drawn"
        );
        assert_ne!(
            before_pod.wrapped_dek, after_pod.wrapped_dek,
            "and its wrapped DEK is the replacement credential's"
        );
        let before_operator = before.slots.first().ok_or("the operator slot exists")?;
        let after_operator = after.slots.first().ok_or("the operator slot exists")?;
        assert_eq!(
            before_operator.wrap_prefix, after_operator.wrap_prefix,
            "the operator slot's prefix is byte-identical"
        );
        assert_eq!(
            before_operator.wrapped_dek, after_operator.wrapped_dek,
            "and so is its wrapped DEK"
        );
        Ok(())
    }

    /// A passphrase rotation draws a fresh salt as well as a fresh wrap nonce,
    /// and keeps the parameters the file already carried: a rotation replaces the
    /// credential, not the KDF.
    #[test]
    fn rotated_passphrase_slot_gets_a_fresh_salt_and_wrap_nonce() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let before =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let rotated = rewrap_slot(
            &blob,
            &SlotCredential::Passphrase(PASSPHRASE),
            SlotSelector::Index(0),
            &Recipient {
                id: 1,
                label: "operator",
                credential: SlotCredential::Passphrase(b"a different passphrase"),
            },
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let after =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        let block_of =
            |envelope: &KeytabEnvelope<'_>| -> Result<[u8; KDF_BLOCK_LEN], &'static str> {
                envelope
                    .slots
                    .first()
                    .and_then(|slot| slot.kdf)
                    .ok_or("the passphrase slot carries a KDF block")
            };
        let before_block = block_of(&before)?;
        let after_block = block_of(&after)?;
        assert_ne!(
            salt_from_block(&before_block),
            salt_from_block(&after_block),
            "the salt must be freshly drawn"
        );
        assert_eq!(
            before_block.get(..KDF_SALT_START),
            after_block.get(..KDF_SALT_START),
            "the block's header before the salt is unchanged"
        );
        assert_eq!(
            before_block.get(KDF_SALT_END..),
            after_block.get(KDF_SALT_END..),
            "and the parameters after it are the file's own"
        );
        let before_slot = before.slots.first().ok_or("the slot exists")?;
        let after_slot = after.slots.first().ok_or("the slot exists")?;
        assert_ne!(
            before_slot.wrap_nonce, after_slot.wrap_nonce,
            "and the wrap nonce is freshly drawn too"
        );
        Ok(())
    }

    /// Seal plus five rotations, and no payload nonce is ever reused - which is
    /// the property, not a proxy for it.
    #[test]
    fn seal_plus_five_rotations_never_reuses_a_payload_nonce() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(1, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let mut credential = SlotCredential::RawKey(&RAW_KEY);
        let mut nonces: Vec<[u8; NONCE_LEN]> = Vec::new();
        let mut rotate_to_other = true;
        for round in 0..=ROTATIONS {
            let envelope =
                KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
            assert!(
                !nonces.contains(&envelope.payload_nonce),
                "round {round} reused a payload nonce"
            );
            nonces.push(envelope.payload_nonce);
            let replacement = if rotate_to_other {
                &OTHER_KEY
            } else {
                &RAW_KEY
            };
            rotate_to_other = !rotate_to_other;
            blob = rewrap_slot(
                &blob,
                &credential,
                SlotSelector::Index(0),
                &raw_recipient_with(1, "operator", replacement),
            )
            .map_err(|error| format!("rewrap failed: {error}"))?;
            credential = SlotCredential::RawKey(replacement);
        }
        assert_eq!(
            nonces.len(),
            ROTATIONS + 1,
            "the seal and five rotations are all counted"
        );
        Ok(())
    }

    /// Seal plus five rotations, and no `(key, nonce)` pair repeats - across the
    /// payload and the wraps alike.
    ///
    /// The pairs are reconstructed from the file: the payload's key is the
    /// unchanged DEK, and each wrap's key is the slot credential it was made
    /// with. A rotation that reused either nonce would repeat a pair here, which
    /// is the AEAD property the format depends on.
    #[test]
    fn seal_plus_five_rotations_never_reuses_a_key_nonce_pair() -> TestResult {
        let mut blob = seal(PLAINTEXT, &[raw_recipient(1, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        let mut key = &RAW_KEY;
        let mut payload_pairs: Vec<([u8; DEK_LEN], [u8; NONCE_LEN])> = Vec::new();
        let mut wrap_pairs: Vec<([u8; KEK_LEN], [u8; NONCE_LEN])> = Vec::new();
        let mut rotate_to_other = true;
        for round in 0..=ROTATIONS {
            let envelope =
                KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
            let credential = SlotCredential::RawKey(key);
            let selection = envelope
                .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), &credential)
                .map_err(|error| format!("select failed: {error}"))?;
            let dek = selection
                .unwrap_dek(&credential, &PanickingKdf)
                .map_err(|error| format!("unwrap failed: {error}"))?;
            let slot = envelope.slots.first().ok_or("the slot exists")?;
            let payload_pair = (*dek, envelope.payload_nonce);
            let wrap_pair = (*key, slot.wrap_nonce);
            assert!(
                !payload_pairs.contains(&payload_pair),
                "round {round} reused a payload (key, nonce) pair"
            );
            assert!(
                !wrap_pairs.contains(&wrap_pair),
                "round {round} reused a wrap (key, nonce) pair"
            );
            payload_pairs.push(payload_pair);
            wrap_pairs.push(wrap_pair);
            let next = if rotate_to_other {
                &OTHER_KEY
            } else {
                &RAW_KEY
            };
            rotate_to_other = !rotate_to_other;
            blob = rewrap_slot(
                &blob,
                &credential,
                SlotSelector::Index(0),
                &raw_recipient_with(1, "operator", next),
            )
            .map_err(|error| format!("rewrap failed: {error}"))?;
            key = next;
        }
        assert!(
            !payload_pairs.iter().any(|pair| wrap_pairs.contains(pair)),
            "no (key, nonce) pair may be used for both a payload and a wrap"
        );
        Ok(())
    }

    /// KRP-93: a replacement of another kind is a reseal, not a rotation, and is
    /// reported as caller error rather than as corruption.
    #[test]
    fn rotation_refuses_kind_mismatch_with_rotation_mismatch() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(6, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            matches!(
                rewrap_slot(
                    &blob,
                    &SlotCredential::RawKey(&RAW_KEY),
                    SlotSelector::Label("operator"),
                    &passphrase_recipient(6, "operator"),
                ),
                Err(EnvelopeError::RotationMismatch)
            ),
            "a kind change is a reseal, and a reseal is not a rotation"
        );
        Ok(())
    }

    /// The writer applies the reader's slot-token rules: two recipients sharing
    /// an id are refused before any wrap is produced, so `seal` cannot emit a
    /// file `KeytabEnvelope::parse` would refuse.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/seal.rs::seal_refuses_duplicate_recipient_ids keeps the uniform test signature while it only asserts"
    )]
    fn seal_refuses_duplicate_recipient_ids() -> TestResult {
        assert!(
            matches!(
                seal(
                    PLAINTEXT,
                    &[raw_recipient(3, "one"), raw_recipient(3, "two")],
                    &Kdf::default()
                ),
                Err(EnvelopeError::Malformed(Malformed::DuplicateSlot))
            ),
            "two recipients sharing an id must be refused by the writer"
        );
        Ok(())
    }

    /// Two recipients sharing a label are refused by the writer too, for the
    /// same reason: the reader refuses the file, so no writer may produce it.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/seal.rs::seal_refuses_duplicate_recipient_labels keeps the uniform test signature while it only asserts"
    )]
    fn seal_refuses_duplicate_recipient_labels() -> TestResult {
        assert!(
            matches!(
                seal(
                    PLAINTEXT,
                    &[raw_recipient(1, "same"), raw_recipient(2, "same")],
                    &Kdf::default()
                ),
                Err(EnvelopeError::Malformed(Malformed::DuplicateSlot))
            ),
            "two recipients sharing a label must be refused by the writer"
        );
        Ok(())
    }

    /// A recipient label spelled like another recipient's decimal id is refused
    /// by the writer, exactly as the reader refuses the file.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/seal.rs::seal_refuses_a_label_spelled_like_another_recipients_id keeps the uniform test signature while it only asserts"
    )]
    fn seal_refuses_a_label_spelled_like_another_recipients_id() -> TestResult {
        assert!(
            matches!(
                seal(
                    PLAINTEXT,
                    &[raw_recipient(1, "x"), raw_recipient(2, "1")],
                    &Kdf::default()
                ),
                Err(EnvelopeError::Malformed(Malformed::SlotIdentifier))
            ),
            "a label spelled like another recipient's id must be refused by the writer"
        );
        Ok(())
    }

    /// A recipient label spelled like its *own* decimal id is refused by the
    /// writer: even a single-slot file would carry two spellings of one token.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/seal.rs::seal_refuses_a_label_spelled_like_its_own_id keeps the uniform test signature while it only asserts"
    )]
    fn seal_refuses_a_label_spelled_like_its_own_id() -> TestResult {
        assert!(
            matches!(
                seal(PLAINTEXT, &[raw_recipient(7, "7")], &Kdf::default()),
                Err(EnvelopeError::Malformed(Malformed::SlotIdentifier))
            ),
            "a label spelled like its own id must be refused by the writer"
        );
        Ok(())
    }

    /// A label carrying a character that cannot be rendered is refused: the
    /// reader refuses such a label, and the diagnostics render labels verbatim.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/seal.rs::seal_refuses_an_unrenderable_label keeps the uniform test signature while it only asserts"
    )]
    fn seal_refuses_an_unrenderable_label() -> TestResult {
        for label in [
            "a\u{1b}b",
            "a\u{202e}b",
            "a\u{61c}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ] {
            assert!(
                matches!(
                    seal(PLAINTEXT, &[raw_recipient(1, label)], &Kdf::default()),
                    Err(EnvelopeError::Malformed(Malformed::SlotLabel))
                ),
                "a label carrying an unrenderable character must be refused by the writer"
            );
        }
        Ok(())
    }

    /// Zero-width joiners and spaces stay legal: real scripts and emoji
    /// sequences use them, and they neither forge nor reorder a line.
    #[test]
    fn seal_accepts_format_characters_that_cannot_forge_a_line() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "a\u{200d}b\u{200b}c")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            KeytabEnvelope::parse(&blob).is_ok(),
            "a joiner is not a character that can forge or reorder a line"
        );
        Ok(())
    }

    /// The writer and the reader agree on the canonical spelling rule: `"07"`
    /// is not the decimal spelling of id 7, so both sides accept it.
    #[test]
    fn seal_accepts_a_non_canonical_numeric_label() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(7, "07")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            KeytabEnvelope::parse(&blob).is_ok(),
            "the reader accepts the same label shape, so the writer must too"
        );
        Ok(())
    }

    /// `seal` refuses a plaintext over the reader's payload cap: a successful
    /// seal must always parse, and the cap is the reader's own rule
    /// (`KeytabEnvelope::parse` rejects `payload_len > MAX_PAYLOAD_LEN`).
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/seal.rs::seal_refuses_a_payload_over_the_cap keeps the uniform test signature while it only asserts"
    )]
    fn seal_refuses_a_payload_over_the_cap() -> TestResult {
        let plaintext = vec![0x41; MAX_PAYLOAD_LEN.saturating_add(1)];
        assert!(
            matches!(
                seal(&plaintext, &[raw_recipient(7, "operator")], &Kdf::default()),
                Err(EnvelopeError::Malformed(Malformed::PayloadLength))
            ),
            "a plaintext over the cap must be refused by the writer"
        );
        Ok(())
    }

    /// A rotation honours a caller-supplied band, exactly as an unlock does: an
    /// envelope sealed with non-default parameters is refused under the default
    /// band and rotates under one that admits them, and the rotated slot still
    /// opens with its replacement.
    #[test]
    fn rotation_honours_a_caller_supplied_band() -> TestResult {
        // 16 MiB, t=1, p=1: at or above the crate's floor, and far below what
        // the default band admits, so only a caller band can carry it.
        let params = Argon2idParams::new(0x4000, 1, 1)
            .map_err(|error| format!("the fixture parameters must be admissible: {error}"))?;
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::Argon2id(params),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            matches!(
                rewrap_slot(
                    &blob,
                    &SlotCredential::Passphrase(PASSPHRASE),
                    SlotSelector::Label("operator"),
                    &passphrase_recipient(1, "operator")
                ),
                Err(EnvelopeError::Malformed(Malformed::Argon2Parameters))
            ),
            "the default band refuses a file sealed with another parameter set"
        );
        let limits = KdfLimits::between(params, params)
            .map_err(|error| format!("one parameter set is a valid band: {error}"))?;
        let replacement = SlotCredential::Passphrase(b"a different passphrase");
        let rotated = rewrap_slot_with_limits(
            &blob,
            &SlotCredential::Passphrase(PASSPHRASE),
            SlotSelector::Label("operator"),
            // Same byte length as the label it replaces - a rotation keeps the
            // file's shape - and its own passphrase, so the replacement is what
            // the rotated slot must open under.
            &Recipient::new(
                1,
                "rotated!",
                SlotCredential::Passphrase(b"a different passphrase"),
            ),
            limits,
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let parsed =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        let selection = parsed
            .select_slot(SlotSelector::Label("rotated!"), &limits, &replacement)
            .map_err(|error| format!("select failed: {error}"))?;
        let opened = selection
            .unlock(&replacement, &Argon2Kdf)
            .map_err(|error| format!("unlock failed: {error}"))?;
        assert_eq!(
            opened.as_slice(),
            PLAINTEXT,
            "the rotated slot opens with its replacement under the same band"
        );
        Ok(())
    }

    /// A rotation rewrites a file that is already valid, so a replacement label
    /// duplicating another slot's label is refused - the result is the reader's
    /// next input.
    #[test]
    fn rotation_refuses_a_replacement_label_duplicating_another_slot() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "aaaa"), raw_recipient(2, "bbbb")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            matches!(
                rewrap_slot(
                    &blob,
                    &SlotCredential::RawKey(&RAW_KEY),
                    SlotSelector::Label("aaaa"),
                    &raw_recipient_with(1, "bbbb", &OTHER_KEY)
                ),
                Err(EnvelopeError::RotationMismatch)
            ),
            "a replacement label duplicating another slot must be refused"
        );
        Ok(())
    }

    /// A replacement label spelled like another slot's decimal id is refused.
    #[test]
    fn rotation_refuses_a_replacement_label_spelled_like_another_slots_id() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "x"), raw_recipient(2, "y")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            matches!(
                rewrap_slot(
                    &blob,
                    &SlotCredential::RawKey(&RAW_KEY),
                    SlotSelector::Label("x"),
                    &raw_recipient_with(1, "2", &OTHER_KEY)
                ),
                Err(EnvelopeError::RotationMismatch)
            ),
            "a replacement label spelled like another slot's id must be refused"
        );
        Ok(())
    }

    /// A replacement label spelled like the rotated slot's own decimal id is
    /// refused.
    #[test]
    fn rotation_refuses_a_replacement_label_spelled_like_its_own_id() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(3, "x")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            matches!(
                rewrap_slot(
                    &blob,
                    &SlotCredential::RawKey(&RAW_KEY),
                    SlotSelector::Label("x"),
                    &raw_recipient_with(3, "3", &OTHER_KEY)
                ),
                Err(EnvelopeError::RotationMismatch)
            ),
            "a replacement label spelled like the slot's own id must be refused"
        );
        Ok(())
    }

    /// A replacement label carrying a character that cannot be rendered is
    /// refused as caller error on a valid file, like the other gate rules. The
    /// replacement keeps the replaced label's byte length, so only the value can
    /// be the refusal.
    #[test]
    fn rotation_refuses_an_unrenderable_replacement_label() -> TestResult {
        for (label, replacement) in [("x", "\u{1b}"), ("abc", "\u{202e}"), ("abc", "\u{2028}")] {
            let blob = seal(PLAINTEXT, &[raw_recipient(1, label)], &Kdf::default())
                .map_err(|error| format!("seal failed: {error}"))?;
            assert!(
                matches!(
                    rewrap_slot(
                        &blob,
                        &SlotCredential::RawKey(&RAW_KEY),
                        SlotSelector::Label(label),
                        &raw_recipient_with(1, replacement, &OTHER_KEY)
                    ),
                    Err(EnvelopeError::RotationMismatch)
                ),
                "a replacement label carrying an unrenderable character must be refused"
            );
        }
        Ok(())
    }

    /// A relabel that collides with nothing still rotates, and the result
    /// parses and opens under the replacement credential: the gate refuses
    /// collisions, not relabelling.
    #[test]
    fn rotation_accepts_a_non_colliding_relabel() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient(1, "x"), raw_recipient(2, "y")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let rotated = rewrap_slot(
            &blob,
            &SlotCredential::RawKey(&RAW_KEY),
            SlotSelector::Label("x"),
            &raw_recipient_with(1, "z", &OTHER_KEY),
        )
        .map_err(|error| format!("rewrap failed: {error}"))?;
        let parsed =
            KeytabEnvelope::parse(&rotated).map_err(|error| format!("parse failed: {error}"))?;
        let replacement = SlotCredential::RawKey(&OTHER_KEY);
        let selection = parsed
            .select_slot(
                SlotSelector::Label("z"),
                &KdfLimits::defaults(),
                &replacement,
            )
            .map_err(|error| format!("select failed: {error}"))?;
        let opened = selection
            .unlock(&replacement, &PanickingKdf)
            .map_err(|error| format!("unlock failed: {error}"))?;
        assert_eq!(
            opened.as_slice(),
            PLAINTEXT,
            "the relabelled slot opens with its replacement credential"
        );
        Ok(())
    }

    /// A label of a different byte length is a reseal: the file's shape would
    /// change, so the slots the rotation does not touch could not stay where they
    /// are.
    #[test]
    fn rotation_refuses_label_length_mismatch_with_rotation_mismatch() -> TestResult {
        let blob = seal(PLAINTEXT, &[raw_recipient(1, "operator")], &Kdf::default())
            .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            matches!(
                rewrap_slot(
                    &blob,
                    &SlotCredential::RawKey(&RAW_KEY),
                    SlotSelector::Index(0),
                    &raw_recipient_with(1, "pod", &OTHER_KEY),
                ),
                Err(EnvelopeError::RotationMismatch)
            ),
            "a label of another length is a reseal, not a rotation"
        );
        Ok(())
    }

    /// **D4: the file authenticates in full before `RotationMismatch` is
    /// decided.** A tampered header must be refused as what it is - a file that
    /// does not authenticate - and not as [`EnvelopeError::RotationMismatch`],
    /// which is *caller* error on a **valid** file: reporting it here sent the
    /// caller hunting for a reseal while the file in hand was forged.
    ///
    /// The tamper is a kind switch: a passphrase slot's `slot_type` and
    /// `kek_alg` bytes are rewritten to the raw-key ones and its 36-byte KDF
    /// block is cut out, with `header_len` reduced by the same 36 bytes, so the
    /// file still parses - as a raw-key slot whose wrap prefix no longer matches
    /// the AAD it was sealed under, and whose kind no longer matches the
    /// passphrase replacement the caller asks for. The mismatch check ran first
    /// and answered for the whole file; the unlock decides now, and its verdict
    /// is the authentication failure.
    #[test]
    fn a_tampered_envelope_is_refused_before_rotation_mismatch() -> TestResult {
        // The fixture's offsets: the fixed header is 70 bytes, and the slot is
        // `slot_id` (4) `slot_type` (1) `slot_label_len` (1) "operator" (8)
        // `kek_alg` (1), then the KDF block, `wrap_alg`, the nonce and the wrap.
        const SLOT_TYPE_OFFSET: usize = 74;
        const KEK_ALG_OFFSET: usize = 84;
        const KDF_BLOCK_OFFSET: usize = 85;
        const HEADER_LEN_OFFSET: usize = 16;
        let sealed = seal(
            PLAINTEXT,
            &[passphrase_recipient(7, "operator")],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let header_len = KeytabEnvelope::parse(&sealed)
            .map_err(|error| format!("the sealed file must parse: {error}"))?
            .header
            .len();
        let mut tampered = sealed;
        if let Some(byte) = tampered.get_mut(SLOT_TYPE_OFFSET) {
            *byte = SLOT_TYPE_RAW_KEY;
        }
        if let Some(byte) = tampered.get_mut(KEK_ALG_OFFSET) {
            *byte = KEK_ALG_DIRECT_256;
        }
        drop(tampered.drain(KDF_BLOCK_OFFSET..KDF_BLOCK_OFFSET + KDF_BLOCK_LEN));
        let shortened = u32::try_from(header_len - KDF_BLOCK_LEN).unwrap_or(u32::MAX);
        if let Some(field) = tampered.get_mut(HEADER_LEN_OFFSET..HEADER_LEN_OFFSET + 4) {
            field.copy_from_slice(&shortened.to_le_bytes());
        }
        let parsed = KeytabEnvelope::parse(&tampered)
            .map_err(|error| format!("the tampered file still parses: {error}"))?;
        assert_eq!(
            parsed.slots.first().map(|slot| slot.kind),
            Some(SlotType::RawKey),
            "the tamper moved the slot's kind, and the file parses as the raw-key slot it now claims to be"
        );
        // The caller asks for a passphrase replacement: a shape the tampered
        // header cannot accept, which is exactly what the mismatch check used
        // to report as a reseal.
        let refused = rewrap_slot(
            &tampered,
            &SlotCredential::RawKey(&RAW_KEY),
            SlotSelector::Index(0),
            &passphrase_recipient(7, "operator"),
        );
        assert!(
            matches!(refused, Err(EnvelopeError::AuthenticationFailed)),
            "a tampered header is an authentication failure, not a rotation mismatch: {refused:?}"
        );
        Ok(())
    }

    /// KRP-88: the seal path never derives, for a raw-key recipient - the
    /// backend that panics is not reached, on sealing or on the unlock that
    /// follows it.
    #[test]
    fn a_raw_key_recipient_never_reaches_argon2_on_the_seal_path() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient_with(5, "pod", &OTHER_KEY)],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let envelope =
            KeytabEnvelope::parse(&blob).map_err(|error| format!("parse failed: {error}"))?;
        let credential = SlotCredential::RawKey(&OTHER_KEY);
        let plaintext = envelope
            .select_slot(
                SlotSelector::Label("pod"),
                &KdfLimits::defaults(),
                &credential,
            )
            .map_err(|error| format!("select failed: {error}"))?
            .unlock(&credential, &PanickingKdf)
            .map_err(|error| format!("unlock failed: {error}"))?;
        assert_eq!(plaintext.as_slice(), PLAINTEXT);
        Ok(())
    }

    /// SOW §4/A6: `seal` takes the caller's KDF **by reference**, and so does
    /// the deterministic half. Asserted in the source because a signature is
    /// what the row fixed - a test can only show the value it happened to pass -
    /// and because a second, by-value overload is exactly what the row forbids.
    #[test]
    fn seal_takes_kdf_by_reference() -> TestResult {
        let source = include_str!("seal.rs");
        let production = production_text(source);
        for function in ["pub fn seal(", "fn seal_with("] {
            let start = production
                .find(function)
                .ok_or_else(|| format!("{function} must still exist"))?;
            let parameters = production
                .get(start..)
                .and_then(|rest| rest.get(..rest.find('{')?))
                .ok_or_else(|| format!("{function}'s signature must close"))?;
            assert!(
                parameters.contains("kdf: &Kdf"),
                "{function} must take the caller's KDF by reference: {parameters}"
            );
        }
        assert!(
            !production.contains("kdf: Kdf"),
            "no by-value overload of the KDF may survive (SOW section 4, KRP-88)"
        );
        Ok(())
    }
}
