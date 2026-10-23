//! The plug point's implementation: a still-locked envelope, opened on demand.
//!
//! [`EnvelopeUnlocker`] is the whole of what this crate adds to
//! `kpasswd_rs::KeytabUnlocker`. It owns the ciphertext, the slot selector and
//! the credential, derives and decrypts nothing until it is asked, and hands the
//! plaintext back as a `Zeroizing<Vec<u8>>` that the exchange drops.
//!
//! Three properties are structural rather than promised:
//!
//! * **Envelope-only.** [`EnvelopeUnlocker::new`] checks the magic before it
//!   moves a byte, so a plaintext keytab - a bearer secret - can never become
//!   the deferred credential (r12/D2).
//! * **Three fields, no cache.** The ciphertext, the owned credential and the
//!   Argon2id band, and nothing else; no interior mutability and no plaintext
//!   field, which is what makes "the unlocker cannot cache" a fact about the
//!   declaration.
//! * **A closed error map.** Every [`EnvelopeError`] becomes exactly one
//!   `kpasswd_rs::UnlockError`, whose type carries no payload.

use core::fmt;

use kpasswd_rs::{KeytabUnlocker, UnlockError, is_envelope};
use zeroize::Zeroizing;

use crate::{
    credential::{SlotCredential, SlotSelector},
    envelope::KeytabEnvelope,
    format::{EnvelopeError, KEK_LEN, Malformed},
    kdf::{Argon2Kdf, KdfBackend, KdfLimits},
};

/// The owned form of [`SlotSelector`].
///
/// A selector borrows its label; the unlock may happen long after the caller's
/// string is gone, so the label is copied into a `String` of this crate's own.
/// A selector holds no secret.
enum OwnedSlotSelector {
    /// The slot at this position, as [`SlotSelector::Index`].
    Index(u8),
    /// The slot with this label, as [`SlotSelector::Label`].
    Label(String),
}

impl OwnedSlotSelector {
    /// Take ownership of a caller's selector.
    ///
    /// [`SlotSelector`] is `#[non_exhaustive]`, but this crate defines it, so
    /// this match is exhaustive where a consumer's could not be: a selector this
    /// build cannot own does not exist.
    fn from_borrowed(slot: SlotSelector<'_>) -> Self {
        match slot {
            SlotSelector::Index(index) => Self::Index(index),
            SlotSelector::Label(label) => Self::Label(label.to_owned()),
        }
    }

    /// The selector the envelope takes, borrowed for the length of the call.
    fn as_borrowed(&self) -> SlotSelector<'_> {
        match self {
            Self::Index(index) => SlotSelector::Index(*index),
            Self::Label(label) => SlotSelector::Label(label),
        }
    }
}

/// The owned form of [`SlotCredential`].
///
/// Both borrowed variants become a `Zeroizing` buffer of this crate's own - the
/// key is copied, the passphrase is copied - and
/// [`SlotCredential::PassphraseOwned`] is moved in without a copy, which is what
/// a caller that already owns the secret hands over. Nothing here is `Clone`: a
/// second copy of a passphrase is the defect, not the convenience.
enum OwnedSlotCredential {
    /// A raw KEK, copied out of the caller's borrow.
    RawKey(Zeroizing<[u8; KEK_LEN]>),
    /// Passphrase text, copied or moved in.
    Passphrase(Zeroizing<Vec<u8>>),
}

impl OwnedSlotCredential {
    /// Take ownership of a caller's credential.
    fn from_borrowed(credential: SlotCredential<'_>) -> Self {
        match credential {
            SlotCredential::RawKey(key) => Self::RawKey(Zeroizing::new(*key)),
            SlotCredential::Passphrase(text) => Self::Passphrase(Zeroizing::new(text.to_vec())),
            // The one variant that is already owned: moved, never copied.
            SlotCredential::PassphraseOwned(text) => Self::Passphrase(text),
        }
    }

    /// The credential the envelope takes, borrowed for the length of the call.
    fn as_borrowed(&self) -> SlotCredential<'_> {
        match self {
            Self::RawKey(key) => SlotCredential::RawKey(key),
            Self::Passphrase(text) => SlotCredential::Passphrase(text.as_slice()),
        }
    }
}

/// Which slot to open, and what opens it, owned by the unlocker.
///
/// The selector is not a secret; the credential is. Keeping the two together
/// leaves [`EnvelopeUnlocker`] with exactly the three fields its no-cache guard
/// pins, and keeps `PassphraseOwned`'s single buffer intact.
struct OwnedCredential {
    /// Which slot the caller named.
    slot: OwnedSlotSelector,
    /// What opens that slot.
    secret: OwnedSlotCredential,
}

impl OwnedCredential {
    /// Take ownership of a caller's selector and credential.
    fn from_borrowed(slot: SlotSelector<'_>, credential: SlotCredential<'_>) -> Self {
        Self {
            slot: OwnedSlotSelector::from_borrowed(slot),
            secret: OwnedSlotCredential::from_borrowed(credential),
        }
    }
}

/// A still-locked keytab: an envelope, a resolved slot, and the credential that
/// opens it. Nothing is derived and nothing is decrypted until `unlock`.
#[non_exhaustive]
pub struct EnvelopeUnlocker {
    /// The envelope's bytes, exactly as the caller handed them over.
    bytes: Zeroizing<Vec<u8>>,
    /// Which slot to open, and what opens it.
    credential: OwnedCredential,
    /// The Argon2id band the unlock honours.
    limits: KdfLimits,
}

impl EnvelopeUnlocker {
    /// Wraps an encrypted keytab together with the slot to open and the
    /// credential that opens it.
    ///
    /// Only the magic is checked here. Bytes that are not an envelope are
    /// refused, so a plain keytab can never be stored as if it were locked.
    /// The bytes are moved into a buffer that is wiped on drop **before** that
    /// check, so refused bytes are wiped too. A borrowed credential is copied
    /// into a wiped-on-drop buffer of the unlocker's own, and
    /// [`SlotCredential::PassphraseOwned`] is moved in without a second copy.
    ///
    /// The slot is never picked for you. To use, say, the only slot a raw key
    /// can open, read [`KeytabEnvelope::slots`] and name the slot you found.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Malformed`] with [`Malformed::Magic`] when the bytes are
    /// not an envelope. Nothing else is checked here: a slot that does not exist
    /// and a wrong credential are reported by `unlock`, so a locked keytab can
    /// be built before its credential is ever tried.
    #[inline]
    pub fn new(
        bytes: Vec<u8>,
        slot: SlotSelector<'_>,
        credential: SlotCredential<'_>,
    ) -> Result<Self, EnvelopeError> {
        // Wrapped **before** the admission test: the refusal path drops the
        // buffer too, and a plaintext keytab is exactly what it refuses, so the
        // wiped-on-drop custody has to cover the bytes on both branches.
        let buffer = Zeroizing::new(bytes);
        if !is_envelope(buffer.as_slice()) {
            return Err(EnvelopeError::Malformed(Malformed::Magic));
        }
        Ok(Self {
            bytes: buffer,
            credential: OwnedCredential::from_borrowed(slot, credential),
            limits: KdfLimits::defaults(),
        })
    }

    /// Sets the range of Argon2id parameters this unlock accepts.
    ///
    /// A passphrase slot whose parameters fall outside it is refused before any
    /// derivation. The default, [`KdfLimits::defaults`], accepts only the
    /// default parameters.
    #[must_use]
    #[inline]
    pub const fn kdf_limits(mut self, limits: KdfLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Parse the envelope, locate the named slot, and open it with `kdf`.
    ///
    /// The band in [`EnvelopeUnlocker::limits`] is checked inside the selection
    /// before `kdf` is reached, so an attacker-supplied parameter block costs a
    /// comparison rather than a derivation.
    /// # Errors
    ///
    /// Every [`EnvelopeError`] [`KeytabEnvelope::parse`],
    /// [`KeytabEnvelope::select_slot`] and `Selection::unlock` report.
    fn open(&self, kdf: &dyn KdfBackend) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let envelope = KeytabEnvelope::parse(self.bytes.as_slice())?;
        let credential = self.credential.secret.as_borrowed();
        let selection = envelope.select_slot(
            self.credential.slot.as_borrowed(),
            &self.limits,
            &credential,
        )?;
        selection.unlock(&credential, kdf)
    }

    /// Check the selected slot against this unlocker's band, without opening it.
    ///
    /// A caller that wants the envelope's own diagnosis of a refusal, rather
    /// than the payload-free [`UnlockError`] that `unlock` reports, calls this
    /// before the exchange. It parses the header, resolves the
    /// selector and runs the same band comparison the unlock runs, and stops
    /// there: **no key is derived, no ciphertext is touched,
    /// and no secret reaches the error.** The refusal it returns is the one the
    /// format defines, so an operator reads *which* rule was broken.
    ///
    /// Calling it is optional and changes nothing about the unlock: `unlock`
    /// repeats every check for itself, because a caller that skips this must
    /// not get a weaker exchange.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Malformed`] with [`Malformed::Argon2Parameters`] when
    /// the slot's parameters are outside the band, and every other
    /// [`EnvelopeError`] that parsing the header or resolving the selector
    /// reports.
    #[inline]
    pub fn check_cost_band(&self) -> Result<(), EnvelopeError> {
        let envelope = KeytabEnvelope::parse(self.bytes.as_slice())?;
        let credential = self.credential.secret.as_borrowed();
        envelope
            .select_slot(
                self.credential.slot.as_borrowed(),
                &self.limits,
                &credential,
            )?
            .check_cost_band()
    }

    /// [`EnvelopeUnlocker::open`], classified for the plug point.
    ///
    /// Split from the trait method so a test can inject a [`KdfBackend`] that
    /// fails loudly: "an out-of-band block is refused before the backend" has to
    /// hold for whatever backend a caller would inject, not only for
    /// [`Argon2Kdf`].
    /// # Errors
    ///
    /// Whatever [`EnvelopeUnlocker::open`] reports, as the payload-free
    /// [`UnlockError`] classification [`classify`] fixes.
    fn unlocked(&self, kdf: &dyn KdfBackend) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        self.open(kdf).map_err(classify)
    }
}

impl KeytabUnlocker for EnvelopeUnlocker {
    /// The plaintext keytab, in the clear.
    ///
    /// The value is constructed here and moved out by `return`; no binding
    /// survives the call, and the only field this type could cache it in does
    /// not exist.
    /// # Errors
    ///
    /// [`UnlockError`]: [`UnlockError::NotAuthenticated`] for a wrong credential
    /// or altered bytes, [`UnlockError::RefusedByPolicy`] when the selected
    /// slot's Argon2 parameters are outside the band, [`UnlockError::Malformed`]
    /// for anything else about the file - including a selector that names no
    /// slot - and [`UnlockError::Unavailable`] when the derivation could not
    /// run.
    #[inline]
    fn unlock(&self) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        self.unlocked(&Argon2Kdf)
    }
}

impl fmt::Debug for EnvelopeUnlocker {
    /// Names the type and redacts everything: the ciphertext, the selector and
    /// the credential are all present, and a derived `Debug` would print the
    /// first and the last of them wherever the boxed unlocker is formatted.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnvelopeUnlocker(<redacted>)")
    }
}

/// The one place an [`EnvelopeError`] becomes an [`UnlockError`] (SOW §4.6).
///
/// The map is a total function with no wildcard: a new envelope failure has to
/// be classified deliberately, which is what stops one riding out as an
/// implementation's own message. `RotationMismatch` is unreachable on the unlock
/// path - only a reseal reports it - and it is mapped rather than
/// `unreachable!()`, which the workspace denies.
const fn classify(error: EnvelopeError) -> UnlockError {
    match error {
        EnvelopeError::AuthenticationFailed => UnlockError::NotAuthenticated,
        EnvelopeError::Malformed(Malformed::Argon2Parameters) => UnlockError::RefusedByPolicy,
        EnvelopeError::Malformed(
            Malformed::TooShort
            | Malformed::Magic
            | Malformed::Version
            | Malformed::HeaderLength
            | Malformed::HeaderBoundary
            | Malformed::SlotCount
            | Malformed::SlotType
            | Malformed::SlotLabel
            | Malformed::SlotPairing
            | Malformed::SlotIdentifier
            | Malformed::DuplicateSlot
            | Malformed::Algorithm
            | Malformed::PayloadLength
            | Malformed::LengthIdentity,
        )
        | EnvelopeError::RotationMismatch => UnlockError::Malformed,
        EnvelopeError::DerivationFailed | EnvelopeError::EntropyUnavailable => {
            UnlockError::Unavailable
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kpasswd_rs::{KeytabUnlocker, UnlockError};

    use super::{EnvelopeUnlocker, classify, is_envelope};
    use crate::{
        credential::{SlotCredential, SlotSelector},
        envelope::KeytabEnvelope,
        format::{EnvelopeError, MAGIC, Malformed},
        kdf::{Argon2idParams, Kdf},
        seal::seal,
        test_support::{
            OTHER_KEY, PASSPHRASE, PLAINTEXT, PanickingKdf, RAW_KEY, TestResult,
            passphrase_recipient, raw_recipient_with,
        },
    };

    /// A selector for the single-slot fixtures below.
    const OPERATOR: SlotSelector<'_> = SlotSelector::Label("operator");

    /// A plaintext keytab is a bearer secret, so the deferred state must refuse
    /// it on the magic rather than store it (r12/D2).
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/unlocker.rs::envelope_unlocker_refuses_a_plaintext_keytab keeps the uniform test signature while it only asserts"
    )]
    fn envelope_unlocker_refuses_a_plaintext_keytab() -> TestResult {
        let outcome = EnvelopeUnlocker::new(
            b"a keytab stands here".to_vec(),
            OPERATOR,
            SlotCredential::Passphrase(PASSPHRASE),
        );
        assert!(
            matches!(outcome, Err(EnvelopeError::Malformed(Malformed::Magic))),
            "non-envelope bytes must be refused before anything is stored"
        );
        Ok(())
    }

    /// The gate and the parser agree on the magic.
    ///
    /// A sealed envelope is accepted by the dependency's `is_envelope` - the
    /// check `new` delegates to - and the crate's own magic is what it tests
    /// for: a dependency magic change must fail here rather than silently split
    /// the two doors.
    #[test]
    fn the_dependency_magic_agrees_with_this_crates_magic() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient_with(1, "operator", &RAW_KEY)],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        assert!(
            is_envelope(&blob),
            "the dependency's gate must accept what this crate writes"
        );
        assert!(
            KeytabEnvelope::parse(&blob).is_ok(),
            "and this crate's parser must accept it too"
        );
        assert!(
            is_envelope(MAGIC),
            "the crate's magic is the dependency's magic"
        );
        assert!(
            !is_envelope(b"a keytab stands here"),
            "and neither door accepts a plaintext keytab"
        );
        Ok(())
    }

    /// The refusal path must wipe too: the buffer is wrapped in `Zeroizing`
    /// **before** the magic test, so a refused plaintext keytab is wiped on the
    /// way out exactly as the accepted buffer is.
    #[test]
    fn the_admission_gate_wipes_the_buffer_it_refuses() -> TestResult {
        let source = crate::production_text(include_str!("unlocker.rs"));
        let start = source
            .find("pub fn new(")
            .ok_or("`EnvelopeUnlocker::new` must still exist")?;
        let body = source.get(start..).unwrap_or_default();
        let end = body.find("\n    }").unwrap_or(body.len());
        let window = body.get(..end).unwrap_or_default();
        let wrap = window.find("Zeroizing::new(bytes)");
        let test = window.find("is_envelope(");
        assert!(
            matches!((wrap, test), (Some(wrap_offset), Some(test_offset)) if wrap_offset < test_offset),
            "`new` must move the buffer into `Zeroizing` before it tests the magic, so the refusal path wipes what it refuses"
        );
        // Ordering alone would pass a `new` that copied the bytes and dropped
        // the copy unwiped: `new` takes no copy at all.
        for copy in [
            ".clone()",
            ".to_vec()",
            ".to_owned()",
            "copy_from_slice(",
            "extend_from_slice(",
        ] {
            assert!(
                !window.contains(copy),
                "`new` must not copy the bytes it may refuse (found `{copy}`)"
            );
        }
        Ok(())
    }

    /// The behavioural half of the guard above: the bytes `new` refuses are
    /// wiped before their allocation is freed.
    ///
    /// `new` takes the buffer by value, so the test reads the freed block back
    /// through `/proc/self/mem`. The first 32 bytes are skipped: the allocator
    /// writes its free-list bookkeeping there.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/unlocker.rs::the_refused_buffer_is_wiped_before_it_is_freed keeps the uniform test signature while it only asserts"
    )]
    fn the_refused_buffer_is_wiped_before_it_is_freed() -> TestResult {
        use crate::test_support::FreedMemory;

        /// Bytes in the refused buffer: small enough for the allocator's
        /// per-thread cache, so the freed block stays mapped and unmerged.
        const LEN: usize = 256;
        /// Leading bytes of a freed block the allocator may overwrite.
        const HEADER: usize = 32;
        /// Bytes after the header the test reads back.
        const WATCHED: usize = 224;
        /// A byte value a wipe never leaves behind.
        const MARKER: u8 = 0xa5;

        let mut memory = FreedMemory::new(WATCHED);
        let refused = vec![MARKER; LEN];
        let address = refused.as_ptr().addr().saturating_add(HEADER);
        let outcome = EnvelopeUnlocker::new(refused, OPERATOR, SlotCredential::RawKey(&RAW_KEY));
        let residue = memory.residue(address, MARKER);
        assert!(
            matches!(outcome, Err(EnvelopeError::Malformed(Malformed::Magic))),
            "a marker buffer is not an envelope, so `new` must refuse it"
        );
        assert_eq!(
            residue, 0,
            "`new` must wipe the bytes it refuses before freeing them; {residue} of {WATCHED} survived"
        );

        // Instrument control: an unwiped block freed the same way is visible,
        // so the zero above is a wipe rather than a blind spot.
        let plain = vec![MARKER; LEN];
        let control_address = plain.as_ptr().addr().saturating_add(HEADER);
        drop(plain);
        let control = memory.residue(control_address, MARKER);
        assert_eq!(
            control, WATCHED,
            "the instrument must see an unwiped freed block; it saw {control} of {WATCHED} bytes"
        );
        Ok(())
    }

    /// A raw-key slot opens through the trait object a client holds, and the
    /// plaintext comes back byte-for-byte.
    #[test]
    fn a_raw_key_unlock_round_trips_through_the_trait() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient_with(1, "operator", &RAW_KEY)],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let unlocker = EnvelopeUnlocker::new(blob, OPERATOR, SlotCredential::RawKey(&RAW_KEY))
            .map_err(|error| format!("a sealed envelope must be accepted: {error}"))?;
        let trait_object: &dyn KeytabUnlocker = &unlocker;
        let plaintext = trait_object
            .unlock()
            .map_err(|error| format!("the fixture must open: {error}"))?;
        assert_eq!(
            plaintext.as_slice(),
            PLAINTEXT,
            "the payload comes back exactly as it was sealed"
        );
        Ok(())
    }

    /// The wrong raw key fails the wrap's tag, and that is the authentication
    /// classification - not a parse failure and not a policy refusal.
    #[test]
    fn a_wrong_credential_is_not_authenticated() -> TestResult {
        let blob = seal(
            PLAINTEXT,
            &[raw_recipient_with(1, "operator", &RAW_KEY)],
            &Kdf::default(),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let unlocker = EnvelopeUnlocker::new(blob, OPERATOR, SlotCredential::RawKey(&OTHER_KEY))
            .map_err(|error| format!("a sealed envelope must be accepted: {error}"))?;
        assert!(
            matches!(unlocker.unlock(), Err(UnlockError::NotAuthenticated)),
            "a key that does not open the slot must be NotAuthenticated"
        );
        Ok(())
    }

    /// A slot whose declared Argon2 parameters fall outside the band is refused
    /// by policy, and the backend that panics if reached proves the refusal
    /// precedes every derivation.
    #[test]
    fn an_out_of_band_argon2_block_is_refused_by_policy() -> TestResult {
        // 16 MiB, t=1, p=1: at or above the crate's floor, and far below the
        // 64 MiB the default band admits, so only the band can refuse it.
        let params = Argon2idParams::new(0x4000, 1, 1)
            .map_err(|error| format!("the fixture parameters must be admissible: {error}"))?;
        let blob = seal(
            PLAINTEXT,
            &[passphrase_recipient(1, "operator")],
            &Kdf::Argon2id(params),
        )
        .map_err(|error| format!("seal failed: {error}"))?;
        let unlocker =
            EnvelopeUnlocker::new(blob, OPERATOR, SlotCredential::Passphrase(PASSPHRASE))
                .map_err(|error| format!("a sealed envelope must be accepted: {error}"))?;
        assert!(
            matches!(
                unlocker.unlocked(&PanickingKdf),
                Err(UnlockError::RefusedByPolicy)
            ),
            "a block outside the default band is refused before the backend is reached"
        );
        Ok(())
    }

    /// Every [`EnvelopeError`] becomes exactly the [`UnlockError`] SOW §4.6
    /// names, arm by arm.
    ///
    /// The match below is exhaustive over the envelope's variants, and it names
    /// no `Unreadable`: that variant does not exist, because this crate opens no
    /// file, so reintroducing it fails this test to compile.
    #[test]
    #[expect(
        clippy::match_same_arms,
        reason = "deliberate: src/unlocker.rs::every_envelope_error_maps_to_a_classification SOW §4.6 lists RotationMismatch as its own row: it is unreachable on the unlock path and classified as Malformed deliberately, so it keeps its own arm to name that decision"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/unlocker.rs::every_envelope_error_maps_to_a_classification keeps the uniform test signature while it only asserts"
    )]
    fn every_envelope_error_maps_to_a_classification() -> TestResult {
        let errors = [
            EnvelopeError::AuthenticationFailed,
            EnvelopeError::Malformed(Malformed::Argon2Parameters),
            EnvelopeError::Malformed(Malformed::TooShort),
            EnvelopeError::Malformed(Malformed::Magic),
            EnvelopeError::Malformed(Malformed::Version),
            EnvelopeError::Malformed(Malformed::HeaderLength),
            EnvelopeError::Malformed(Malformed::HeaderBoundary),
            EnvelopeError::Malformed(Malformed::SlotCount),
            EnvelopeError::Malformed(Malformed::SlotType),
            EnvelopeError::Malformed(Malformed::SlotLabel),
            EnvelopeError::Malformed(Malformed::SlotPairing),
            EnvelopeError::Malformed(Malformed::SlotIdentifier),
            EnvelopeError::Malformed(Malformed::DuplicateSlot),
            EnvelopeError::Malformed(Malformed::Algorithm),
            EnvelopeError::Malformed(Malformed::PayloadLength),
            EnvelopeError::Malformed(Malformed::LengthIdentity),
            EnvelopeError::DerivationFailed,
            EnvelopeError::EntropyUnavailable,
            EnvelopeError::RotationMismatch,
        ];
        for error in errors {
            let expected = match error {
                EnvelopeError::AuthenticationFailed => UnlockError::NotAuthenticated,
                EnvelopeError::Malformed(Malformed::Argon2Parameters) => {
                    UnlockError::RefusedByPolicy
                }
                EnvelopeError::Malformed(
                    Malformed::TooShort
                    | Malformed::Magic
                    | Malformed::Version
                    | Malformed::HeaderLength
                    | Malformed::HeaderBoundary
                    | Malformed::SlotCount
                    | Malformed::SlotType
                    | Malformed::SlotLabel
                    | Malformed::SlotPairing
                    | Malformed::SlotIdentifier
                    | Malformed::DuplicateSlot
                    | Malformed::Algorithm
                    | Malformed::PayloadLength
                    | Malformed::LengthIdentity,
                ) => UnlockError::Malformed,
                EnvelopeError::DerivationFailed | EnvelopeError::EntropyUnavailable => {
                    UnlockError::Unavailable
                }
                EnvelopeError::RotationMismatch => UnlockError::Malformed,
            };
            assert_eq!(
                classify(error),
                expected,
                "the classification of {error} must match SOW §4.6"
            );
        }
        Ok(())
    }

    /// Every secret-bearing field the unlocker owns is a `Zeroizing` buffer, so
    /// the ciphertext and the credential die with it.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/unlocker.rs::owned_unlocker_secrets_are_zeroizing keeps the uniform test signature while it only asserts"
    )]
    fn owned_unlocker_secrets_are_zeroizing() -> TestResult {
        let source = crate::production_text(include_str!("unlocker.rs"));
        for declaration in [
            "bytes: Zeroizing<Vec<u8>>,",
            "credential: OwnedCredential,",
            "limits: KdfLimits,",
            "slot: OwnedSlotSelector,",
            "secret: OwnedSlotCredential,",
            "RawKey(Zeroizing<[u8; KEK_LEN]>),",
            "Passphrase(Zeroizing<Vec<u8>>),",
        ] {
            assert!(
                source.contains(declaration),
                "the unlocker's declarations must contain {declaration}; a bare buffer would be the defect"
            );
        }
        for selector in ["Index(u8),", "Label(String),"] {
            assert!(
                source.contains(selector),
                "the selector holds no secret, so {selector} is expected"
            );
        }
        Ok(())
    }

    /// The §4.3 no-cache guard: exactly three fields, and no interior mutability
    /// a `&self` unlock could write a plaintext cache through.
    ///
    /// The interior-mutability scan runs over the file's whole production half
    /// rather than the declaration alone: a module-level cache written through
    /// `&self` is exactly what the no-cache property forbids, and a
    /// declaration-only scan cannot see it.
    ///
    /// Proof it bites: a fourth field named in the three-field assertion fails
    /// the count, a `RefCell` in the declaration fails the scan, and a
    /// `thread_local!` anywhere in the production half fails it too.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/unlocker.rs::unlocker_fields_hold_ciphertext_and_credential_only keeps the uniform test signature while it only asserts"
    )]
    fn unlocker_fields_hold_ciphertext_and_credential_only() -> TestResult {
        let source = crate::production_text(include_str!("unlocker.rs"));
        let declaration = struct_declaration(&source, "pub struct EnvelopeUnlocker {");
        let fields: Vec<&str> = declaration
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.is_empty()
                    && !line.starts_with("///")
                    && !line.starts_with("//")
                    && !line.starts_with("#[")
            })
            .collect();
        assert_eq!(
            fields,
            vec![
                "bytes: Zeroizing<Vec<u8>>,",
                "credential: OwnedCredential,",
                "limits: KdfLimits,",
            ],
            "the unlocker has exactly three fields: the ciphertext, the owned credential and the band"
        );
        // The scan covers the file's whole production half, not only the
        // declaration: a module-level `static` or `thread_local!` cache written
        // through `&self` would evade a declaration-only scan.
        for forbidden in [
            "Cell<",
            "RefCell",
            "Mutex",
            "RwLock",
            "OnceCell",
            "OnceLock",
            "Atomic",
            "thread_local!",
            "static mut ",
        ] {
            assert!(
                !source.contains(forbidden),
                "the production half must name no {forbidden}: a cache the guard cannot see is how the no-cache property would be lost"
            );
        }
        Ok(())
    }

    /// The trait object a client boxes must cross a `tokio::spawn` boundary, so
    /// the implementation is `Send + Sync`.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/unlocker.rs::the_unlocker_is_send_and_sync keeps the uniform test signature while it only asserts"
    )]
    fn the_unlocker_is_send_and_sync() -> TestResult {
        /// Fails to compile if `T` is not both `Send` and `Sync`.
        const fn assert_send_and_sync<T>()
        where
            T: Send + Sync,
        {
        }
        assert_send_and_sync::<EnvelopeUnlocker>();
        Ok(())
    }

    /// The body of the declaration that starts with `header`, from the line
    /// after its `{` to its closing `}`.
    ///
    /// A source guard has to read the declaration rather than a signature, and
    /// this is the one shape every guard in this file parses: the crate's
    /// formatter keeps the closing brace at column zero.
    #[expect(
        clippy::panic,
        reason = "deliberate: src/unlocker.rs::struct_declaration a missing declaration means the guard is about code that no longer exists"
    )]
    fn struct_declaration<'source>(source: &'source str, header: &str) -> &'source str {
        let start = source.find(header).map_or_else(
            || panic!("the declaration `{header}` must still exist"),
            |offset| offset.saturating_add(header.len()),
        );
        let body = source.get(start..).unwrap_or_default();
        let end = body.find("\n}").unwrap_or(body.len());
        body.get(..end).unwrap_or_default()
    }
}
