//! An encrypted file format for Kerberos keytabs, and an unlocker that hands the
//! decrypted keytab to `kpasswd-rs`.
//!
//! The point is to keep a keytab encrypted while it is stored, so that the
//! copies piling up in snapshots, backups and leftover volumes are useless
//! without a key kept somewhere else. That is all it protects. Anything that can
//! unlock the file can leak the keytab, so a compromised host or a key stored
//! next to the file defeats it, and it does nothing about plain copies that
//! leaked before.
//!
//! [`seal`] encrypts a keytab for up to eight recipients, each of which gets a
//! slot that opens with either a raw 32-byte key or a passphrase.
//! [`EnvelopeUnlocker`] holds the sealed bytes and implements
//! [`kpasswd_rs::KeytabUnlocker`]: hand it to
//! [`kpasswd_rs::AdminIdentity::from_locked_keytab`], and the keytab is
//! decrypted only when an exchange needs it, in a buffer that is wiped on drop.
//! [`rewrap_slot`] replaces the key of one slot, and [`KeytabEnvelope::parse`]
//! reads a file's header, for example to list its slots.
//!
//! # File format
//!
//! The keytab is encrypted once with XChaCha20-Poly1305, under a random 256-bit
//! data key (DEK). The DEK is wrapped once per slot, under that slot's
//! key-encryption key (KEK), the way LUKS and age do it. A raw-key slot uses its
//! 32 bytes directly as the KEK, which suits a key that is already random: a
//! Kubernetes Secret, a `0400` key file, a systemd `LoadCredential=`, an OS
//! keyring. A passphrase slot derives the KEK with Argon2id. Opening a raw-key
//! slot runs no Argon2 code and allocates none of its memory.
//!
//! There is one version, one cipher and one way to build the associated data,
//! so two writers can't produce files that are both valid and incompatible.
//! Writers apply the reader's structural rules too, so whatever [`seal`] or
//! [`rewrap_slot`] returns, [`KeytabEnvelope::parse`] accepts.
//!
//! ```text
//! header (all integers little-endian, canonical)
//!   magic          "KRBRESETKEYTAB"      14 bytes
//!   version        u16 = 1
//!   header_len     u32   byte offset of the payload ciphertext
//!   payload_alg    u8    = 1 (XChaCha20-Poly1305)
//!   payload_nonce  24 bytes
//!   payload_len    u64   plaintext length, tag excluded
//!   file_id        16 bytes  random at seal, never changed afterwards
//!   slot_count     u8    1..=8
//!   slots[slot_count]
//! payload_ciphertext || tag(16)
//!
//! slot
//!   slot_id        u32
//!   slot_type      u8    1 = raw-key, 2 = passphrase
//!   slot_label_len u8    byte count, at most 64
//!   slot_label     UTF-8, no control, line-separator or bidi characters, exactly slot_label_len bytes
//!   kek_alg        u8    1 = direct-256, 2 = argon2id
//!   kdf            absent for raw-key slots; for passphrase slots the
//!                  36-byte block { argon2_version u32 = 0x13, salt 16,
//!                  memory_kib u32, iterations u32, parallelism u32,
//!                  output_len u32 = 32 }, carrying the caller's parameters
//!   wrap_alg       u8    = 1 (XChaCha20-Poly1305)
//!   wrap_nonce     24 bytes
//!   wrapped_dek    32 bytes || tag(16)
//! ```
//!
//! `header_len` must be exactly the fixed header plus the serialized slots, and
//! `payload_len` is the length of the plaintext, so a file is accepted only if
//! it is exactly `header_len + payload_len + 16` bytes long. That rejects both
//! truncation and trailing bytes.
//!
//! The payload is encrypted with the whole header as associated data, so any
//! change to the header stops the payload from authenticating: a slot that was
//! swapped, removed or copied in from another file, or an older copy of the
//! header. Each slot's wrap authenticates that slot's own bytes, `slot_id`
//! through `wrap_nonce`, together with the magic, `version`, `payload_alg`,
//! `payload_len` and `file_id`. `file_id` is drawn at random when the file is
//! sealed and never changes, which stops a slot from being moved into another
//! file. The payload nonce is left out of the wraps on purpose, so a rotation
//! can re-encrypt the payload under a fresh nonce without breaking the other
//! slots.
//!
//! No nonce is ever reused. Every encryption draws a fresh one, and a rotation
//! draws a new wrap nonce, a new salt for a passphrase slot, and a new payload
//! nonce. No path, host name or other metadata goes into the associated data,
//! so the file can be moved or renamed freely.
//!
//! # Argon2id cost
//!
//! A passphrase slot uses RFC 9106 section 4's SECOND RECOMMENDED parameters by
//! default: 64 MiB, t=3, p=4. That is what [`Argon2idParams::defaults`] and
//! `Kdf::default()` give you. The FIRST RECOMMENDED set, 2 GiB, t=1, p=4, is
//! not offered as a preset, because 2 GiB per unlock is a decision for the
//! deployment; pass those numbers to [`Argon2idParams::new`] if you want it.
//!
//! The parameters are stored in the slot, so on unlock they come from a file
//! that may be hostile. [`KdfLimits`] is the range a reader accepts, and a slot
//! outside it is refused before any derivation starts. Only the selected slot is
//! checked and derived; the others are parsed and left alone.
//! [`KdfLimits::defaults`] accepts exactly the default parameters. If you seal
//! with others, give [`EnvelopeUnlocker::kdf_limits`] and
//! [`rewrap_slot_with_limits`] a range that includes them, built with
//! [`KdfLimits::between`].

#![deny(
    clippy::big_endian_bytes,
    reason = "the envelope format stores every integer little-endian; a big-endian conversion is a format bug"
)]

// The crate compiles twice - as a library, and as its own test target, whose
// root is binary-like so a `pub` item no test consumes looks dead. The test
// target now exercises the whole surface, so the `dead_code_pub_in_binary`
// expectation this crate used to carry is retired, exactly as its reason said
// it would be; the lint stays denied for the library build, where every item is
// reachable from outside the crate.

mod credential;
mod envelope;
mod format;
mod kdf;
mod seal;
mod unlocker;

#[expect(
    clippy::pub_use,
    clippy::useless_attribute,
    reason = "SOW §4.6: the vault's surface is flat at the crate root and every implementation module is private, so this is the one place a re-export is the API rather than a convenience; clippy's `useless_attribute` reads any lint attribute on a `use` item as useless, and this is the only place `pub_use` can be scoped"
)]
pub use {
    credential::{
        Recipient, SlotCredential, SlotSelector, raw_key_from_bytes, strip_one_line_ending,
    },
    envelope::{KeytabEnvelope, Selection},
    format::{EnvelopeError, Malformed, SlotInfo, SlotType},
    kdf::{Argon2Kdf, Argon2idParams, Kdf, KdfBackend, KdfLimits},
    seal::{rewrap_slot, rewrap_slot_with_limits, seal},
    unlocker::EnvelopeUnlocker,
};

/// The production half of one source file, for the crate's source guards.
///
/// A guard about production code has to *see* production code, and
/// `#[cfg(test)]` does not mark a file: this crate's test modules sit at the end
/// of each file, but a module may also carry `#[cfg(test)]`-gated accessors in
/// the middle of its production half. A split at the first `#[cfg(test)]` would
/// therefore stop the scan before the builder such a guard is about, so this
/// walks the `#[cfg(test)]`-gated *modules* and skips exactly those.
///
/// A `#[cfg(test)]` item that is not a module is kept - it is a production item
/// its own module uses, and nothing after it becomes test code because of it.
/// A module body is taken to end at the first line that is exactly `}`: the
/// crate formats inline modules that way, and a guard that misreads a file then
/// fails its own "must have scanned" assertion rather than passing quietly.
///
/// The guards live in the modules they are about (each module) and
/// a restricted visibility is denied at module scope by this workspace's lint
/// table, so the shared half lives here, where a private item is visible to
/// every descendant module.
#[cfg(test)]
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut kept = Vec::new();
    let mut lines = source.lines().enumerate().peekable();
    while let Some((index, line)) = lines.next() {
        let text = line.trim();
        if !text.starts_with("#[cfg(test)]") && !text.starts_with("#[cfg(all(test") {
            kept.push((index.saturating_add(1), line));
            continue;
        }
        let attribute_line = index.saturating_add(1);
        // Skip the item's leading block: attributes (including the multi-line
        // bodies this crate's `#[expect(...)]` forms have), the `//`-comments
        // between them, and their closing line.
        let mut in_attribute = false;
        while let Some((_line_index, candidate)) = lines.peek() {
            let attribute_text = candidate.trim();
            if attribute_text.starts_with("#[") {
                in_attribute = !attribute_text.contains(')');
                if lines.next().is_none() {
                    break;
                }
                continue;
            }
            if in_attribute {
                in_attribute = attribute_text != ")]";
                if lines.next().is_none() {
                    break;
                }
                continue;
            }
            if attribute_text.starts_with("//") {
                if lines.next().is_none() {
                    break;
                }
                continue;
            }
            break;
        }
        let is_module = lines.peek().is_some_and(|(_line_index, item)| {
            let candidate = item.trim();
            candidate.ends_with('{')
                && (candidate.starts_with("mod ") || candidate.contains(" mod "))
        });
        if !is_module {
            kept.push((attribute_line, line));
            continue;
        }
        for (_line_index, body_line) in lines.by_ref() {
            if body_line == "}" {
                break;
            }
        }
    }
    kept
}

/// The production half of one source file, as text.
///
/// What [`production_lines`] yields, rejoined: a guard that searches for a
/// signature rather than scanning line by line wants the text, and it wants it
/// to stop at the test modules. Splitting at the first `#[cfg(test)]` is the
/// shortcut that assumes no test-only item sits in the middle of a production
/// half, which the moved guards assume.
#[cfg(test)]
fn production_text(source: &str) -> String {
    production_lines(source)
        .into_iter()
        .map(|(_number, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod manifest_tests {
    use crate::test_support::TestResult;

    /// The crate ships under the workspace's lints, and its feature set is the
    /// one the plan allows: none.
    ///
    /// The manifest is read as text because that is what the property is about -
    /// a `[features]` table anywhere in it, or a lint opt-out that is not the
    /// workspace's, is the defect. A member that stops inheriting the lints
    /// silently stops being held to them, which is not a state a review would
    /// notice in a diff of compiled code.
    ///
    /// The scan is table- and comment-aware rather than a substring search: a
    /// comment naming `workspace = true`, a differently spaced `[ features ]`
    /// header, or `[features]` buried in a longer table name must not be able to
    /// satisfy the first assertion or evade the second.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/lib.rs::crate_is_a_member_with_the_workspace_lints keeps the uniform test signature while it only asserts"
    )]
    fn crate_is_a_member_with_the_workspace_lints() -> TestResult {
        let manifest = include_str!("../Cargo.toml");
        // The manifest has no `#` inside a string, so cutting each line at its
        // first `#` removes exactly the TOML comments.
        let lines: Vec<&str> = manifest
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default().trim())
            .collect();

        let mut in_lints = false;
        let mut lints_inherited = false;
        let mut features_table = false;
        for line in &lines {
            let header = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'));
            if let Some(name) = header {
                let normalized: String = name
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                features_table |= normalized.split('.').any(|segment| segment == "features");
                in_lints = normalized == "lints";
                continue;
            }
            if in_lints && *line == "workspace = true" {
                lints_inherited = true;
            }
        }

        assert!(
            lints_inherited,
            "the crate must opt into the workspace lints inside its `[lints]` table"
        );
        assert!(
            !features_table,
            "the vault crate has no features: it is the crypto"
        );
        Ok(())
    }
}

/// Guards for the source-scan helpers themselves: every other guard in this
/// crate stands on `production_lines`, so its heuristic is pinned here rather
/// than trusted.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod production_text_tests {
    use crate::test_support::TestResult;

    /// `production_text` keeps items before a `#[cfg(test)]` module, drops that
    /// module whole - including the bodies of modules nested inside it - and
    /// resumes at the next production item.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/lib.rs::production_text_skips_exactly_the_test_modules keeps the uniform test signature while it only asserts"
    )]
    fn production_text_skips_exactly_the_test_modules() -> TestResult {
        let source = concat!(
            "fn kept() {}\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn helper() {}\n",
            "    mod inner {\n",
            "        fn deep() {}\n",
            "    }\n",
            "}\n",
            "fn also_kept() {}\n",
        );
        let production = crate::production_text(source);
        assert!(
            production.contains("fn kept()"),
            "production items before a test module are kept"
        );
        assert!(
            !production.contains("fn helper()"),
            "a test module's body is not production code"
        );
        assert!(
            !production.contains("fn deep()"),
            "including modules nested inside it"
        );
        assert!(
            production.contains("fn also_kept()"),
            "and the scan resumes after the module closes"
        );
        Ok(())
    }

    /// A `#[cfg(test)]` item that is not a module is a production item its own
    /// module uses, so it stays.
    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/lib.rs::production_text_keeps_non_module_test_items keeps the uniform test signature while it only asserts"
    )]
    fn production_text_keeps_non_module_test_items() -> TestResult {
        let source = concat!(
            "fn kept() {}\n",
            "#[cfg(test)]\n",
            "fn helper() {}\n",
            "fn also_kept() {}\n",
        );
        let production = crate::production_text(source);
        assert!(
            production.contains("fn helper()"),
            "a `#[cfg(test)]` fn is a production item and stays"
        );
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
mod test_support {
    use core::error::Error;
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    use std::fs::File;
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    use std::os::unix::fs::FileExt as _;

    use zeroize::Zeroizing;

    use crate::{
        credential::{Recipient, SlotCredential, SlotSelector},
        envelope::KeytabEnvelope,
        format::{EnvelopeError, KDF_BLOCK_LEN, KEK_LEN},
        kdf::{Argon2Kdf, Kdf, KdfBackend, KdfLimits},
        seal::seal,
    };

    /// What every unit test returns: a failure is an `Err` the harness reports, so a
    /// test propagates with `?` instead of panicking (core guideline: tests return
    /// `Result`).
    pub(crate) type TestResult = Result<(), Box<dyn Error>>;

    /// Reads what a freed heap block still holds, through this process's own
    /// `/proc/self/mem`: reading freed memory directly would take `unsafe`,
    /// which the crate forbids.
    ///
    /// The file is opened and the read buffer allocated by
    /// [`FreedMemory::new`], before the block under test is freed: an
    /// allocation made after the free could be handed that very block and
    /// overwrite what the test is looking for.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) struct FreedMemory {
        /// `/proc/self/mem`.
        file: File,
        /// Where each read lands; its length is how many bytes a read covers.
        buffer: Vec<u8>,
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    impl FreedMemory {
        /// Opens `/proc/self/mem` and sizes the buffer for reads of `len` bytes.
        #[expect(
            clippy::panic,
            reason = "a test that cannot read its own memory must fail, not pass"
        )]
        pub(crate) fn new(len: usize) -> Self {
            let file = File::open("/proc/self/mem")
                .unwrap_or_else(|error| panic!("cannot open /proc/self/mem: {error}"));
            Self {
                file,
                buffer: vec![0; len],
            }
        }

        /// How many of the bytes at `address` still hold `marker`.
        #[expect(
            clippy::panic,
            reason = "a test that cannot read its own memory must fail, not pass"
        )]
        pub(crate) fn residue(&mut self, address: usize, marker: u8) -> usize {
            let offset = u64::try_from(address)
                .unwrap_or_else(|error| panic!("an address must fit a file offset: {error}"));
            self.file
                .read_exact_at(&mut self.buffer, offset)
                .unwrap_or_else(|error| {
                    panic!("cannot read /proc/self/mem at {address:#x}: {error}")
                });
            self.buffer
                .iter()
                .copied()
                .filter(|byte| *byte == marker)
                .count()
        }
    }

    /// The raw key the raw-key tests seal with.
    pub(crate) const RAW_KEY: [u8; KEK_LEN] = [0x11; KEK_LEN];

    /// A key that is not the sealing key.
    pub(crate) const OTHER_KEY: [u8; KEK_LEN] = [0x22; KEK_LEN];

    /// The passphrase the passphrase tests seal with.
    pub(crate) const PASSPHRASE: &[u8] = b"correct horse battery staple";

    /// A plaintext standing in for a keytab.
    pub(crate) const PLAINTEXT: &[u8] = b"a keytab stands here";

    /// Fill `LEN` bytes deterministically from `seed` and `base`, so a sealed
    /// file is reproducible for the golden vector.
    pub(crate) fn fill<const LEN: usize>(seed: u8, base: u8) -> [u8; LEN] {
        let mut bytes = [0; LEN];
        for (index, cell) in bytes.iter_mut().enumerate() {
            let offset = u8::try_from(index).unwrap_or(u8::MAX);
            *cell = seed.wrapping_add(base).wrapping_add(offset);
        }
        bytes
    }

    /// A raw-key recipient sealed with `key`.
    pub(crate) fn raw_recipient_with<'key>(
        id: u32,
        label: &'key str,
        key: &'key [u8; KEK_LEN],
    ) -> Recipient<'key> {
        Recipient {
            id,
            label,
            credential: SlotCredential::RawKey(key),
        }
    }

    /// A raw-key recipient sealed with the shared fixture key.
    pub(crate) fn raw_recipient(id: u32, label: &str) -> Recipient<'_> {
        raw_recipient_with(id, label, &RAW_KEY)
    }

    /// A passphrase recipient.
    pub(crate) fn passphrase_recipient(id: u32, label: &str) -> Recipient<'_> {
        Recipient {
            id,
            label,
            credential: SlotCredential::Passphrase(PASSPHRASE),
        }
    }

    /// A backend that fails loudly: reaching a derivation on a raw-key path is
    /// exactly the failure the pod's memory guarantee rests on, and a
    /// derivation on a block outside the caller's band is the failure SOW B6c
    /// names.
    pub(crate) struct PanickingKdf;

    impl KdfBackend for PanickingKdf {
        #[expect(
            clippy::panic,
            reason = "reaching the backend on a path that must not derive is the failure under test"
        )]
        #[expect(
            clippy::panic_in_result_fn,
            reason = "failing loudly is the assertion this backend exists to make"
        )]
        fn derive_argon2id(
            &self,
            _passphrase: &[u8],
            _block: &[u8; KDF_BLOCK_LEN],
            _limits: &KdfLimits,
        ) -> Result<Zeroizing<[u8; KEK_LEN]>, EnvelopeError> {
            panic!("the KDF backend was reached on a path that must never derive");
        }
    }

    /// Seal, parse, select with `credential`, and unlock.
    #[expect(
        clippy::panic,
        reason = "an envelope operation failing means the format is broken"
    )]
    pub(crate) fn roundtrip(
        recipients: &[Recipient<'_>],
        credential: &SlotCredential<'_>,
    ) -> Vec<u8> {
        let blob = seal(PLAINTEXT, recipients, &Kdf::default())
            .unwrap_or_else(|error| panic!("seal failed: {error}"));
        let envelope =
            KeytabEnvelope::parse(&blob).unwrap_or_else(|error| panic!("parse failed: {error}"));
        let selected = envelope
            .select_slot(SlotSelector::Index(0), &KdfLimits::defaults(), credential)
            .unwrap_or_else(|error| panic!("select failed: {error}"));
        let plaintext = selected
            .unlock(credential, &Argon2Kdf)
            .unwrap_or_else(|error| panic!("unlock failed: {error}"));
        plaintext.to_vec()
    }

    /// Lower-case hex of a buffer, for the golden comparison.
    pub(crate) fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            use core::fmt::Write as _;
            let _written = text.write_fmt(format_args!("{byte:02x}"));
        }
        text
    }
}
