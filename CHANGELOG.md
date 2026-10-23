# Changelog

All notable changes to this crate are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- Nothing yet.

## [0.2.2] - 2026-10-23

### Changed

- Internal only: the repository now holds itself to the strictest union of its own lint gates and `rmcp-server-kit`'s. Rustfmt's import layout is checked on a dated nightly, rustdoc is built the way docs.rs builds it, and new gates keep the lint profile equal to the guideline it cites, refuse `allow` attributes, require catalogued `expect` reasons, and require every test to be documented and to return `Result`. The source changes are import layout, test code and lint-reason wording; the API, the behavior and the envelope format are unchanged.

## [0.2.1] - 2026-10-23

### Changed

- Dependency refresh: the lockfile moves `ctutils`, which `digest` pulls in, from 0.4.3 to 0.4.5. The manifest's dependency requirements are unchanged, and so are the API and the envelope format.
- The 0.2.0 entry's recovery route for envelopes whose labels 0.2.0 refuses no longer assumes cargo can resolve 0.1.0: it is yanked, so the entry now gives the `.crate` download URL and its SHA-256, to unpack and depend on by `path`.

## [0.2.0] - 2026-10-23

### Added

- `rewrap_slot_with_limits`: rotation with a caller-supplied `KdfLimits` band, so an envelope sealed with non-default Argon2id parameters can be rotated (`rewrap_slot` remains that call at `KdfLimits::defaults()`).

### Changed

- **Breaking for some existing envelopes:** a slot label may no longer carry a control character (C0, DEL, C1), a line or paragraph separator (U+2028, U+2029) or a Unicode bidirectional control (U+061C, U+200E, U+200F, U+202A..=U+202E, U+2066..=U+2069). `KeytabEnvelope::parse` refuses such an envelope with `Malformed::SlotLabel`, so it no longer unlocks, and `seal` and `rewrap_slot` refuse to write one. 0.1.0 accepted any UTF-8 label of up to 64 bytes. Envelopes whose labels avoid these characters are unaffected, and the wire format is otherwise unchanged (`version` stays 1). To recover an affected envelope, use 0.1.0. It is yanked, so cargo no longer resolves it from the registry: download `https://static.crates.io/crates/kpasswd-rs-keytab-vault/kpasswd-rs-keytab-vault-0.1.0.crate`, check that its SHA-256 is `33eca9c890719e43e8eb87170e3dcdd20537e61f25d1cc00c5059950382cc6d4`, unpack it and depend on it by `path`. Then relabel the slot in place with `rewrap_slot` and a replacement label of the same byte length, or unlock it and `seal` it again. Zero-width joiners and the other formatting characters stay legal, so real scripts and emoji sequences keep working.
- `SlotCredential`'s `Debug` no longer names a passphrase's byte length. A raw key's length is its type, so that one is still named; no bytes are ever printed.

### Fixed

- Slot labels can no longer forge or reorder the operator-facing slot diagnostics (`slot_summaries`, `slots`); 0.1.0 rendered the characters listed under Changed verbatim.
- `seal` and `rewrap_slot` apply the reader's slot-token rules (unique slot ids and labels, no label spelled like any slot's decimal id), so a writer can no longer return `Ok` over bytes `KeytabEnvelope::parse` refuses.
- `seal` refuses a plaintext longer than the reader's payload cap (`MAX_PAYLOAD_LEN`), so it can no longer return `Ok` over a file `parse` refuses for its declared length.
- `raw_key_from_bytes` accepts exactly ASCII hex in its hex branch: a leading `+` (which `u8::from_str_radix` alone takes) is refused, so the accepted set is the documented one.
- `EnvelopeUnlocker::new` moves the buffer into a `Zeroizing` buffer before the magic test, so the plaintext keytab it refuses is wiped on the way out.

## [0.1.0] - 2026-10-06

First release: the encrypted keytab format (`seal`, `rewrap_slot`, `KeytabEnvelope`) and `EnvelopeUnlocker`, which opens it for `kpasswd-rs`.
