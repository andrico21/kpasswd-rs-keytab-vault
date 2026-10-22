# Release the label-rule tightening as 0.2.0, with an accurate changelog and a recovery path for 0.1.0 envelopes

- Class: compatibility / release. There is no code defect here; the risk is shipping
  a wire-format tightening as if it were compatible.
- Status: applied in `69ee24a`; the owner chose A, the 0.2.0 release (see Decision).

## Problem

0.1.0 is published: tag `0.1.0`, and the crate is in the
crates.io index. The worktree tightens what counts as a valid envelope:
`parse_slot` now refuses a label that contains a control or bidi character, and so
will U+2028/U+2029 if
[low-label-line-separators.md](low-label-line-separators.md) lands. 0.1.0's `seal`
and `rewrap_slot` accepted any UTF-8 label of up to 64 bytes. So an envelope that
0.1.0 wrote and read can stop parsing - and therefore stop unlocking - after an
upgrade.

Measured with envelopes sealed by `0a88441` and read by the worktree:

| Label | Parse | Unlock |
| --- | --- | --- |
| `op\u{1b}[31m` | `Malformed(SlotLabel)` | `Malformed(SlotLabel)` |
| `op\u{202e}x` | `Malformed(SlotLabel)` | `Malformed(SlotLabel)` |
| `operator` | Ok | Ok |

`seal` also returns `Err` for some inputs it accepted in 0.1.0:

- labels with those characters - envelopes 0.1.0 itself could still parse;
- duplicate slot tokens and plaintexts over 1 MiB - here 0.1.0's output was
  unparseable anyway, so that part is a pure fix.

Why a patch release is the wrong vehicle:

- Under Cargo's semver rules, 0.1.x to 0.1.y counts as compatible. A consumer that
  declares `kpasswd-rs-keytab-vault = "0.1.0"` - `krb-reset-pw` does today
  (`krb-reset-pw/Cargo.toml:33`) - would pick up a 0.1.1 on `cargo update` and start
  refusing such envelopes, with no change on its side.
- The operator would then see
  `failed to parse the keytab envelope: an envelope slot label is too long, not UTF-8, or carries a character that cannot be rendered`
  (`krb-reset-pw/src/main.rs:726`).
- The crate's own policy (README: "It is pre-1.0, so a minor release may break the
  API") puts breaking changes in a minor release.

The `[Unreleased]` changelog is also inaccurate:

- `CHANGELOG.md:13` says the labels "also refuse the Unicode bidirectional
  controls ...; control characters were already refused". In 0.1.0 control
  characters were not refused - that is what the Fixed entry on line 21 describes.
- Nothing says that existing envelopes can stop opening, or how to recover them.

## Decision for the owner

- **A (recommended): accept the break and release as 0.2.0.** Add a changelog entry
  with the recovery recipe below, and keep the format `version` at 1. It is a
  security fix, the label rule is part of the documented wire format (`src/lib.rs:52`),
  and labels are operator-chosen display names, so few if any real envelopes are
  affected.
- **B: stay on 0.1.x** by parsing legacy labels and escaping them only when rendered.
  `KeytabEnvelope::slots()` returns the raw label to callers, so this would leave the
  wire rule unenforced and need a new escaping API. Not recommended.
- **C: bump `FORMAT_VERSION` to 2.** That refuses every 0.1.0 envelope, not only the
  rare bad-label ones, and contradicts the single-version design (README "The format";
  `src/format.rs:17-22`). Not recommended.

## Proposed change (option A)

### 1. Rewrite `[Unreleased]` in `CHANGELOG.md` now

Fold the label entries into one accurate breaking entry, with recovery steps. The
other entries are kept word for word, one line per bullet as the file is written
now. Keep a Changelog has no "Breaking" section, so the entry goes under Changed
with a bold lead.

```markdown
## [Unreleased]

### Added

- `rewrap_slot_with_limits`: rotation with a caller-supplied `KdfLimits` band, so an envelope sealed with non-default Argon2id parameters can be rotated (`rewrap_slot` remains that call at `KdfLimits::defaults()`).

### Changed

- **Breaking for some existing envelopes:** a slot label may no longer carry a control character (C0, DEL, C1), a line or paragraph separator (U+2028, U+2029) or a Unicode bidirectional control (U+061C, U+200E, U+200F, U+202A..=U+202E, U+2066..=U+2069). `KeytabEnvelope::parse` refuses such an envelope with `Malformed::SlotLabel`, so it no longer unlocks, and `seal` and `rewrap_slot` refuse to write one. 0.1.0 accepted any UTF-8 label of up to 64 bytes. Envelopes whose labels avoid these characters are unaffected, and the wire format is otherwise unchanged (`version` stays 1). To recover an affected envelope, use 0.1.x: relabel the slot in place with `rewrap_slot` and a replacement label of the same byte length, or unlock it and `seal` it again. Zero-width joiners and the other formatting characters stay legal, so real scripts and emoji sequences keep working.
- `SlotCredential`'s `Debug` no longer names a passphrase's byte length. A raw key's length is its type, so that one is still named; no bytes are ever printed.

### Fixed

- Slot labels can no longer forge or reorder the operator-facing slot diagnostics (`slot_summaries`, `slots`); 0.1.0 rendered the characters listed under Changed verbatim.
- `seal` and `rewrap_slot` apply the reader's slot-token rules (unique slot ids and labels, no label spelled like any slot's decimal id), so a writer can no longer return `Ok` over bytes `KeytabEnvelope::parse` refuses.
- `seal` refuses a plaintext longer than the reader's payload cap (`MAX_PAYLOAD_LEN`), so it can no longer return `Ok` over a file `parse` refuses for its declared length.
- `raw_key_from_bytes` accepts exactly ASCII hex in its hex branch: a leading `+` (which `u8::from_str_radix` alone takes) is refused, so the accepted set is the documented one.
- `EnvelopeUnlocker::new` moves the buffer into a `Zeroizing` buffer before the magic test, so the plaintext keytab it refuses is wiped on the way out.
```

If the line-separator plan is not adopted, drop "a line or paragraph separator
(U+2028, U+2029)" from the Changed entry.

### 2. Release commit (release procedure step 4, `kpasswd-rs/docs/release-procedure.md:24`)

All of these go in one commit:

- `Cargo.toml:3`: `version = "0.2.0"`.
- `CHANGELOG.md`: rename `[Unreleased]` to `[0.2.0] - <date>`, and open a new empty
  `[Unreleased]` above it (`- Nothing yet.`).
- Lift `publish = false`, as step 4 requires.
- Update both lockfiles. The CI and fuzz checks run with `--locked`, and fail
  (exit 101) after the bump until these are updated:

  ```sh
  cargo update -p kpasswd-rs-keytab-vault --offline
  cargo update --manifest-path fuzz/Cargo.toml -p kpasswd-rs-keytab-vault --offline   # once fuzz/Cargo.lock is tracked
  ```

  Each command changes exactly one line: `Cargo.lock:761` and
  `fuzz/Cargo.lock:779` (`version = "0.1.0"` to `"0.2.0"`).

Then steps 5-8 as usual. At step 5, `cargo package --list` must not list
`docs/fix-plans/` (see the [README](README.md) note on packaging).

### 3. Downstream (separate repository, after publishing)

`krb-reset-pw`: bump to `kpasswd-rs-keytab-vault = "0.2.0"` deliberately. Nothing
else changes: it only selects slots, unlocks, and prints `slot_summaries()`. It has
no `seal` or `rewrap_slot` call.

## Recovery recipe for an affected envelope

This applies to an envelope whose label is now refused. Use 0.1.x for every step,
because 0.2.0 cannot open the envelope.

1. **Find the slot.** `KeytabEnvelope::parse(&bytes)?.slots()`, then check each
   `label` against the rule in the changelog entry.
2. **Relabel without the plaintext.** Call `rewrap_slot` on the envelope with the
   slot's current credential, `SlotSelector::Index(i)`, and
   `Recipient::new(id, "<clean label of the same byte length>", <credential>)`.
   0.1.0's rotation checks only the credential kind and the label byte length, so it
   relabels in place. The revalidation probe exercised that same gate: a same-length
   relabel of a 0.1.0 envelope returned `Ok`.
3. **Or, with the plaintext:** unlock it, then `seal` it again with clean labels.

## Verification

- Before the release commit: `cargo test` passes, including
  `envelope::tests::golden_raw_key_vector_matches` and
  `golden_passphrase_vector_matches` (`src/envelope.rs:986`, `:1009`). Those pin the
  unchanged on-disk bytes for clean labels.
- Envelopes sealed by `0a88441` with clean labels parse and unlock with the worktree
  (revalidation probe: `X wt_reads_head_file normal_label parse=Ok unlock=Ok(true)`).
- After the bump, both `--locked` checks are consistent again:

  ```sh
  cargo metadata --locked --offline --format-version 1 >/dev/null
  cargo metadata --locked --offline --format-version 1 --manifest-path fuzz/Cargo.toml >/dev/null
  ```

  This was checked on a scratch copy of the worktree, bumped to 0.2.0, with the two
  `cargo update` commands above.

## Risks / open questions

- How many 0.1.0 envelopes are affected is unknown. Envelopes come from whatever
  tooling the operator uses with the vault API; `krb-reset-pw` does not seal. A
  deliberate control or bidi character in a label is unlikely, and the recipe above
  is cheap.
- The 0.1.x line stays as it is. No 0.1.1 is planned; publishing one with these
  fixes would bring back the silent-upgrade problem.
