# Slot labels: refuse U+2028 and U+2029 as well

- Class: low - a residual of the confirmed run-1 finding
  `src/format.rs/Slot::describe:unfiltered-slot-label-in-operator-diagnostic-line`
  (file-controlled labels rendered verbatim into operator-facing slot diagnostics).
- Status: applied in `69ee24a`. The change was prototyped on a throwaway copy of the
  worktree: `cargo fmt --check`, `cargo clippy --all-targets -D warnings` for the
  Linux and Windows targets, the full suite, and a mutation check.

## Problem

The worktree's label rule refuses C0/C1 controls and the Unicode bidirectional
controls, both when reading (`parse_slot`) and when writing (`seal`, and the
`rewrap_slot` gate). LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR (U+2029) are
neither: `char::is_control()` is false for both (they are general categories Zl and
Zp), and neither is in the bidi list.

So the label `operator\u{2028}8: forged-pod (passphrase)`:

- still seals, parses and unlocks;
- comes back verbatim from `KeytabEnvelope::slot_summaries()` and `slots()`.

A renderer that breaks lines on these characters then shows a forged second summary
line - the effect the finding was about. That includes browsers and most GUI/web log
viewers, and text that passes through JSON or JavaScript. Terminals do not break on
them.

Revalidation probe, identical on `0a88441` and on the worktree:

```text
F4 L5_line_separator_u2028 seal=Ok parse=Ok slots=1
   summaries=["7: operator\u{2028}8: forged-pod (passphrase) (raw key)"] u2028_or_u2029=true
F4 char_class u2028.is_control=false u2029.is_control=false u0085.is_control=true
```

## Root cause

`src/format.rs:133-143`, `is_unrenderable_in_a_label`:

```rust
character.is_control()
    || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}'
                           | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
```

Its doc comment (`src/format.rs:122-131`) states the intent - "C0/C1 controls can
forge a line". But the set of characters that force a line break is wider than
category Cc. Unicode's mandatory breaks (UAX #14 classes BK, CR, LF, NL) are
U+000A-U+000D and U+0085, all in Cc, plus U+2028 and U+2029, the only members of Zl
and Zp.

## Proposed fix

The reader and both writers already share this one predicate:

- `parse_slot` (`src/format.rs:518`)
- `slot_prefix` (`src/seal.rs:473`)
- `replacement_label_conflicts` (`src/seal.rs:546`)

So adding two match arms covers all three paths:

```diff
--- a/src/format.rs
+++ b/src/format.rs
@@ -137,6 +137,8 @@
             '\u{061c}'
                 | '\u{200e}'
                 | '\u{200f}'
+                | '\u{2028}'
+                | '\u{2029}'
                 | '\u{202a}'..='\u{202e}'
                 | '\u{2066}'..='\u{2069}'
         )
```

Doc updates in the same commit:

- `is_unrenderable_in_a_label` (`src/format.rs:125`): "C0/C1 controls and the line
  and paragraph separators (U+2028, U+2029) can forge a line; the Unicode
  bidirectional controls (...) can reorder one, ...".
- `Malformed::SlotLabel` (`src/format.rs:191-192`): "... or carries a character that
  cannot be rendered (a control, a line or paragraph separator, or a bidirectional
  control)."
- Crate docs, format table (`src/lib.rs:52`):
  `slot_label     UTF-8, no control, line-separator or bidi characters, exactly slot_label_len bytes`.
- `CHANGELOG.md`: the entry is part of the release plan's rewrite of `[Unreleased]`
  ([release-0.2.0-label-rule-compatibility.md](release-0.2.0-label-rule-compatibility.md)).

## Regression tests

Extend the three existing label tests. Each new case has the byte length of the
fixture label it replaces, so only the character can be the reason for the refusal.

```diff
--- a/src/format.rs   (format::tests::unrenderable_label_rejected)
+++ b/src/format.rs
@@ -978,6 +980,8 @@
             [0xe2, 0x80, 0x8e],
             [0xe2, 0x80, 0xae],
             [0xe2, 0x81, 0xa6],
+            [0xe2, 0x80, 0xa8],
+            [0xe2, 0x80, 0xa9],
         ] {
             let mut mutated = blob.clone();
             overwrite_bytes(&mut mutated, label, &bytes);
--- a/src/seal.rs   (seal::tests::seal_refuses_an_unrenderable_label)
+++ b/src/seal.rs
@@ -1155,7 +1155,13 @@
     fn seal_refuses_an_unrenderable_label() {
-        for label in ["a\u{1b}b", "a\u{202e}b", "a\u{61c}b"] {
+        for label in [
+            "a\u{1b}b",
+            "a\u{202e}b",
+            "a\u{61c}b",
+            "a\u{2028}b",
+            "a\u{2029}b",
+        ] {
--- a/src/seal.rs   (seal::tests::rotation_refuses_an_unrenderable_replacement_label)
+++ b/src/seal.rs
@@ -1351,7 +1357,7 @@
     fn rotation_refuses_an_unrenderable_replacement_label() {
-        for (label, replacement) in [("x", "\u{1b}"), ("abc", "\u{202e}")] {
+        for (label, replacement) in [("x", "\u{1b}"), ("abc", "\u{202e}"), ("abc", "\u{2028}")] {
```

Also update the case-list comment in `unrenderable_label_rejected`: "LF, DEL, a C1
control, the line and paragraph separators, and the three bidirectional controls
with distinct roles".

`seal::tests::seal_accepts_format_characters_that_cannot_forge_a_line`
(`src/seal.rs:1173`) is unchanged and still passes: zero-width joiners and spaces
stay legal.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --lib -- unrenderable_label_rejected seal_refuses_an_unrenderable_label \
    rotation_refuses_an_unrenderable_replacement_label seal_accepts_format_characters_that_cannot_forge_a_line
```

Prototype result:

- The full suite passes: 94 lib tests and 3 integration tests.
- Mutation check: deleting the two new match arms fails
  `unrenderable_label_rejected`, `seal_refuses_an_unrenderable_label` and
  `rotation_refuses_an_unrenderable_replacement_label`.

## Compatibility

This tightens the wire format. An envelope whose label contains U+2028 or U+2029 is
valid for 0.1.0 and for the current worktree, and will stop parsing - and so stop
unlocking - after this change.

Ship it in the same release as the control/bidi tightening, so users take one break,
not two. That release's changelog entry, recovery recipe and version bump are in
[release-0.2.0-label-rule-compatibility.md](release-0.2.0-label-rule-compatibility.md).
A label that deliberately contains U+2028 is implausible.

## Risks / open questions

- **Should other invisible-but-harmless characters be refused too?** For example
  U+200B, U+FEFF, or the tag characters U+E0000-U+E007F. This plan does not propose
  it: they cannot forge or reorder a line, and the crate deliberately keeps
  formatting characters legal (`seal_accepts_format_characters_that_cannot_forge_a_line`
  pins that). It is a product decision for the owner.
