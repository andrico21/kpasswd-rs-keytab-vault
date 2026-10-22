# Zeroization guards: test the wipe behaviourally, and remove the key copy the textual guard was protecting

- Class: test quality. These are the regression guards for one confirmed run-1
  finding (`EnvelopeUnlocker.new-refused-non-envelope-buffer-dropped-unzeroized`)
  and one hardening note (`cipher_from_key` leaves a stack copy of the key).
- Status: applied in `69ee24a`. Prototyped on a throwaway copy of the worktree with
  `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (Linux and the
  Windows MSVC target), `cargo doc -D warnings`, the full suite, 40 repeated parallel
  runs, and a mutation check.

## Problem

Both wipe fixes are pinned by tests that search the source text, not memory:

- `unlocker::tests::the_admission_gate_wipes_the_buffer_it_refuses`
  (`src/unlocker.rs:386-408`) checks that `Zeroizing::new(bytes)` appears before
  `is_envelope(` in the body of `EnvelopeUnlocker::new`.
- `envelope::tests::cipher_from_key_wipes_its_transient_key`
  (`src/envelope.rs:590-610`) checks that the body of `cipher_from_key` contains
  `zeroize()`.

The review's mutation check found what they miss:

- An extra `let unwiped = bytes.clone();` before the wrap leaves a complete unwiped
  copy of a refused plaintext keytab in freed memory, and the unlocker test still
  passes.
- `parsed.as_mut_slice()[..0].zeroize()` wipes nothing, and the cipher test still
  passes.

## Root cause

- **No memory is observed.** The crate forbids `unsafe` in every target
  (`Cargo.toml:58`, `unsafe_code = "forbid"`). So the audit probe's instrument, a
  counting `#[global_allocator]`, cannot live in the crate's own tests.
- **`cipher_from_key` copies the key onto the stack.**
  `chacha20poly1305::Key::try_from(key.as_slice())` (`src/envelope.rs:521`) makes the
  copy, then wipes it. A stack wipe cannot be observed after the function returns,
  so only a textual guard can watch it.

## Proposed fix

Three parts, in one commit.

### 1. Remove the copy instead of wiping it (`src/envelope.rs`)

hybrid-array 0.4.15 converts `&'a [T; N]` to `&'a Array<T, U>` by reference
(`From` impl at hybrid-array `src/lib.rs:767`, via `cast_from_core`). So the cipher
can be built straight from the caller's array:
`<XChaCha20Poly1305 as KeyInit>::new(key.into())`. At every call site that array is
already held in a `Zeroizing`.

The function can no longer fail:

- it returns the cipher instead of a `Result`;
- the five call sites drop their `?` (`src/envelope.rs:353,457,489`,
  `src/seal.rs:215,407`);
- the now-unused `Zeroize as _` import goes.

The only remaining copy is inside the cipher, and its `Drop` wipes it under the
`zeroize` feature (chacha20poly1305 0.11.0 `src/lib.rs:296-304`). `Cargo.toml:20`
enables `features = ["alloc", "zeroize"]`.

```diff
@@ -14,7 +14,7 @@
 use chacha20poly1305::aead::{Aead, Payload};
 use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
-use zeroize::{Zeroize as _, Zeroizing};
+use zeroize::Zeroizing;
@@ -513,19 +513,12 @@
 /// Build an XChaCha20-Poly1305 cipher from 32 bytes of key material.
 ///
-/// # Errors
-///
-/// `EnvelopeError::Malformed(Malformed::SlotPairing)` if the fixed-size key material is not
-/// accepted by the cipher constructor.
-pub(crate) fn cipher_from_key(key: &[u8; KEK_LEN]) -> Result<XChaCha20Poly1305, EnvelopeError> {
-    let mut parsed = chacha20poly1305::Key::try_from(key.as_slice())
-        .map_err(|_length_error| EnvelopeError::Malformed(Malformed::SlotPairing))?;
-    let cipher = <XChaCha20Poly1305 as KeyInit>::new(&parsed);
-    // The constructor copies the key into the cipher, whose own state wipes on
-    // drop (the `zeroize` feature); this stack local would not, so its bytes are
-    // wiped here rather than left behind for whatever reuses the frame.
-    parsed.as_mut_slice().zeroize();
-    Ok(cipher)
+/// The caller's array is handed to the cipher by reference - `&[u8; 32]`
+/// converts to `&chacha20poly1305::Key` without a copy - so this function
+/// holds no copy of the key that could outlive it. The cipher keeps its own
+/// copy and wipes it on drop (`chacha20poly1305`'s `zeroize` feature).
+pub(crate) fn cipher_from_key(key: &[u8; KEK_LEN]) -> XChaCha20Poly1305 {
+    <XChaCha20Poly1305 as KeyInit>::new(key.into())
 }
```

In each of the five callers, `let cipher = cipher_from_key(..)?;` becomes
`let cipher = cipher_from_key(..);`.

### 2. A shared memory reader for tests (`src/lib.rs`, `mod test_support`)

`FreedMemory` reads what a freed heap block still holds, through the process's own
`/proc/self/mem`, using `FileExt::read_exact_at`. It needs no `unsafe`, and it
exists on Linux/glibc only.

```diff
@@ -357,6 +357,63 @@
     use crate::kdf::{Argon2Kdf, Kdf, KdfBackend, KdfLimits};
     use crate::seal::seal;
+    #[cfg(all(target_os = "linux", target_env = "gnu"))]
+    use std::fs::File;
+    #[cfg(all(target_os = "linux", target_env = "gnu"))]
+    use std::os::unix::fs::FileExt as _;
+
+    /// Reads what a freed heap block still holds, through this process's own
+    /// `/proc/self/mem`: reading freed memory directly would take `unsafe`,
+    /// which the crate forbids.
+    ///
+    /// The file is opened and the read buffer allocated by
+    /// [`FreedMemory::new`], before the block under test is freed: an
+    /// allocation made after the free could be handed that very block and
+    /// overwrite what the test is looking for.
+    #[cfg(all(target_os = "linux", target_env = "gnu"))]
+    pub(crate) struct FreedMemory {
+        /// `/proc/self/mem`.
+        file: File,
+        /// Where each read lands; its length is how many bytes a read covers.
+        buffer: Vec<u8>,
+    }
+
+    #[cfg(all(target_os = "linux", target_env = "gnu"))]
+    impl FreedMemory {
+        /// Opens `/proc/self/mem` and sizes the buffer for reads of `len` bytes.
+        #[expect(
+            clippy::panic,
+            reason = "a test that cannot read its own memory must fail, not pass"
+        )]
+        pub(crate) fn new(len: usize) -> Self {
+            let file = File::open("/proc/self/mem")
+                .unwrap_or_else(|error| panic!("cannot open /proc/self/mem: {error}"));
+            Self {
+                file,
+                buffer: vec![0; len],
+            }
+        }
+
+        /// How many of the bytes at `address` still hold `marker`.
+        #[expect(
+            clippy::panic,
+            reason = "a test that cannot read its own memory must fail, not pass"
+        )]
+        pub(crate) fn residue(&mut self, address: usize, marker: u8) -> usize {
+            let offset = u64::try_from(address)
+                .unwrap_or_else(|error| panic!("an address must fit a file offset: {error}"));
+            self.file
+                .read_exact_at(&mut self.buffer, offset)
+                .unwrap_or_else(|error| {
+                    panic!("cannot read /proc/self/mem at {address:#x}: {error}")
+                });
+            self.buffer
+                .iter()
+                .copied()
+                .filter(|byte| *byte == marker)
+                .count()
+        }
+    }
 
     /// The raw key the raw-key tests seal with.
```

The `.iter().copied().filter(..).count()` shape is deliberate. The plain
`.iter().filter(|b| **b == m).count()` trips `clippy::naive_bytecount`, a pedantic
lint, which this crate denies.

### 3. Tests

**`src/unlocker.rs`.** Add a no-copy assertion to the existing ordering guard, and a
behavioural test after it:

```diff
@@ -405,6 +405,67 @@
             matches!((wrap, test), (Some(wrap_offset), Some(test_offset)) if wrap_offset < test_offset),
             "`new` must move the buffer into `Zeroizing` before it tests the magic, so the refusal path wipes what it refuses"
         );
+        // Ordering alone would pass a `new` that copied the bytes and dropped
+        // the copy unwiped: `new` takes no copy at all.
+        for copy in [
+            ".clone()",
+            ".to_vec()",
+            ".to_owned()",
+            "copy_from_slice(",
+            "extend_from_slice(",
+        ] {
+            assert!(
+                !window.contains(copy),
+                "`new` must not copy the bytes it may refuse (found `{copy}`)"
+            );
+        }
+    }
+
+    /// The behavioural half of the guard above: the bytes `new` refuses are
+    /// wiped before their allocation is freed.
+    ///
+    /// `new` takes the buffer by value, so the test reads the freed block back
+    /// through `/proc/self/mem`. The first 32 bytes are skipped: the allocator
+    /// writes its free-list bookkeeping there.
+    #[cfg(all(target_os = "linux", target_env = "gnu"))]
+    #[test]
+    fn the_refused_buffer_is_wiped_before_it_is_freed() {
+        use crate::test_support::FreedMemory;
+
+        /// Bytes in the refused buffer: small enough for the allocator's
+        /// per-thread cache, so the freed block stays mapped and unmerged.
+        const LEN: usize = 256;
+        /// Leading bytes of a freed block the allocator may overwrite.
+        const HEADER: usize = 32;
+        /// Bytes after the header the test reads back.
+        const WATCHED: usize = 224;
+        /// A byte value a wipe never leaves behind.
+        const MARKER: u8 = 0xa5;
+
+        let mut memory = FreedMemory::new(WATCHED);
+        let refused = vec![MARKER; LEN];
+        let address = refused.as_ptr().addr().saturating_add(HEADER);
+        let outcome = EnvelopeUnlocker::new(refused, OPERATOR, SlotCredential::RawKey(&RAW_KEY));
+        let residue = memory.residue(address, MARKER);
+        assert!(
+            matches!(outcome, Err(EnvelopeError::Malformed(Malformed::Magic))),
+            "a marker buffer is not an envelope, so `new` must refuse it"
+        );
+        assert_eq!(
+            residue, 0,
+            "`new` must wipe the bytes it refuses before freeing them; {residue} of {WATCHED} survived"
+        );
+
+        // Instrument control: an unwiped block freed the same way is visible,
+        // so the zero above is a wipe rather than a blind spot.
+        let plain = vec![MARKER; LEN];
+        let control_address = plain.as_ptr().addr().saturating_add(HEADER);
+        drop(plain);
+        let control = memory.residue(control_address, MARKER);
+        assert_eq!(
+            control, WATCHED,
+            "the instrument must see an unwiped freed block; it saw {control} of {WATCHED} bytes"
+        );
     }
```

**`src/envelope.rs`.** Replace `cipher_from_key_wipes_its_transient_key` with a
no-copy guard and a behavioural test. The behavioural test pins the `zeroize`
feature: without it, the dropped cipher would leave its key behind.

```diff
@@ -588,14 +581,14 @@
-    /// The transient `Key` the cipher constructor takes must be wiped: the
-    /// cipher's own state wipes on drop, this stack local would not.
+    /// `cipher_from_key` holds no copy of the key: the caller's array goes into
+    /// the cipher by reference, so nothing is left behind for a wipe to miss.
     #[test]
     #[expect(
         clippy::panic,
         reason = "a missing function means the guard is about code that no longer exists"
     )]
-    fn cipher_from_key_wipes_its_transient_key() {
+    fn cipher_from_key_binds_no_copy_of_the_key() {
         let source = production_text(include_str!("envelope.rs"));
         let start = source
             .find("pub(crate) fn cipher_from_key(")
@@ -603,9 +596,59 @@
         let body = source.get(start..).unwrap_or_default();
         let end = body.find("\n}").unwrap_or(body.len());
         let window = body.get(..end).unwrap_or_default();
-        assert!(
-            window.contains("zeroize()"),
-            "the key local must be wiped before the cipher is returned"
+        for copy in ["let ", "Key::", ".clone()", "to_vec(", "copy_from_slice("] {
+            assert!(
+                !window.contains(copy),
+                "`cipher_from_key` must not hold its own copy of the key (found `{copy}`)"
+            );
+        }
+    }
+
+    /// The cipher's own copy of the key is wiped when the cipher is dropped.
+    ///
+    /// `chacha20poly1305`'s `zeroize` feature does the wipe; this pins the
+    /// feature. The cipher sits 32 bytes into its heap block, clear of the
+    /// free-list bookkeeping the allocator writes at the start of a freed block,
+    /// and the block is read back through `/proc/self/mem` after it is freed.
+    #[cfg(all(target_os = "linux", target_env = "gnu"))]
+    #[test]
+    fn a_dropped_cipher_wipes_its_key() {
+        use core::ptr;
+
+        /// A cipher at a fixed offset from the start of its heap block.
+        #[repr(C)]
+        struct Padded {
+            /// Keeps the cipher clear of the allocator's bookkeeping.
+            _pad: [u8; 32],
+            /// The cipher under test.
+            cipher: XChaCha20Poly1305,
+        }
+
+        /// A byte value a wipe never leaves behind.
+        const MARKER: u8 = 0xa5;
+
+        let mut memory = FreedMemory::new(KEK_LEN);
+        let boxed = Box::new(Padded {
+            _pad: [0; 32],
+            cipher: cipher_from_key(&[MARKER; KEK_LEN]),
+        });
+        let address = ptr::from_ref(&boxed.cipher).addr();
+        drop(boxed);
+        let residue = memory.residue(address, MARKER);
+        assert_eq!(
+            residue, 0,
+            "a dropped cipher must not leave its key in freed memory; {residue} key bytes survived"
+        );
+
+        // Instrument control: an unwiped block of the same shape is visible, so
+        // the zero above is a wipe rather than a blind spot.
+        let plain = Box::new([MARKER; 64]);
+        let control_address = plain.as_ptr().addr().saturating_add(32);
+        drop(plain);
+        let control = memory.residue(control_address, MARKER);
+        assert_eq!(
+            control, KEK_LEN,
+            "the instrument must see an unwiped freed block; it saw {control} of {KEK_LEN} bytes"
         );
     }
```

## Mutation check (prototype)

Each mutation reverts one guarded property; each was caught.

| Mutation | Caught by |
| --- | --- |
| Test the magic before wrapping (the audited order) | `the_refused_buffer_is_wiped_before_it_is_freed` (all 224 watched bytes survive) and the ordering guard |
| Extra `let unwiped = bytes.clone();` before the wrap | The new no-copy assertion. The behavioural test passes here, by design: the original block is still wiped. |
| Remove chacha20poly1305's `zeroize` feature | `a_dropped_cipher_wipes_its_key` ("32 key bytes survived") |
| An owned copy back in `cipher_from_key` (`let owned = *key;`) | `cipher_from_key_binds_no_copy_of_the_key` |

Flakiness: 40 runs of the two behavioural tests at `--test-threads=8`, plus 3 full
parallel `--lib` runs, gave 0 failures.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings   # cfg-gated code must leave nothing unused
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo test
```

Prototype result:

- every check passes;
- the suite runs 94 lib tests (92 before) and 3 integration tests;
- the Windows-target clippy run is clean, so the cfg-gated items leave nothing
  unused there.

## Design notes and limits

- **Gated to `all(target_os = "linux", target_env = "gnu")`.** glibc's thread cache
  writes at most 16 bytes of bookkeeping (`next`, `key`) at the start of a freed
  small block. The tests skip 32 bytes and use blocks that stay in that cache.
  Elsewhere the tests compile out: CI's Linux job runs them, and the Windows job
  builds without them.
- **They fail loudly, never skip.** If `/proc/self/mem` cannot be read, or the
  instrument control cannot see an unwiped block (`MALLOC_PERTURB_` set, or another
  allocator), the test fails with a message that says so.
- **Scope.** The behavioural tests watch the block that is actually freed. The
  no-copy guards cover extra copies in the two functions' own bodies. Copies made
  inside dependencies (for example inside an `Aead` implementation) are out of
  scope.
- **No allocation between the free and the read.** The probe buffer and file are
  set up before the free, so an allocation after it cannot be handed the freed
  block and refill it.

## Alternatives considered

- **A counting global allocator.** This is what the audit probe used. It needs
  `unsafe impl GlobalAlloc`, which `forbid(unsafe_code)` rules out in every target
  of this package. It would only be possible in a separate, non-member crate with
  its own lint table.
- **`EnvelopeUnlocker::new(bytes: Zeroizing<Vec<u8>>, ..)`.** This would make the
  wipe a property of the argument's type, but it is a public API break that moves
  the obligation onto every caller. Not proposed.
