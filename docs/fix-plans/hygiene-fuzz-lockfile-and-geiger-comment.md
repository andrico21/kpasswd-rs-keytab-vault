# Hygiene: track and enforce the fuzz lockfile; correct the geiger comment

- Class: hygiene (CI inputs and comments). There is no crate change.
- Status: applied in `69ee24a`. The lockfile check and the workflow edits were
  checked on throwaway copies, and the edited workflow parses with PyYAML.

## 1. `fuzz/Cargo.lock` is untracked

### Problem

The worktree pins the fuzz harness's direct dependency exactly:
`fuzz/Cargo.toml:16`, `libfuzzer-sys = "=0.4.13"`. The comment says the pin is
"like every other input (KRP-57)". But `fuzz/` is its own workspace
(`fuzz/Cargo.toml:10`, `[workspace]`) with its own lockfile, and that lockfile is
untracked: `git ls-files fuzz` lists only `fuzz/Cargo.toml` and
`fuzz/fuzz_targets/envelope.rs`.

So every scheduled fuzz run re-resolves the rest of its graph: the vault's
~196-crate dependency tree, plus `arbitrary`, `jobserver` and libfuzzer-sys's own
dependencies. The fuzz job's input is not actually pinned, which works against the
point of the cached, accumulating corpus.

`cargo fuzz run` cannot enforce a lockfile itself: it has no `--locked` flag (none
in `cargo fuzz run --help` for cargo-fuzz 0.13.2).

### Fix

1. **Track the lockfile:** `git add fuzz/Cargo.lock`. `.gitignore` ignores only
   `/fuzz/target`, so the lockfile is not ignored. The current untracked file
   matches the root `Cargo.lock` on all 196 shared packages (0 version mismatches)
   and adds 4 fuzz-only packages (`arbitrary`, `jobserver`, `libfuzzer-sys`,
   `kpasswd-rs-keytab-vault-fuzz`). Tracking it as-is pins the fuzz build to the
   shipped dependency set.
2. **Enforce it in the fuzz job.** Before the fuzz run, a `--locked` metadata check
   fails the job if the lockfile would have to change:

```diff
@@ -259,6 +260,11 @@
           toolchain: ${{ env.FUZZ_TOOLCHAIN }}
       - name: Install cargo-fuzz
         run: cargo install cargo-fuzz --locked --version 0.13.2
+      # The harness's own lockfile is tracked (fuzz/Cargo.lock). cargo-fuzz has
+      # no --locked flag, so this step is the lock: a stale lockfile fails here
+      # instead of the fuzz build silently re-resolving the harness's inputs.
+      - name: Check the fuzz lockfile is current
+        run: cargo +${{ env.FUZZ_TOOLCHAIN }} metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml > /dev/null
       # The corpus is the job's memory: without a restore it re-learns the same
       # shapes every run. Keyed on the inputs it is a seed for, so a changed
       # parser gets a fresh cache line while the previous one still seeds it.
```

The fuzz job stays advisory (`continue-on-error: true`), so a stale lockfile shows
up as a red fuzz job, not a red CI run.

### Verification

`cargo metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml` exits
0 with the current lockfile. On a copy whose lockfile was made stale (the
`libfuzzer-sys` entry removed), it exits 101 with: `cannot update the lock file ...
because --locked was passed to prevent this`.

### Keeping it current

- When a dependency in the root `Cargo.lock` moves, move the fuzz lockfile in the
  same commit:
  `cargo update --manifest-path fuzz/Cargo.toml -p <crate> --precise <version> --offline`.
  That keeps the harness on the same versions as the shipped crate.
- The vault's own version bump touches `fuzz/Cargo.lock:779` too; see
  [release-0.2.0-label-rule-compatibility.md](release-0.2.0-label-rule-compatibility.md),
  step 2.
- Optional: compare the shared package versions of the two lockfiles in the lint
  job, so drift is caught automatically. Not proposed here, to keep the change
  minimal.

## 2. The geiger comment says the census is committed; it is gitignored

### Problem

`.github/workflows/rust.yaml:111-112`:

```text
# Advisory, but version-pinned like the gating tools: `geiger.txt` is a
# committed census, so the tool that produced it is an input too.
```

But `.gitignore:10-11` ignores `/geiger.txt` ("cargo-geiger's report
(`scripts/ci-local.sh` writes it at the root)"). The CI step only prints the census
into the job log (`tail -50 geiger.txt`).

### Fix

```diff
@@ -108,8 +108,9 @@
       - name: Check for unused dependencies
         run: cargo machete
 
-      # Advisory, but version-pinned like the gating tools: `geiger.txt` is a
-      # committed census, so the tool that produced it is an input too.
+      # Advisory, but version-pinned like the gating tools: the census below is
+      # this job's log (`geiger.txt` is gitignored), and it should change only
+      # when the dependency tree does, not when the tool does.
       - name: Install cargo-geiger
         run: cargo install cargo-geiger --locked --version 0.13.0
         continue-on-error: true
```

The version pin itself stays. The alternative is to commit `geiger.txt` and
un-ignore it, so the comment becomes true. That is not proposed: the census changes
with every dependency move and would churn the history.

## Shared file

The CI plan ([blocking-ci-security-job-advisory-db.md](blocking-ci-security-job-advisory-db.md))
edits the security job of the same workflow. Its hunks (lines 42-95) do not overlap
these (108-116 and 259-266), so either plan can be applied first.
