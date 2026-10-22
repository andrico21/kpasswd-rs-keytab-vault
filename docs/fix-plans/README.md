# Fix plans - open issues after the run-1 fix revalidation

Working documents for `kpasswd-rs-keytab-vault`. They cover what is still open after
revalidating two things:

- the run-1 security audit, `~/security-audit-skill/kpasswd-rs-keytab-vault/run-1`;
- the uncommitted fixes applied on top of `0a88441`.

All four confirmed run-1 findings are fixed in the worktree; these plans cover what
those fixes left open, broke, or guard too weakly.

**Baseline.** The worktree as of 2026-10-07 13:15 +04:

- `cat src/*.rs | sha256sum` starts with `24db36c4`;
- `.github/workflows/*` and `scripts/ci-local.sh` are unchanged since 2026-10-06 23:55.

All five plans were applied in `69ee24a` (2026-10-07); the baseline above is the tree they were written against.

**How the plans were checked.** No change was applied to the worktree.

- The code changes were applied to a throwaway copy of it, which passed:
  - `cargo fmt --check`;
  - `cargo clippy --all-targets -D warnings` for Linux and the
    `x86_64-pc-windows-msvc` target;
  - `cargo doc -D warnings`;
  - the full test suite;
  - a mutation check showing each new test fails when the fix it guards is reverted.
- The CI change was run step by step on a fresh, networked runner home with the
  pinned tool versions, including the negative controls.

## Plans

| Plan | Class | Problem |
| --- | --- | --- |
| [blocking-ci-security-job-advisory-db.md](blocking-ci-security-job-advisory-db.md) | **blocking** | The security job fails on every run: the advisory database is cloned where cargo-deny never reads it. Behind that, `cargo deny --offline` cannot resolve dependencies on a fresh runner, and `cargo audit --no-fetch` lets the yanked check pass while checking nothing (exit 0). |
| [low-label-line-separators.md](low-label-line-separators.md) | low | U+2028 and U+2029 are still legal in labels, so a slot summary can still be forged in any viewer that breaks lines on them. |
| [release-0.2.0-label-rule-compatibility.md](release-0.2.0-label-rule-compatibility.md) | release | 0.1.0 envelopes with control or bidi characters in a label stop opening. The changelog misstates the history and gives no recovery path; this needs 0.2.0, not 0.1.x. |
| [tests-behavioural-zeroization-guards.md](tests-behavioural-zeroization-guards.md) | test quality | The two wipe guards only search the source text; an extra unwiped clone, or a wipe of nothing, passes both. |
| [hygiene-fuzz-lockfile-and-geiger-comment.md](hygiene-fuzz-lockfile-and-geiger-comment.md) | hygiene | `fuzz/Cargo.lock` is untracked and unenforced. The workflow calls the gitignored `geiger.txt` a committed census. |

Resolved since the review, so no plan: the `EnvelopeError::RotationMismatch` doc
(`src/format.rs:246-249`) now lists the label rules.

Correction to the review: it said `cargo audit` "passes either way". The exit code
is 0, but on a fresh runner that is because `--no-fetch` silently disables the
yanked check. The CI plan covers it.

## Order

1. **CI security job first.** No change merges green without it, and `release.yml`
   publishes only after a green CI run.
2. **Label line separators and the zeroization guards next**, in either order. Both
   edit `src/seal.rs`, in different hunks: the label test lists, and two
   `cipher_from_key` call sites.
3. **Hygiene before the release**, because the version bump also touches
   `fuzz/Cargo.lock` once it is tracked.
4. **Release 0.2.0 last:** the changelog rewrite, the version bump and both
   lockfiles, all in the release commit.

## Shared files

| File | Plans | Overlap |
| --- | --- | --- |
| `.github/workflows/rust.yaml` | CI (security job, lines 42-95); hygiene (geiger comment 108-116, fuzz job 259-266) | None, disjoint hunks |
| `src/seal.rs` | label (test lists near 1157 and 1353); zeroization (`cipher_from_key` call sites 215 and 407) | None |
| `src/format.rs` | label (predicate 137-141, test ~980) | - |
| `src/envelope.rs`, `src/unlocker.rs`, `src/lib.rs` | zeroization only | - |
| `CHANGELOG.md` | release (rewrites `[Unreleased]`, including the label plan's entry) | - |
| `scripts/ci-local.sh` | CI only | - |

## Decisions for the owner

1. **Release the label tightening as 0.2.0** (recommended), rather than as a 0.1.x
   patch, or by keeping legacy labels readable. See the release plan.
2. **Refuse U+2028/U+2029 in the same release** (recommended): one break instead of
   two. See the label plan.
3. **Keep zero-width and other formatting characters legal** (recommended; this is
   the current behaviour). See the label plan.
4. **Packaging.** `docs/fix-plans/` is untracked, and `Cargo.toml` has no
   `exclude`, so committing it as-is would ship these documents in the next
   `.crate`. Before committing, add `exclude = ["docs/fix-plans/"]` under
   `[package]`, as rskrb5-fork does, or keep these documents out of the repository.
   Release procedure step 5 (`cargo package --list`) would catch it either way.
