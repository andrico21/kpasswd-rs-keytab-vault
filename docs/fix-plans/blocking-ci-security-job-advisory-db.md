# CI security job: resolve the advisory database in cargo-deny's layout, keep the deny gate online, make the yanked gate fail closed

- Class: **blocking** (CI). The `Security Audit` job fails on every run, and
  `release.yml` publishes only after a green CI run of the same commit.
- Found by: revalidation of the run-1 audit fixes (2026-10-07). Defect 1 was
  reported in the review; defects 2 and 3 were found while preparing this plan.
- Applies to: the uncommitted worktree on `0a88441` - `.github/workflows/rust.yaml`
  and `scripts/ci-local.sh`, both unchanged since 2026-10-06 23:55.
- Status: applied in `69ee24a`. The exact change below was run step by step on a
  fresh, networked runner home with the pinned tool versions (see Verification).

## Problem

The worktree replaced each tool's own database fetch with one up-front
`git clone` of the RustSec advisory database, then runs both gates without
network: `cargo deny --offline check` and `cargo audit --no-fetch --deny yanked`.
That has three defects, each sufficient on its own:

1. **The clone is in cargo-audit's layout, not cargo-deny's.** cargo-deny reads
   `<db-path>/advisory-db-<hash>/` - here
   `~/.cargo/advisory-db/advisory-db-3157b0e258782691` - and the step clones into
   `~/.cargo/advisory-db` itself. `cargo deny --offline check` exits 1:
   `failed to get 'FETCH_HEAD' metadata ... cannot change to '.../advisory-db-3157b0e258782691'`.
2. **`--offline` also takes `cargo metadata` offline.** A fresh runner's cargo
   cache is empty: the job builds nothing, and the `cargo install` steps cache only
   the tools' own dependencies. So even with the right layout the deny gate fails:
   `no matching package named 'argon2' found ... offline mode`.
3. **`--no-fetch` quietly disables cargo-audit's yanked check.** The flag also stops
   cargo-audit refreshing the crates.io index. With no index cache, cargo-audit
   prints `error: couldn't check if the package is yanked` for every crate (200
   lines here) and still **exits 0**. `--deny yanked` then passes without checking
   anything. At `0a88441` the online `cargo audit --deny yanked` did check.

The local mirror hid all three. This machine has both a cargo-audit clone and an
older cargo-deny checkout under `~/.cargo/advisory-db`, plus a full registry and
index cache. `scripts/ci-local.sh` also prints the cargo-audit clone's revision,
which is not the checkout cargo-deny reads.

## Root cause (worktree, line numbers as of 2026-10-07 13:15 +04)

- `.github/workflows/rust.yaml:56-61` - `DB="${CARGO_HOME:-$HOME/.cargo}/advisory-db"`,
  `rm -rf "$DB"`, `git clone --depth 1 ... "$DB"`. That path is the directory
  cargo-deny treats as `db-path` (`deny.toml:14`, `db-path = "~/.cargo/advisory-db"`),
  not the checkout under it.
- `rust.yaml:84` - `cargo deny --offline check`. The global flag is documented as
  "Run without accessing the network" and also applies to `cargo metadata`. The
  `check` subcommand's own `-d, --disable-fetch` skips only the database fetch: "the
  database won't be fetched, but an error will occur if it doesn't already exist
  locally".
- `rust.yaml:92` - `cargo audit --no-fetch --deny yanked`, with no `--db`, so it reads
  the cargo-audit layout. `--no-fetch` also skips the index update the yanked check
  needs.
- `scripts/ci-local.sh:112-124` - the same flags, and
  `git -C "$advisory_db" rev-parse HEAD` prints the audit clone's revision.

## Evidence

All runs used the pinned tools: cargo-deny 0.19.6 and cargo-audit 0.22.1.

| Setup | Result |
| --- | --- |
| Worktree layout (one shallow clone at `~/.cargo/advisory-db`), sandboxed | `cargo deny --offline check` exit 1 (FETCH_HEAD / `advisory-db-3157...` missing); `cargo audit --no-fetch` exit 0 |
| Same, plus a clone at `advisory-db-3157b0e258782691` | `cargo deny --offline check` exit 0 |
| Fresh `CARGO_HOME`, network on, cargo-deny checkout present | `cargo deny --offline check` exit 1 (`no matching package named 'argon2' found`); `cargo deny check --disable-fetch` exit 0 |
| Fresh `CARGO_HOME`, network on | `cargo audit --no-fetch --db <checkout> --deny yanked` exit 0, with 200x `couldn't check if the package is yanked` |
| Same, after `cargo fetch --locked` | exit 0, 0 such lines |
| `cargo deny fetch db`, network cut, no checkout | exit 1, nothing created |
| `cargo deny fetch db`, network cut, checkout present | **exit 0**, logs `fetched ... in 188ms`, checkout unchanged |
| `cargo deny check --disable-fetch`, no checkout | exit 1 (fails closed) |

## Proposed fix

The new step order:

1. Fetch the locked dependency graph.
2. Install cargo-deny.
3. Resolve the database once, with cargo-deny, into its own layout.
4. Run the deny gate with `--disable-fetch`.
5. Install cargo-audit.
6. Run the audit gate against that same checkout, by path, and fail on any unchecked
   yanked status.

### `.github/workflows/rust.yaml` (security job)

```diff
@@ -42,31 +42,12 @@
         with:
           toolchain: 1.99.0
 
-      # The advisory data is a mutable third-party feed on purpose: a pinned
-      # revision would go stale and silently miss advisories. It is therefore a
-      # *declared* input, not a hidden one - resolved exactly once here, with the
-      # resolved revision recorded for the run, and consumed offline by both
-      # gates below (--offline / --no-fetch), so no second fetch can change what
-      # a verdict was decided against. A failed resolve fails the job: a missing
-      # feed must never read as "no advisories".
-      - name: Resolve the RustSec advisory database once
-        shell: bash
-        run: |
-          set -euo pipefail
-          DB="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
-          # The runner image ships a non-empty ~/.cargo/advisory-db that
-          # cargo-audit refuses to initialize into; this replaces it with a
-          # clean shallow checkout instead.
-          rm -rf "$DB"
-          git clone --depth 1 --single-branch https://github.com/rustsec/advisory-db "$DB"
-          REVISION=$(git -C "$DB" rev-parse HEAD)
-          echo "RustSec advisory-db revision: $REVISION"
-          {
-            echo "### RustSec advisory database"
-            echo ""
-            echo "- revision: \`$REVISION\`"
-            echo "- resolved by: \`git clone --depth 1 https://github.com/rustsec/advisory-db\`"
-          } >> "$GITHUB_STEP_SUMMARY"
+      # The locked dependency graph on the runner before any gate reads it:
+      # `cargo deny check` resolves the graph through `cargo metadata`, and
+      # cargo-audit's yanked check reads the crates.io index cache this fills
+      # (`--no-fetch` below stops cargo-audit refreshing that cache itself).
+      - name: Fetch the locked dependency graph
+        run: cargo fetch --locked
 
       # Pinned like every other input (KRP-57): an unpinned `cargo install`
       # resolves whichever release is newest when the job runs, so a gate
@@ -76,20 +57,66 @@
       - name: Install cargo-deny
         run: cargo install cargo-deny --locked --version 0.19.6
 
+      # The advisory data is a mutable third-party feed on purpose: a pinned
+      # revision would go stale and silently miss advisories. It is therefore a
+      # *declared* input, not a hidden one - resolved exactly once here, in
+      # cargo-deny's own layout (`<db-path>/advisory-db-<hash>`, the only place
+      # `cargo deny check` reads), with the revision recorded for the run and
+      # the checkout handed to cargo-audit by path. Deleting it first is
+      # load-bearing: with a checkout already present, `cargo deny fetch db`
+      # reports success even when the fetch failed, so a stale copy would pass.
+      - name: Resolve the RustSec advisory database once
+        shell: bash
+        run: |
+          set -euo pipefail
+          # deny.toml: db-path = "~/.cargo/advisory-db". `cargo deny fetch db` clones each
+          # db-url into its own subdirectory there - the layout `cargo deny check` reads -
+          # and that one checkout is the snapshot both gates below are decided against.
+          ROOT="$HOME/.cargo/advisory-db"
+          rm -rf "$ROOT"
+          cargo deny fetch db
+          mapfile -t CHECKOUTS < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type d -name 'advisory-db-*')
+          if [ "${#CHECKOUTS[@]}" -ne 1 ]; then
+            echo "::error::expected one cargo-deny advisory-db checkout under $ROOT, found ${#CHECKOUTS[@]}"
+            exit 1
+          fi
+          DB="${CHECKOUTS[0]}"
+          REVISION=$(git -C "$DB" rev-parse HEAD)
+          echo "RustSec advisory-db revision: $REVISION ($DB)"
+          echo "ADVISORY_DB=$DB" >> "$GITHUB_ENV"
+          {
+            echo "### RustSec advisory database"
+            echo ""
+            echo "- revision: \`$REVISION\`"
+            echo "- checkout: \`$DB\`, resolved once by \`cargo deny fetch db\`"
+          } >> "$GITHUB_STEP_SUMMARY"
+
       # Advisory/ban/license/source policy is pinned in deny.toml; yanked
       # crates are denied there explicitly (cargo-deny >= 0.18 semantics).
-      # `--offline` keeps this gate on the snapshot resolved above - deny.toml's
-      # db-path is the same checkout.
+      # `--disable-fetch` keeps the advisory check on the snapshot resolved
+      # above. Unlike `--offline`, it leaves `cargo metadata` and the yanked
+      # lookup online, which a fresh runner's empty cargo cache needs.
       - name: Check advisories, licenses, bans & sources
-        run: cargo deny --offline check
+        run: cargo deny check --disable-fetch
 
       - name: Install cargo-audit
         run: cargo install cargo-audit --locked --version 0.22.1
 
       # `--deny yanked` because plain `cargo audit` reports a yanked crate as
-      # a warning and still exits 0; `--no-fetch` consumes the same snapshot.
+      # a warning and still exits 0; `--no-fetch --db` reads the snapshot
+      # resolved above.
       - name: Audit RustSec advisories
-        run: cargo audit --no-fetch --deny yanked
+        shell: bash
+        run: |
+          set -euo pipefail
+          cargo audit --no-fetch --db "$ADVISORY_DB" --deny yanked 2>&1 | tee "$RUNNER_TEMP/cargo-audit.log"
+          # --no-fetch also skips the crates.io index refresh; where the index cache is
+          # missing, cargo-audit prints this and still exits 0, which would pass the
+          # yanked gate without checking anything.
+          if grep -q "couldn't check if the package is yanked" "$RUNNER_TEMP/cargo-audit.log"; then
+            echo "::error::cargo-audit could not read the yanked status of every crate; refusing to pass the yanked gate unchecked"
+            exit 1
+          fi
 
       - name: Install cargo-vet
         run: cargo install cargo-vet --locked --version 0.10.2
```

Why each piece is there:

- **`cargo fetch --locked` comes first.** It gives `cargo metadata` the packages it
  needs, and gives cargo-audit the index cache its yanked check reads. `--locked`
  keeps the graph exactly as the lockfile pins it.
- **`rm -rf "$ROOT"` stays.** The runner image ships a non-empty
  `~/.cargo/advisory-db`. Also, `cargo deny fetch db` reports success when the
  network fails, as long as a checkout already exists. Deleting first is what makes
  a failed fetch fail the step instead of reusing a stale copy.
- **The one-checkout assertion is a second fail-closed layer.** It also fails loudly
  if `deny.toml` gains a second `db-urls` entry or `db-path` moves.
- **`ADVISORY_DB` is passed through `$GITHUB_ENV`.** That way cargo-audit reads the
  very checkout cargo-deny decided against.
- **The deny gate uses `--disable-fetch` instead of `--offline`.** Only the database
  stays pinned; `cargo metadata` and the index lookups keep their network.
- **The `grep` guard closes cargo-audit's fail-open.** The step already runs with
  `pipefail`, so a real audit failure exits before the grep.

### `scripts/ci-local.sh` (`job_security`)

```diff
@@ -105,22 +105,43 @@
 job_security() {
   section "Security Audit"
 
-  # One resolved snapshot, as in CI: the revision both advisory gates below
-  # are decided against is printed, and the gates stay off the network so a
-  # second fetch cannot change a verdict. A machine with no checkout yet gets
-  # the fetch from the tools once, with a notice - CI never does that.
-  local advisory_db="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
-  if [ -d "$advisory_db/.git" ]; then
-    printf '\n--- RustSec advisory-db revision\n'
-    git -C "$advisory_db" rev-parse HEAD
-    run "cargo deny --offline check" cargo deny --offline check
-    run "cargo audit --no-fetch --deny yanked" cargo audit --no-fetch --deny yanked
+  # The locked dependency graph, as in CI: `cargo deny check` resolves it
+  # through `cargo metadata`, and cargo-audit's yanked check reads the crates.io
+  # index cache this fills (`--no-fetch` stops cargo-audit refreshing it).
+  run "cargo fetch --locked" cargo fetch --locked
+
+  # One advisory snapshot for both gates, in cargo-deny's own layout under
+  # deny.toml's db-path (`<db-path>/advisory-db-<hash>`), as in CI. With a
+  # checkout already present, `cargo deny fetch db` reports success even when
+  # it cannot reach the network, so the revision's commit date is printed: an
+  # old date is a stale feed. (CI deletes the checkout first; here that would
+  # make every offline run fail.)
+  run "cargo deny fetch db" cargo deny fetch db
+  local root="$HOME/.cargo/advisory-db"
+  local checkouts=()
+  mapfile -t checkouts < <(find "$root" -mindepth 1 -maxdepth 1 -type d -name 'advisory-db-*' 2>/dev/null)
+  if [ "${#checkouts[@]}" -ne 1 ]; then
+    printf '\nFAIL: expected one cargo-deny advisory-db checkout under %s, found %d\n' \
+      "$root" "${#checkouts[@]}"
+    FAILURES=$((FAILURES + 1))
+    FAILED_JOBS+=("advisory-db checkout")
   else
-    printf '\nNOTE: no advisory-db checkout at %s; the gates below will fetch one.\n' "$advisory_db"
-    run "cargo deny check" cargo deny check
-    run "cargo audit --deny yanked" cargo audit --deny yanked
-    printf '\n--- RustSec advisory-db revision (fetched by the gates)\n'
-    git -C "$advisory_db" rev-parse HEAD 2>/dev/null || true
+    local db="${checkouts[0]}"
+    printf '\n--- RustSec advisory-db revision\n%s (committed %s)\n' \
+      "$(git -C "$db" rev-parse HEAD)" "$(git -C "$db" log -1 --format=%cI)"
+    run "cargo deny check --disable-fetch" cargo deny check --disable-fetch
+    # --no-fetch also skips the crates.io index refresh; a crate missing from
+    # the index cache makes cargo-audit print "couldn't check if the package is
+    # yanked" and still exit 0, so that line fails the leg here.
+    run "cargo audit --no-fetch --db <checkout> --deny yanked" bash -c '
+      out=$(cargo audit --no-fetch --db "$1" --deny yanked 2>&1)
+      status=$?
+      printf "%s\n" "$out"
+      if grep -q "couldn'"'"'t check if the package is yanked" <<<"$out"; then
+        echo "cargo-audit could not read the yanked status of every crate"
+        status=1
+      fi
+      exit "$status"' _ "$db"
   fi
   # --locked reads supply-chain/imports.lock and performs no network I/O.
   run "cargo vet --locked" cargo vet --locked
```

The local mirror deliberately differs from CI in one place: it does not delete the
checkout. Deleting it would make every offline run fail and would remove the
developer's own copy. Instead it prints the revision's commit date, because the
fetch's exit code cannot reveal a stale feed.

## Verification

Done while preparing this plan. The step bodies above were run verbatim, in order,
against a throwaway, networked runner home whose `HOME` and `CARGO_HOME` started
empty:

- `cargo fetch --locked` exit 0.
- Resolve: exactly one checkout, `advisory-db-3157b0e258782691` (revision
  `f246cde7...` at the time), and `ADVISORY_DB` exported.
- `cargo deny check --disable-fetch` printed
  `advisories ok, bans ok, licenses ok, sources ok`.
- The audit step loaded 1293 advisories, printed 0 "couldn't check" lines, and
  exited 0.
- Negative controls: the audit step without `cargo fetch --locked` exits 1 (the
  guard fires), and the deny step with no checkout exits 1.
- PyYAML parses the proposed workflow. The two `run:` bodies are byte-identical to
  the scripts that were executed, and the step order is as listed above.
- The proposed `scripts/ci-local.sh security`, run in a throwaway repository copy,
  passes every leg both online and with the network cut (`unshare -rn`), and prints
  the revision with its commit date.

After applying:

```sh
bash -n scripts/ci-local.sh
python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/rust.yaml"))'
scripts/ci-local.sh security
```

Then open a PR. The `Security Audit` job should be green, its summary should show the
revision, and the audit step's log should read
`Loaded N security advisories (from .../advisory-db/advisory-db-3157b0e258782691)`.

## Compatibility / notes

- CI and the local mirror only: no crate change, and `deny.toml` is unchanged.
- If `deny.toml`'s `db-path` or `db-urls` changes, `ROOT` and the one-checkout
  assertion must follow. The assertion fails loudly if they drift.
- [hygiene-fuzz-lockfile-and-geiger-comment.md](hygiene-fuzz-lockfile-and-geiger-comment.md)
  edits the same workflow file in disjoint hunks (the geiger comment and the fuzz
  job).

## Risks / open questions

- The guard matches cargo-audit's message text. The version is pinned, and the
  existing KRP-57 comment already requires revalidation on a bump. When bumping,
  re-run the negative control: the audit step on a fresh `CARGO_HOME` without
  `cargo fetch` must exit 1.
- Both gates read the crates.io index as of `cargo fetch --locked`, a few seconds
  earlier. That is the freshness this job has always had.
