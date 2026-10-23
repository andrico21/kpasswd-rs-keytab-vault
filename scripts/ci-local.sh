#!/usr/bin/env bash
#
# Best-effort local equivalent of .github/workflows/rust.yaml.
#
# This repository has exactly one automated gate besides GitHub Actions: this
# script. It reproduces the `lint`, `nightly-lint`, `lint-gates`, `security`,
# `build-linux` and `msrv` jobs at the same strictness.
#
# Not one-for-one. Two gaps, stated here because "I ran CI" should not
# overstate what ran:
#
#   * Windows: the workflow compiles the crate and its test targets on
#     windows-latest. That needs an MSVC linker and a Windows host, neither of
#     which exists here, so this script only *compiles and lints* for the MSVC target
#     (cargo check, cargo clippy). It never links, so the MSVC link flags (/DYNAMICBASE,
#     /HIGHENTROPYVA, /NXCOMPAT, /CETCOMPAT) are parsed but not exercised.
#   * The scheduled fuzz job is not mirrored: it is schedule/dispatch-only and
#     advisory (section 12 classes fuzzing informational).
#
# Usage: scripts/ci-local.sh [job ...]
#   Jobs: lint nightly-lint lint-gates security build-linux build-windows msrv (default: all seven)
#
# Optional tools that CI marks `continue-on-error: true` (cargo-geiger) are
# skipped with a notice when absent rather than failing; everything gating in
# CI is required here.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

HAVE_CARGO_GEIGER=$(
  command -v cargo-geiger >/dev/null 2>&1 && echo yes || echo no
)
WINDOWS_TARGET="x86_64-pc-windows-msvc"

# Track the worst outcome. A skipped optional tool is not a failure; a
# failed gating step is.
FAILURES=0
declare -a FAILED_JOBS=()

section() { printf '\n=== %s ===\n' "$1"; }

run() {
  # run <label> <command...>
  #
  # Each leg's output is kept under `target/ci-local/` as well as printed: a
  # leg that fails once and passes on every re-run is otherwise undiagnosable.
  local label=$1
  shift
  local log_dir=target/ci-local
  mkdir -p "$log_dir"
  local log="$log_dir/$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_').log"
  printf '\n--- %s\n' "$label"
  # The leg's status, not `tee`'s: an `if cmd | tee` tests the *pipeline's*
  # status, which is tee's, so a failing leg would report PASS.
  "$@" 2>&1 | tee "$log"
  local status=${PIPESTATUS[0]}
  if [ "$status" -eq 0 ]; then
    printf 'PASS: %s\n' "$label"
  else
    printf 'FAIL(%d): %s  (output: %s)\n' "$status" "$label" "$log"
    FAILURES=$((FAILURES + 1))
    FAILED_JOBS+=("$label")
  fi
}

job_lint() {
  section "Lint (fmt + clippy)"
  # The workflow exports CARGO_BUILD_WARNINGS=deny at job scope, covering
  # the `cargo check` step; clippy needs its own -D warnings on top.
  export CARGO_BUILD_WARNINGS=deny

  run "workflow lint: actions pinned to full SHAs" bash -c '
    unpinned=$(grep -rEn "^[[:space:]]*(-[[:space:]]*)?uses:" .github/workflows/ \
      | grep -Ev "uses:[[:space:]]+[^[:space:]]+@[0-9a-f]{40}([[:space:]]|$)" || true)
    if [ -n "$unpinned" ]; then
      echo "unpinned action refs found (every uses: ref must be a 40-hex commit SHA):"
      echo "$unpinned"
      exit 1
    fi'
  run "scripts/check-drift.sh" bash scripts/check-drift.sh

  run "rustfmt: cargo fmt --all -- --check" cargo fmt --all -- --check
  run "rustfmt (fuzz harness): cargo fmt --all --manifest-path fuzz/Cargo.toml -- --check" cargo fmt --all --manifest-path fuzz/Cargo.toml -- --check
  run "taplo check" taplo check
  run "taplo fmt --check" taplo fmt --check

  # The doc surface: the lint table denies every rustdoc lint, and only
  # `cargo doc` exercises them.
  run "rustdoc: RUSTDOCFLAGS=-Dwarnings cargo doc --locked --no-deps --all-features" \
    env RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

  run "cargo test --locked (the crate's suite)" cargo test --locked

  # The crate enables all+pedantic+restriction+cargo at "deny" via
  # `[workspace.lints]` in Cargo.toml; -D warnings promotes any residual
  # warning.
  run "clippy: cargo clippy --locked --all-targets --all-features -- -D warnings" \
    cargo clippy --locked --all-targets --all-features -- -D warnings
  run "clippy (fuzz harness): cargo clippy --locked --all-targets --all-features --manifest-path fuzz/Cargo.toml -- -D warnings" cargo clippy --locked --all-targets --all-features --manifest-path fuzz/Cargo.toml -- -D warnings
  run "cargo check --locked --all-targets --all-features --keep-going (build.warnings=deny)" \
    cargo check --locked --all-targets --all-features --keep-going
  # `allow_attributes` sees only outer `#[allow]`; an inner `#![allow]` would
  # pass it unseen, so the guidelines gate on this grep instead.
  run "no inner #![allow] attributes" bash -c '
    found=$(grep -rn --include="*.rs" "#!\[allow(" src tests fuzz/fuzz_targets || true)
    [ -z "$found" ] || { echo "inner #![allow] found; use #![expect]:"; echo "$found"; exit 1; }'
}

job_nightly_lint() {
  section "Lint (dated nightly, rustfmt imports + docs.rs rustdoc)"
  # The pin lives in the workflow's nightly-lint job; reading it here keeps the
  # two from drifting. Exactly one dated NIGHTLY_TOOLCHAIN line is expected.
  local pins nightly
  pins=$(sed -n 's/^[[:space:]]*NIGHTLY_TOOLCHAIN:[[:space:]]*"\{0,1\}\(nightly-[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\)"\{0,1\}[[:space:]]*\(#.*\)\{0,1\}$/\1/p' .github/workflows/rust.yaml)
  if [ "$(printf '%s\n' "$pins" | grep -c .)" -ne 1 ]; then
    printf '\nFAIL: expected exactly one dated NIGHTLY_TOOLCHAIN in .github/workflows/rust.yaml, found: %s\n' "${pins:-none}"
    FAILURES=$((FAILURES + 1))
    FAILED_JOBS+=("nightly pin unreadable")
    return
  fi
  nightly=$pins
  if ! rustup toolchain list | grep -q "^${nightly}-"; then
    printf '\nFAIL: toolchain %s not installed (run: rustup toolchain install %s --profile minimal --component rustfmt)\n' \
      "$nightly" "$nightly"
    FAILURES=$((FAILURES + 1))
    FAILED_JOBS+=("nightly toolchain missing")
    return
  fi
  run "rustfmt (nightly import options): cargo +$nightly fmt --all -- --check" \
    cargo +"$nightly" fmt --all -- --check
  run "rustfmt (nightly, fuzz harness): cargo +$nightly fmt --all --manifest-path fuzz/Cargo.toml -- --check" \
    cargo +"$nightly" fmt --all --manifest-path fuzz/Cargo.toml -- --check
  run "rustdoc as docs.rs builds it: cargo +$nightly doc --locked --no-deps --all-features" \
    env RUSTDOCFLAGS="-D warnings --cfg docsrs" CARGO_BUILD_WARNINGS=deny CARGO_TARGET_DIR=target/nightly \
    cargo +"$nightly" doc --locked --no-deps --all-features
}

job_lint_gates() {
  section "Lint gates (lint-ratchet)"
  # The dash gate reads the git index, as in CI: stage or commit new files first.
  run "python3 is 3.11 or newer (tomllib)" \
    python3 -c 'import sys; assert sys.version_info >= (3, 11), sys.version'
  run "gate self-tests" \
    bash -c 'for s in scripts/lint-ratchet/*.py; do python3 -B "$s" --self-test || exit 1; done'
  run "vendored guideline checksum" bash -c 'cd docs/rust-guidelines && sha256sum -c SHA256SUMS'
  run "allow gate" python3 -B scripts/lint-ratchet/allow_gate.py --enforce
  run "profile equality" python3 -B scripts/lint-ratchet/profile_eq.py --clippy-toml
  run "dash gate" python3 -B scripts/lint-ratchet/dash_gate.py --enforce
}

job_security() {
  section "Security Audit"

  # The locked dependency graph, as in CI: `cargo deny check` resolves it
  # through `cargo metadata`, and cargo-audit's yanked check reads the crates.io
  # index cache this fills (`--no-fetch` stops cargo-audit refreshing it).
  run "cargo fetch --locked" cargo fetch --locked

  # One advisory snapshot for both gates, in cargo-deny's own layout under
  # deny.toml's db-path (`<db-path>/advisory-db-<hash>`), as in CI. With a
  # checkout already present, `cargo deny fetch db` reports success even when
  # it cannot reach the network, so the revision's commit date is printed: an
  # old date is a stale feed. (CI deletes the checkout first; here that would
  # make every offline run fail.)
  run "cargo deny fetch db" cargo deny fetch db
  local root="$HOME/.cargo/advisory-db"
  local checkouts=()
  mapfile -t checkouts < <(find "$root" -mindepth 1 -maxdepth 1 -type d -name 'advisory-db-*' 2>/dev/null)
  if [ "${#checkouts[@]}" -ne 1 ]; then
    printf '\nFAIL: expected one cargo-deny advisory-db checkout under %s, found %d\n' \
      "$root" "${#checkouts[@]}"
    FAILURES=$((FAILURES + 1))
    FAILED_JOBS+=("advisory-db checkout")
  else
    local db="${checkouts[0]}"
    printf '\n--- RustSec advisory-db revision\n%s (committed %s)\n' \
      "$(git -C "$db" rev-parse HEAD)" "$(git -C "$db" log -1 --format=%cI)"
    run "cargo deny check --disable-fetch" cargo deny check --disable-fetch
    # --no-fetch also skips the crates.io index refresh; a crate missing from
    # the index cache makes cargo-audit print "couldn't check if the package is
    # yanked" and still exit 0, so that line fails the leg here.
    run "cargo audit --no-fetch --db <checkout> --deny yanked" bash -c '
      out=$(cargo audit --no-fetch --db "$1" --deny yanked 2>&1)
      status=$?
      printf "%s\n" "$out"
      if grep -q "couldn'"'"'t check if the package is yanked" <<<"$out"; then
        echo "cargo-audit could not read the yanked status of every crate"
        status=1
      fi
      exit "$status"' _ "$db"
  fi
  # --locked reads supply-chain/imports.lock and performs no network I/O.
  run "cargo vet --locked" cargo vet --locked
  run "cargo machete" cargo machete

  # Recommended, non-gating in CI: report but never fail on absence.
  if [ "$HAVE_CARGO_GEIGER" = yes ]; then
    printf '\n--- cargo geiger (informational)\n'
    cargo geiger > geiger.txt 2>&1 || true
    tail -50 geiger.txt
  else
    printf '\nSKIP: cargo-geiger not installed (informational in CI)\n'
  fi
}

job_build_linux() {
  section "Build & Test (Linux)"
  export CARGO_BUILD_WARNINGS=deny

  run "cargo build --locked --verbose" cargo build --locked --verbose
  run "cargo test --locked --verbose" cargo test --locked --verbose
}

job_build_windows() {
  section "Build (Windows, check + clippy)"
  # The full job needs an MSVC linker and a Windows host. Only the
  # compilation half is reproducible here; the header lists what this
  # therefore does NOT catch. RUSTFLAGS is set anyway so the same cfg and
  # codegen options are parsed, but note `cargo check` does not link, so
  # the /link-args are syntax-checked only.
  local windows_flags="-C control-flow-guard=yes -C link-args=/DYNAMICBASE -C link-args=/HIGHENTROPYVA -C link-args=/NXCOMPAT -C link-args=/CETCOMPAT"

  if ! rustup target list --installed 2>/dev/null | grep -qx "$WINDOWS_TARGET"; then
    printf '\nFAIL: rust target %s not installed (run: rustup target add %s)\n' \
      "$WINDOWS_TARGET" "$WINDOWS_TARGET"
    FAILURES=$((FAILURES + 1))
    FAILED_JOBS+=("windows target missing")
    return
  fi

  run "cargo check --locked --target $WINDOWS_TARGET --all-targets --all-features (the crate must stay portable)" \
    env RUSTFLAGS="$windows_flags" \
    cargo check --locked --target "$WINDOWS_TARGET" --all-targets --all-features
  run "clippy (Windows): cargo clippy --locked --target $WINDOWS_TARGET --all-targets --all-features -- -D warnings" \
    env RUSTFLAGS="$windows_flags" \
    cargo clippy --locked --target "$WINDOWS_TARGET" --all-targets --all-features -- -D warnings
}

job_msrv() {
  section "MSRV (rust-version, compile-only)"
  # Mirrors the workflow's msrv job: RUSTUP_TOOLCHAIN outranks
  # rust-toolchain.toml, and lints are capped because this proves compile
  # compatibility, not lint cleanliness. A separate target dir keeps the
  # MSRV artifacts apart from the pinned toolchain's.
  local msrv
  msrv=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml \
    | awk -F. 'NF == 2 { print $0 ".0"; next } { print }')
  if ! rustup toolchain list | grep -q "^${msrv}-"; then
    printf '\nFAIL: toolchain %s not installed (run: rustup toolchain install %s --profile minimal)\n' \
      "$msrv" "$msrv"
    FAILURES=$((FAILURES + 1))
    FAILED_JOBS+=("msrv toolchain missing")
    return
  fi
  run "rustc -V on $msrv" env RUSTUP_TOOLCHAIN="$msrv" rustc -V
  run "cargo build --locked on $msrv (lints capped)" \
    env RUSTUP_TOOLCHAIN="$msrv" RUSTFLAGS="--cap-lints=warn" CARGO_BUILD_WARNINGS=allow \
    CARGO_TARGET_DIR=target/msrv cargo build --locked
}

JOBS=("$@")
if [ ${#JOBS[@]} -eq 0 ]; then
  JOBS=(lint nightly-lint lint-gates security build-linux build-windows msrv)
fi

for job in "${JOBS[@]}"; do
  case "$job" in
    lint) job_lint ;;
    nightly-lint) job_nightly_lint ;;
    lint-gates) job_lint_gates ;;
    security) job_security ;;
    build-linux) job_build_linux ;;
    build-windows) job_build_windows ;;
    msrv) job_msrv ;;
    *)
      printf 'unknown job: %s (want: lint nightly-lint lint-gates security build-linux build-windows msrv)\n' "$job" >&2
      exit 2
      ;;
  esac
done

section "Summary"
if [ "$FAILURES" -eq 0 ]; then
  printf 'All selected jobs passed.\n'
  exit 0
fi
printf '%d step(s) failed:\n' "$FAILURES"
for label in "${FAILED_JOBS[@]}"; do
  printf '  - %s\n' "$label"
done
exit 1
