#!/usr/bin/env bash
#
# Copies this repository keeps in step by hand, checked so they cannot
# drift. Run from anywhere; the CI lint job and scripts/ci-local.sh call it.
#
#   1. Toolchain pins. rust-toolchain.toml outranks every workflow's
#      `toolchain:` input (dtolnay/rust-toolchain only sets rustup's
#      default), so an input naming another channel is a pin that does
#      nothing. Allowed: the file's channel, or an `env.*` expression - the
#      fuzz job's dated nightly and the MSRV job's RUSTUP_TOOLCHAIN, which
#      must equal Cargo.toml's rust-version (1.99 -> 1.99.0).
#   2. The fuzz harness's lint profile. fuzz/ is its own workspace
#      (cargo-fuzz), so it cannot inherit the root's [workspace.lints]; it
#      carries a verbatim copy, from the first [workspace.lints.*] header to
#      the end of the file.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

status=0
channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
msrv=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml \
  | awk -F. 'NF == 2 { print $0 ".0"; next } { print }')
if [ -z "$channel" ] || [ -z "$msrv" ]; then
  echo "cannot read the channel from rust-toolchain.toml or rust-version from Cargo.toml"
  exit 1
fi
toolchain_lines=$({ grep -rnE '^[[:space:]]*toolchain:' .github/workflows/ || true; })
if [ -z "$toolchain_lines" ]; then
  echo "no toolchain: inputs in .github/workflows/ - nothing was checked"
  status=1
fi
bad=$(printf '%s\n' "$toolchain_lines" | awk -v ch="$channel" 'NF {
      v = $0
      sub(/^[^:]+:[0-9]+:[[:space:]]*toolchain:[[:space:]]*/, "", v)
      sub(/[[:space:]]+#.*$/, "", v)
      gsub(/"/, "", v)
      if (v != ch && v !~ /^[$][{][{] env[.][A-Z_]+ [}][}]$/) print
    }')
msrv_lines=$({ grep -rnE '^[[:space:]]*RUSTUP_TOOLCHAIN:' .github/workflows/ || true; })
bad_msrv=$(printf '%s\n' "$msrv_lines" | awk -v m="$msrv" 'NF {
      v = $0
      sub(/^[^:]+:[0-9]+:[[:space:]]*RUSTUP_TOOLCHAIN:[[:space:]]*/, "", v)
      sub(/[[:space:]]+#.*$/, "", v)
      gsub(/"/, "", v)
      if (v != m) print
    }')
if [ -n "$bad" ]; then
  printf 'workflow toolchain inputs that are not rust-toolchain.toml'"'"'s channel (%s):\n%s\n' "$channel" "$bad"
  status=1
fi
if [ -z "$msrv_lines" ]; then
  echo "no RUSTUP_TOOLCHAIN in .github/workflows/: the MSRV job is missing"
  status=1
elif [ -n "$bad_msrv" ]; then
  printf 'RUSTUP_TOOLCHAIN values that are not rust-version (%s):\n%s\n' "$msrv" "$bad_msrv"
  status=1
fi

root_lints=$(sed -n '/^\[workspace\.lints\./,$p' Cargo.toml)
fuzz_lints=$(sed -n '/^\[workspace\.lints\./,$p' fuzz/Cargo.toml)
if [ -z "$root_lints" ]; then
  echo "no [workspace.lints.*] tables in Cargo.toml - nothing was compared"
  status=1
elif ! diff <(printf '%s\n' "$root_lints") <(printf '%s\n' "$fuzz_lints"); then
  echo "fuzz/Cargo.toml's lint tables differ from Cargo.toml's (diff above)"
  status=1
fi
if ! grep -A1 -x '\[lints\]' fuzz/Cargo.toml | grep -qx 'workspace = true'; then
  echo "fuzz/Cargo.toml does not opt in with [lints] workspace = true"
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "drift check passed: toolchain pins $channel, MSRV job $msrv, fuzz lint table = root"
fi
exit "$status"
