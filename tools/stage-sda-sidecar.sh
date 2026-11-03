#!/usr/bin/env bash
#
# Stages the `sda` command-line binary and the third-party notices where the
# installer build looks for them, so the NSIS installer ships both:
#
#     tools/stage-sda-sidecar.sh
#     cd gui && node_modules/.bin/tauri build --bundles nsis #       --config src-tauri/tauri.installer.conf.json
#
# Tauri 2 wants the file at gui/src-tauri/binaries/sda-<target-triple>[.exe]. It is
# a release-build product and not in git. tauri-build fails when the file is
# missing, so `externalBin` lives in tauri.installer.conf.json: `cargo test` in
# gui/src-tauri, which tools/verify.sh runs, must work on a fresh checkout.
#
set -eu

fail() { printf '\nFAILED: %s\n' "$1" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
triple=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$triple" ] || fail "rustc -vV reported no host triple"

ext=""
case "$triple" in *windows*) ext=".exe" ;; esac

cargo build --locked --manifest-path "$root/Cargo.toml" -p sda-cli --release \
  || fail "cargo build --locked of sda-cli failed"

# Cargo's answer, because a config file can move the target as well as the
# environment.
target_dir=$(cargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --no-deps \
  | python -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])' | tr -d '\r')
src="$target_dir/release/sda$ext"
[ -f "$src" ] || fail "no sda binary at $src after the build"

dest_dir="$root/gui/src-tauri/binaries"
mkdir -p "$dest_dir"
cp "$src" "$dest_dir/sda-$triple$ext"

python "$root/tools/third-party-notices.py" --target "$triple" "$dest_dir/THIRD-PARTY-NOTICES.txt" \
  || fail "the third-party notices could not be generated"

printf 'staged %s\n' "$dest_dir/sda-$triple$ext"
