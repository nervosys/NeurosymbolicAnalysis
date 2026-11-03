#!/usr/bin/env bash
#
# Builds the `sda` command-line tool for one target and packages it with its
# licence, README and the third-party notices for that target:
#
#     tools/package-cli.sh x86_64-unknown-linux-gnu [out-dir]
#
# The archive is a .zip for Windows and a .tar.gz for everything else, named
# sda-<version>-<target>. The notices skip JavaScript, which the CLI does not
# ship, and are limited to what <target> builds; they still include the GUI's
# Rust crates for that platform, so they overstate rather than omit.
set -eu

fail() { printf '\nFAILED: %s\n' "$1" >&2; exit 1; }

[ $# -ge 1 ] || fail "usage: tools/package-cli.sh <target> [out-dir]"
target=$1
root=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$root/dist}

cargo build --manifest-path "$root/Cargo.toml" --release --locked -p sda-cli --target "$target" \
  || fail "cargo build of sda-cli for $target failed"

meta=$(cargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --no-deps)
target_dir=$(printf '%s' "$meta" | python -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])' | tr -d '\r')
version=$(printf '%s' "$meta" \
  | python -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "sda-cli"))' \
  | tr -d '\r')

ext=""
case "$target" in *windows*) ext=".exe" ;; esac
bin="$target_dir/$target/release/sda$ext"
[ -f "$bin" ] || fail "no sda binary at $bin after the build"

name="sda-$version-$target"
stage="$out/$name"
rm -rf "$stage"
mkdir -p "$stage"
cp "$bin" "$root/LICENSE" "$root/README.md" "$stage/"
python "$root/tools/third-party-notices.py" --skip-js --target "$target" "$stage/THIRD-PARTY-NOTICES.txt" \
  || fail "the third-party notices could not be generated"

format=gztar
case "$target" in *windows*) format=zip ;; esac
archive=$(python -c 'import shutil, sys; print(shutil.make_archive(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))' \
  "$out/$name" "$format" "$out" "$name" | tr -d '\r')
rm -rf "$stage"
printf 'packaged %s\n' "$archive"
