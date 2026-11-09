#!/bin/sh
# Installs kani for CI.
#
# `cargo kani setup` downloads the release bundle with a single `curl` and no
# retry, so one transient GitHub error (a 504 for example) fails the job. This
# script downloads the bundle itself, with retries, keeps it in a directory the
# workflow caches, and hands it to `cargo kani setup --use-local-bundle`.
#
# KANI_VERSION is required. KANI_BUNDLE_DIR defaults to ~/.cache/kani.
set -eu

version="${KANI_VERSION:?set KANI_VERSION, for example 0.68.0}"
dir="${KANI_BUNDLE_DIR:-$HOME/.cache/kani}"
name="kani-$version-x86_64-unknown-linux-gnu.tar.gz"
url="https://github.com/model-checking/kani/releases/download/kani-$version/$name"

cargo install --locked kani-verifier --version "$version"

mkdir -p "$dir"
if tar -tzf "$dir/$name" >/dev/null 2>&1; then
  echo "using the cached bundle $dir/$name"
else
  rm -f "$dir/$name"
  curl --fail --silent --show-error --location \
    --connect-timeout 30 --max-time 600 \
    --retry 8 --retry-delay 15 --retry-all-errors \
    --output "$dir/$name.part" "$url"
  tar -tzf "$dir/$name.part" >/dev/null
  mv "$dir/$name.part" "$dir/$name"
fi

cargo kani setup --use-local-bundle "$dir/$name"
