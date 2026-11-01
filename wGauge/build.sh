#!/bin/sh
# SpaceLens — cross-compile for every supported OS/arch into dist/.
# stdlib-only + CGO off, so a plain Go toolchain is all this needs.
set -e
cd "$(dirname "$0")"

OUT=dist
mkdir -p "$OUT"
V=$(grep 'const Version' cmd/spacelens/server.go | awk '{print $NF}' | tr -d '"')
echo "SpaceLens $V → $OUT/"

for platform in \
  darwin/amd64 darwin/arm64 \
  linux/amd64 linux/arm64 linux/arm \
  windows/amd64 windows/arm64; do
  os=${platform%/*}
  arch=${platform#*/}
  bin="SpaceLens-$os-$arch"
  [ "$os" = "windows" ] && bin="$bin.exe"
  echo "  building $bin"
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
    -o "$OUT/$bin" ./cmd/spacelens
done
echo "done:"
ls -la "$OUT"
