#!/bin/sh
# Build release binaries for every supported OS/arch into dist/.
# Each dist/monitor-<os>-<arch>/ folder holds the binary plus the web/
# dashboard assets it serves; SHA256SUMS lists all binaries.
#
# Requires only the Go toolchain: all targets cross-compile (pure Go,
# no cgo). Run from anywhere: ./build.sh
set -e
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "error: Go toolchain (go 1.27+) is required" >&2
    exit 1
fi

echo "== host tests =="
go test ./...

rm -rf dist
mkdir -p dist

# build <os> <arch> [goarm]
build() {
    os=$1
    arch=$2
    dir="dist/monitor-$os-$arch"
    mkdir -p "$dir"
    if [ "$os" = "windows" ]; then
        bin="$dir/monitor.exe"
    else
        bin="$dir/monitor"
    fi
    if [ "$#" -ge 3 ]; then
        GOARM=$3 GOOS=$os GOARCH=$arch go build -o "$bin" ./cmd/monitor
    else
        GOOS=$os GOARCH=$arch go build -o "$bin" ./cmd/monitor
    fi
    cp -r web "$dir/web"
    echo "built $bin"
}

#              OS        ARCH   (GOARM)
build          windows   amd64
build          windows   arm64
build          windows   386
build          linux     amd64
build          linux     arm64
build          linux     386
build          linux     arm    7   # 32-bit ARM: modernc.org/libc needs ARMv7
build          darwin    amd64
build          darwin    arm64
build          freebsd   amd64
build          openbsd   amd64
build          netbsd    amd64

echo "== checksums =="
if command -v sha256sum >/dev/null 2>&1; then
    ( cd dist && find . -type f -exec sha256sum {} + ) > dist/SHA256SUMS
else
    ( cd dist && find . -type f -exec shasum -a 256 {} + ) > dist/SHA256SUMS
fi

echo "done: dist/ (binaries + web assets + SHA256SUMS)"
