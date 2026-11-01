#!/bin/sh
# build.sh — build IPolice.
#
#   ./build.sh                    host binary only — wgrid[.exe] beside
#                                 go.mod, the name AppDeck launches/imports
#   ./build.sh --all              full cross-compile matrix into ./ and dist/
#                                 + SHA256SUMS (release artefacts)
#   ./build.sh darwin/arm64 …     build one or more specific os/arch targets
#
# Pure-Go stdlib, no cgo: every target builds with `go build` alone.
set -eu

# Package lives in cmd/wgrid; outputs land beside go.mod regardless of
# where the script is invoked from.
cd "$(dirname "$0")"

OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) : ;;
esac
HOST_T="${OS_NAME}/${ARCH}"

TARGETS="
darwin/amd64 darwin/arm64
windows/amd64 windows/arm64 windows/386
linux/amd64 linux/arm64 linux/386 linux/arm
freebsd/amd64 openbsd/amd64 netbsd/amd64
"

ALL=0
DIST=0
ASKED=""
for arg in "$@"; do
  case "$arg" in
    --all) ALL=1; DIST=1 ;;
    */*) ASKED="$ASKED $arg"; DIST=1 ;;
    *) echo "error: unknown option '$arg' (supported: --all, <os>/<arch>…)" >&2; exit 1 ;;
  esac
done

build_one() {
  goos=${1%/*}; goarch=${1#*/}
  if [ "$DIST" = "1" ]; then
    out="wgrid-${goos}-${goarch}"
  else
    out="wgrid"
  fi
  [ "$goos" = "windows" ] && out="${out}.exe"
  echo "== ${goos}/${goarch}"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    sh -c "if [ '$goarch' = 'arm' ]; then export GOARM=7; fi; \
           go build -trimpath -ldflags '-s -w' -o '$out' ./cmd/wgrid"
  if [ "$DIST" = "1" ]; then
    mkdir -p "dist/${goos}-${goarch}"
    cp "$out" "dist/${goos}-${goarch}/"
  fi
}

if [ "$ALL" = "1" ]; then
  for t in $TARGETS; do build_one "$t"; done
elif [ -n "$ASKED" ]; then
  for t in $ASKED; do build_one "$t"; done
else
  build_one "$HOST_T"
fi

if [ "$DIST" = "1" ] && [ -n "$(find dist -type f -name 'wgrid*' -print -quit 2>/dev/null)" ]; then
  ( cd dist && find . -type f -name 'wgrid*' | sort | xargs shasum -a 256 ) > dist/SHA256SUMS
  echo "dist/ + SHA256SUMS written"
fi
echo "done."
