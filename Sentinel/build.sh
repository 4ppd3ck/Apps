#!/bin/sh
# build.sh — build Sentinel.
#
#   ./build.sh                    host binary only — sentinel-<os>-<arch>[.exe]
#                                 beside go.mod, the name AppDeck launches and
#                                 imports (this is the dev/import loop)
#   ./build.sh --all              full cross-compile matrix into ./ and dist/
#                                 + SHA256SUMS (release artefacts)
#   ./build.sh darwin/arm64 …     build one or more specific os/arch targets
#   ./build.sh --host-only        legacy alias for the default
#
# Pure-Go stdlib, no cgo: every target builds with `go build` alone.
# Output layout mirrors AppScope Monitor:
#   ./sentinel-<os>-<arch>[.exe]     in-folder binaries (launcher's pick order)
#   ./dist/<os>-<arch>/sentinel[.exe]
#   ./dist/SHA256SUMS
set -eu

OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) : ;;
esac
HOST="${OS_NAME}-${ARCH}"
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
    --host-only) ;; # legacy alias — the default already builds host-only
    */*) ASKED="$ASKED $arg"; DIST=1 ;;
    *) echo "error: unknown option '$arg' (supported: --all, --host-only, <os>/<arch>…)" >&2; exit 1 ;;
  esac
done

build_one() {
  goos=${1%/*}; goarch=${1#*/}
  out="sentinel-${goos}-${goarch}"
  [ "$goos" = "windows" ] && out="${out}.exe"
  echo "== ${goos}/${goarch}"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    sh -c "if [ '$goarch' = 'arm' ]; then export GOARM=7; fi; \
           go build -trimpath -ldflags '-s -w' -o '$out' ."
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

# SHA256SUMS always reflects the current contents of dist/.
if [ "$DIST" = "1" ] && [ -n "$(find dist -type f -name 'sentinel*' -print -quit 2>/dev/null)" ]; then
  ( cd dist && find . -type f -name 'sentinel*' | sort | xargs shasum -a 256 ) > dist/SHA256SUMS
  echo "dist/ + SHA256SUMS written"
fi
echo "done."
