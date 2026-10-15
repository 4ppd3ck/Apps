#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) BIN="./descale-linux-amd64" ;;
  Linux-aarch64|Linux-arm64) BIN="./descale-linux-arm64" ;;
  Darwin-x86_64) BIN="./descale-darwin-amd64" ;;
  Darwin-arm64) BIN="./descale-darwin-arm64" ;;
  *) echo "unsupported platform; build the Descale server with Go" >&2; exit 1 ;;
esac
if [ "$#" -gt 0 ]; then
  exec "$BIN" "$1"
else
  exec "$BIN"
fi
