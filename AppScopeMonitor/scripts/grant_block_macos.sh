#!/bin/bash
# Grant AppScope Monitor permission to enforce connection/IP/app blocks
# without running the whole monitor as root (macOS).
#
#   ./scripts/grant_block_macos.sh            # install (asks password once)
#   ./scripts/grant_block_macos.sh --revoke   # remove helper + sudoers + rules
#
# What this installs:
#   /usr/local/libexec/appscope-block   root-owned validating helper.
#     - adds DROP-only pf rules (IP/port blocks) into a dedicated pf anchor
#     - toggles the application firewall for app blocks (socketfilterfw)
#   /etc/sudoers.d/appscope-block       NOPASSWD for the invoking user ONLY.
#
# The helper can only ADD or REMOVE block rules through strict argument
# validation -- it cannot open ports or change anything else.
#
# The script is written to run under three callers: `sudo sh ...` (invoker
# arrives via SUDO_USER), the dashboard's Grant button, which runs it through
# `osascript ... with administrator privileges` (runs as root with no
# SUDO_USER -- the console user is resolved from /dev/console), and plain
# root shells. In every case the sudoers entry is written for the human
# user the monitor actually runs as, never for root.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER_SRC="$DIR/appscope-block-helper.sh"
HELPER_DST="/usr/local/libexec/appscope-block"
SUDOERS="/etc/sudoers.d/appscope-block"
ANCHOR="/etc/pf.anchors/appscope-block"
PFCONF="/etc/pf.conf"

if [ "${1:-}" = "--revoke" ]; then
  # lift every applied rule FIRST, while the helper still exists: pf rules
  # live in the anchor (removed below), but application-firewall blocks
  # (socketfilterfw) persist until each one is explicitly unblocked
  if [ -f /var/db/appscope-block/rules.conf ]; then
    while IFS='|' read -r t a b; do
      case "$t" in
        ip) [ -n "$a" ] && sudo "$HELPER_DST" del ip "$a" "$b" >/dev/null 2>&1 || true ;;
        app) [ -n "$b" ] && sudo /usr/libexec/ApplicationFirewall/socketfilterfw \
              unblockapp "$b" >/dev/null 2>&1 || true ;;
      esac
    done < /var/db/appscope-block/rules.conf
  fi
  sudo rm -f "$SUDOERS" "$HELPER_DST"
  if [ -f "${PFCONF}.appscope.bak" ]; then
    sudo cp -p "${PFCONF}.appscope.bak" "$PFCONF"
    sudo rm -f "${PFCONF}.appscope.bak"
    sudo /sbin/pfctl -f "$PFCONF" >/dev/null 2>&1 || true
  fi
  sudo rm -rf /var/db/appscope-block "$ANCHOR" 2>/dev/null || true
  echo "Revoked: applied rules lifted; helper, sudoers entry and pf anchor removed."
  exit 0
fi

[ -f "$HELPER_SRC" ] || { echo "helper source not found: $HELPER_SRC"; exit 1; }

INVOKER="${SUDO_USER:-}"
if [ -z "$INVOKER" ] || [ "$INVOKER" = "root" ]; then
  INVOKER="$(stat -f%Su /dev/console 2>/dev/null || echo root)"
fi

TMP_S="$(mktemp)"; TMP_H="$(mktemp)"
trap 'rm -f "$TMP_S" "$TMP_H"' EXIT
cat > "$TMP_S" <<EOF
# AppScope Monitor: passwordless firewall BLOCK helper (drop-only).
# Remove with: sudo rm $SUDOERS   (see scripts/grant_block_macos.sh)
$INVOKER ALL=(root) NOPASSWD: $HELPER_DST
EOF
cp "$HELPER_SRC" "$TMP_H"
/usr/sbin/visudo -cf "$TMP_S"

sudo mkdir -p /usr/local/libexec
sudo install -m 0755 -o root -g wheel "$TMP_H" "$HELPER_DST"
sudo install -m 0440 -o root -g wheel "$TMP_S" "$SUDOERS"
"$HELPER_DST" status >/dev/null 2>&1 || true

echo "Installed:"
echo "  $HELPER_DST  (validating drop-only firewall helper)"
echo "  $SUDOERS     (passwordless for $INVOKER, that helper only)"
echo "Next: click 're-apply' on the Blocked panel (or restart the monitor)"
echo "to activate any queued blocks. Revoke: $0 --revoke"
