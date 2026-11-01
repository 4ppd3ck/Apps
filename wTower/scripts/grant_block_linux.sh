#!/bin/bash
# Grant AppScope Monitor permission to enforce IP/connection blocks without
# running the whole monitor as root (Linux, iptables).
#
#   ./scripts/grant_block_linux.sh            # install (asks password once)
#   ./scripts/grant_block_linux.sh --revoke   # remove helper + sudoers + rules
#
# Installs /usr/local/bin/appscope-block (root-owned validating helper that
# only adds/removes DROP rules) and a sudoers entry for it.
#
# Like the macOS script, this runs under three callers: `sudo sh ...`
# (invoker via SUDO_USER), the dashboard's Grant button via `pkexec`
# (invoker via PKEXEC_UID -- resolved with getent), and plain root shells.
# The sudoers entry is always written for the human user the monitor runs
# as, never for root.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER_SRC="$DIR/appscope-block-helper.sh"
HELPER_DST="/usr/local/bin/appscope-block"
SUDOERS="/etc/sudoers.d/appscope-block"

if [ "${1:-}" = "--revoke" ]; then
  # lift every applied DROP rule first, while the helper still exists
  if [ -f /var/lib/appscope-block/rules.conf ]; then
    while IFS='|' read -r t a b; do
      [ "$t" = "ip" ] && [ -n "$a" ] && \
        sudo "$HELPER_DST" del ip "$a" "$b" >/dev/null 2>&1 || true
    done < /var/lib/appscope-block/rules.conf
  fi
  # country blocks live in one ipset + two -m set rules: tear those down
  sudo /usr/sbin/iptables -D OUTPUT -m set --match-set appscope_block dst -j DROP 2>/dev/null || true
  sudo /usr/sbin/iptables -D INPUT -m set --match-set appscope_block src -j DROP 2>/dev/null || true
  sudo /usr/sbin/ipset destroy appscope_block 2>/dev/null || true
  sudo rm -f "$SUDOERS" "$HELPER_DST"
  sudo rm -rf /var/lib/appscope-block 2>/dev/null || true
  echo "Revoked: applied rules lifted; helper, sudoers entry and iptables rules removed."
  exit 0
fi

[ -f "$HELPER_SRC" ] || { echo "helper source not found: $HELPER_SRC"; exit 1; }

INVOKER="${SUDO_USER:-}"
if [ -z "$INVOKER" ] || [ "$INVOKER" = "root" ]; then
  if [ -n "${PKEXEC_UID:-}" ]; then
    INVOKER="$(getent passwd "$PKEXEC_UID" 2>/dev/null | cut -d: -f1 || true)"
  fi
fi
if [ -z "$INVOKER" ] || [ "$INVOKER" = "root" ]; then
  INVOKER="root"
fi

TMP_S="$(mktemp)"; TMP_H="$(mktemp)"
trap 'rm -f "$TMP_S" "$TMP_H"' EXIT
cat > "$TMP_S" <<EOF
# AppScope Monitor: passwordless firewall BLOCK helper (drop-only).
# Remove with: sudo rm $SUDOERS   (see scripts/grant_block_linux.sh)
$INVOKER ALL=(root) NOPASSWD: $HELPER_DST
EOF
cp "$HELPER_SRC" "$TMP_H"
visudo -cf "$TMP_S" >/dev/null || visudo -c -f "$TMP_S" >/dev/null

sudo mkdir -p /usr/local/bin
sudo install -m 0755 -o root -g root "$TMP_H" "$HELPER_DST"
sudo install -m 0440 -o root -g root "$TMP_S" "$SUDOERS"
"$HELPER_DST" status >/dev/null 2>&1 || true

echo "Installed:"
echo "  $HELPER_DST  (validating drop-only iptables helper)"
echo "  $SUDOERS     (passwordless for $INVOKER, that helper only)"
echo "Next: click 're-apply' on the Blocked panel (or restart the monitor)"
echo "to activate any queued blocks. Revoke: $0 --revoke"
