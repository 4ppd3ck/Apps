#!/bin/bash
# Grant (or revoke) AppScope Monitor's file collector one narrow permission:
# the right to run `/usr/bin/fs_usage` as root WITHOUT a password, so file
# tracing works while the monitor itself stays unprivileged (macOS).
#
#   ./scripts/grant_files_macos.sh           # grant  (asks password once)
#   ./scripts/grant_files_macos.sh --revoke  # remove the grant
#
# Scope of the grant: ONLY the /usr/bin/fs_usage binary (read-only filesystem
# tracing). The monitor's web dashboard and event database remain owned by
# your user. After granting, click the files-macos chip on the dashboard to
# activate tracing.
#
# Like the blocking grants, this runs under three callers: `sudo sh ...`
# (invoker via SUDO_USER), the dashboard's Grant flow via osascript's
# administrator dialog (runs as root -- the console user is resolved from
# /dev/console), and plain root shells. The sudoers entry is always written
# for the human user the monitor runs as, never for root.
set -euo pipefail

SUDOERS_FILE="/etc/sudoers.d/appscope-fsusage"

if [ "${1:-}" = "--revoke" ]; then
  if sudo rm -f "$SUDOERS_FILE"; then
    echo "Revoked: $SUDOERS_FILE removed. Click the files-macos chip to update status."
  else
    echo "Could not remove $SUDOERS_FILE" >&2
    exit 1
  fi
  exit 0
fi

INVOKER="${SUDO_USER:-}"
if [ -z "$INVOKER" ] || [ "$INVOKER" = "root" ]; then
  INVOKER="$(stat -f%Su /dev/console 2>/dev/null || echo root)"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<EOF
# AppScope Monitor: allow passwordless filesystem tracing (fs_usage only).
# Created by scripts/grant_files_macos.sh
# Remove with: sudo rm $SUDOERS_FILE
$INVOKER ALL=(root) NOPASSWD: /usr/bin/fs_usage
EOF

# Validate before installing so a bad rule can never lock sudo out.
/usr/sbin/visudo -cf "$TMP"

sudo install -m 0440 -o root -g wheel "$TMP" "$SUDOERS_FILE"
echo "Granted: $INVOKER may now run /usr/bin/fs_usage without a password."
echo "Next: click the files-macos chip on the dashboard (or restart the"
echo "monitor) and it should flip to active."
echo "Revoke anytime with: $0 --revoke"
