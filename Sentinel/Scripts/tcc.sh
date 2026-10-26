#!/bin/bash
#
# tcc.sh — inspect and modify macOS TCC (privacy) grants, with debug output.
#
# Replicates (and instruments) what Sentinel's Remove button runs: sqlite3
# against the user TCC database, sudo sqlite3 against the system one. Every
# command is printed before it runs, so a failure can be debugged from the
# output. The Terminal running this script needs Full Disk Access to read
# the user database; writes to the system database need root (the script
# re-runs itself under sudo automatically).
#
# Usage:
#   Scripts/tcc.sh show   <bundle-id>              list the client's rows in both TCC databases
#   Scripts/tcc.sh remove <bundle-id> <service>    delete the row (DB file backed up first)
#   Scripts/tcc.sh grant  <bundle-id> <service>    set auth_value=2 (allowed)
#   Scripts/tcc.sh deny   <bundle-id> <service>    set auth_value=0 (denied)
#
# <service> accepts the short form (SystemPolicyAllFiles) or the full one
# (kTCCServiceSystemPolicyAllFiles).
#
# NOTE: the SYSTEM database is SIP-protected — even root cannot write it
# while System Integrity Protection is enabled (reads still work; writes
# fail with "attempt to write a readonly database" / "Operation not
# permitted"). For system-DB changes, first try Apple's supported tool:
#   sudo tccutil reset SystemPolicyAllFiles <bundle-id>
# or disable SIP in Recovery (csrutil disable), run this script, then
# re-enable SIP. The per-user database has no such restriction.
#
# Examples (AnyTrans leftover Full Disk Access grant):
#   sudo Scripts/tcc.sh show   com.imobie.AnyTrans
#   sudo Scripts/tcc.sh remove com.imobie.AnyTrans SystemPolicyAllFiles
#   sudo Scripts/tcc.sh grant  com.imobie.AnyTrans SystemPolicyAllFiles
#
# Exit codes: 0 ok, 1 failed, 2 usage error. bash-3.2 compatible.

set -uo pipefail

PROG="$(basename "$0")"
SYS_DB="/Library/Application Support/com.apple.TCC/TCC.db"
SQLITE3="/usr/bin/sqlite3"
if [ ! -x "$SQLITE3" ]; then SQLITE3="$(command -v sqlite3 || true)"; fi
if [ -z "$SQLITE3" ]; then echo "FAIL: sqlite3 not found" >&2; exit 1; fi

usage() {
  cat <<EOF
Usage:
  $PROG show   <bundle-id>              list the client's rows in both TCC databases
  $PROG remove <bundle-id> <service>    delete the row (DB file backed up first)
  $PROG grant  <bundle-id> <service>    set auth_value=2 (allowed)
  $PROG deny   <bundle-id> <service>    set auth_value=0 (denied)

<service> accepts the short form (SystemPolicyAllFiles) or the full one
(kTCCServiceSystemPolicyAllFiles). Writes to the system database re-run this
script under sudo automatically. The Terminal running this script needs Full
Disk Access to read the user database.

Examples (AnyTrans leftover Full Disk Access grant):
  sudo $PROG show   com.imobie.AnyTrans
  sudo $PROG remove com.imobie.AnyTrans SystemPolicyAllFiles
  sudo $PROG grant  com.imobie.AnyTrans SystemPolicyAllFiles
EOF
  exit 2
}

die() { echo "FAIL: $*" >&2; exit 1; }

# --- resolve the real user's home even when running under sudo ----------------
user_home() {
  if [ -n "${SUDO_USER:-}" ]; then
    dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
  fi
}
HOME_DIR="$(user_home)"
: "${HOME_DIR:=${HOME:-/Users/$(id -un)}}"
USER_DB="$HOME_DIR/Library/Application Support/com.apple.TCC/TCC.db"

IDENT_RE='^[A-Za-z0-9 ._/+@=-]+$'
ident_ok() { [ -n "$1" ] && [[ "$1" =~ $IDENT_RE ]]; }

# read_rows <db> <sql> — prints rows; errors suppressed (caller checks output)
read_rows() { "$SQLITE3" -csv "$1" "$2" 2>/dev/null; }

diag() {
  echo "== diagnostics =="
  sw_vers 2>/dev/null | sed 's/^/  /'
  echo "  SIP: $(csrutil status 2>/dev/null | head -1)"
  echo "  running as: $(id)"
  echo "  sqlite3: $("$SQLITE3" --version 2>/dev/null)"
  echo "  tccd processes: $(pgrep -l tccd 2>/dev/null | tr '\n' ' ')"
  echo "  files (with BSD flags):"
  ls -lO "$USER_DB" 2>&1 | sed 's/^/    /'
  ls -lO "$SYS_DB" 2>&1 | sed 's/^/    /'
  echo "  directories (with BSD flags):"
  ls -ldO "$(dirname "$USER_DB")" 2>&1 | sed 's/^/    /'
  ls -ldO "$(dirname "$SYS_DB")" 2>&1 | sed 's/^/    /'
  echo
}

# sip_hint — what to do when the kernel refuses a system-DB write: the system
# TCC database is SIP-protected, so even root cannot write it while SIP is on.
# CLIENT must be set; uses the short service name for tccutil.
sip_hint() {
  local svc_short="${SERVICE#kTCCService}"
  echo "  -> the system TCC database is protected by System Integrity" >&2
  echo "     Protection: even root cannot write it while SIP is enabled." >&2
  echo "     Apple's supported remover works with SIP on — try it first:" >&2
  echo "       sudo tccutil reset $svc_short $CLIENT" >&2
  echo "     (for an uninstalled app this can fail; 'sudo tccutil reset" >&2
  echo "      $svc_short' wipes every app's row for that service — they" >&2
  echo "      re-prompt on next use)" >&2
  echo "     To write the database directly, disable SIP in Recovery OS" >&2
  echo "     (csrutil disable), run this script again, then re-enable SIP." >&2
}

# show_client <bundle-id> — dump the client's rows from both databases
show_client() {
  local client=$1 db out rc
  diag
  for db in "$USER_DB" "$SYS_DB"; do
    echo "== $db =="
    if [ ! -e "$db" ]; then echo "  (does not exist)"; echo; continue; fi
    out=$("$SQLITE3" -line "$db" "select service, client, auth_value, case auth_value when 0 then 'denied' when 1 then 'unknown' when 2 then 'ALLOWED' when 3 then 'limited' else '?' end as meaning, case when last_used_time is null or last_used_time = 0 then 'not reported' else datetime(last_used_time + 978307200, 'unixepoch') end as last_used from access where client='$client';" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
      case "$out" in
        *last_used_time*) # older TCC schema without the column
          out=$("$SQLITE3" -line "$db" "select service, client, auth_value, case auth_value when 0 then 'denied' when 1 then 'unknown' when 2 then 'ALLOWED' when 3 then 'limited' else '?' end as meaning from access where client='$client';" 2>&1)
          rc=$?
          ;;
      esac
    fi
    if [ $rc -ne 0 ]; then
      echo "  [unreadable] $out"
      echo "  hint: reading the TCC databases requires Full Disk Access — run"
      echo "        this from a Terminal that has it, or with sudo"
    elif [ -z "$out" ]; then
      echo "  (no rows for $client)"
    else
      echo "$out" | sed 's/^/  /'
    fi
    echo
  done
}

# find_db <client> <service> — echoes the DB path holding the row, or fails
find_db() {
  local client=$1 service=$2 db out unreadable=""
  for db in "$USER_DB" "$SYS_DB"; do
    if [ ! -e "$db" ]; then
      echo "note: $db does not exist (skipping)" >&2
      continue
    fi
    out=$(read_rows "$db" "select client from access where client='$client' and service='$service' limit 1;")
    if [ $? -eq 0 ]; then
      if [ -n "$out" ]; then echo "$db"; return 0; fi
    else
      unreadable="$unreadable $db"
    fi
  done
  if [ -n "$unreadable" ]; then
    echo "note: could not read:$unreadable" >&2
    echo "      (reading the TCC databases needs Full Disk Access — run with" >&2
    echo "       sudo, or from a Terminal that has Full Disk Access)" >&2
  fi
  return 1
}

# write_sql <db> <sql> — run a write, retrying once if the DB is busy/locked
write_sql() {
  local db=$1 sql=$2 out rc
  printf '  $ %s\n' "$SQLITE3 \"$db\" \"$sql\""
  out=$("$SQLITE3" "$db" "$sql" 2>&1)
  rc=$?
  if [ $rc -ne 0 ] && echo "$out" | grep -qi 'lock\|busy'; then
    echo "  -> database busy/locked; stopping tccd and retrying once..."
    killall tccd 2>/dev/null || true
    sleep 1
    out=$("$SQLITE3" "$db" "$sql" 2>&1)
    rc=$?
  fi
  if [ $rc -ne 0 ]; then
    echo "  sqlite3 error: $out" >&2
    case "$out" in
      *readonly* | *"Operation not permitted"* | *"authorization denied"*)
        if [ "$db" = "$SYS_DB" ]; then sip_hint; fi
        ;;
    esac
    return 1
  fi
  if [ -n "$out" ]; then echo "  sqlite3 said: $out"; fi
  return 0
}

# refresh_tccd — tccd caches grants; it re-reads TCC.db when it respawns
refresh_tccd() {
  if killall tccd 2>/dev/null; then
    echo "  tccd stopped — launchd restarts it immediately and it re-reads TCC.db"
  else
    echo "  (could not stop tccd — the change may only show after logout/restart)"
  fi
  sleep 1
}

# --- main ---------------------------------------------------------------------

if [ $# -lt 2 ]; then usage; fi
CMD="$1"
CLIENT="$2"
ident_ok "$CLIENT" || die "invalid client identifier: $CLIENT"

case "$CMD" in
  show)
    [ $# -eq 2 ] || usage
    show_client "$CLIENT"
    exit 0
    ;;
  remove | grant | deny)
    [ $# -eq 3 ] || usage
    SERVICE="$3"
    ;;
  *)
    usage
    ;;
esac

case "$SERVICE" in
  kTCCService*) ;;
  *) SERVICE="kTCCService$SERVICE" ;;
esac
ident_ok "$SERVICE" || die "invalid service identifier: $SERVICE"
WHERE="where client='$CLIENT' and service='$SERVICE'"

DB="$(find_db "$CLIENT" "$SERVICE")" ||
  die "no TCC row for $CLIENT / $SERVICE in either database — check the client/service spelling"

if [ "$DB" = "$SYS_DB" ] && [ "$(id -u)" -ne 0 ]; then
  echo "The row lives in the system database — root is required;"
  echo "re-running with sudo (administrator password will be asked for)..."
  exec sudo /bin/bash "$0" "$@"
fi

diag

case "$CMD" in
  remove)
    echo "== removing row =="
    echo "  row to delete:"
    read_rows "$DB" "select service, client, auth_value from access $WHERE;" | sed 's/^/    /'
    BAK="${DB}.sentinel-backup-$(date +%Y%m%d-%H%M%S)"
    CP_ERR="$(cp -p "$DB" "$BAK" 2>&1)" || {
      echo "  cp error: $CP_ERR" >&2
      if [ "$DB" = "$SYS_DB" ]; then sip_hint; fi
      die "could not back up $DB"
    }
    echo "  backup: $BAK"
    write_sql "$DB" "delete from access $WHERE;" || exit 1
    refresh_tccd
    if [ -n "$(read_rows "$DB" "select client from access $WHERE;")" ]; then
      die "row still present after delete — tccd may have re-created it. Check System Settings -> Privacy & Security -> Files and Folders; an MDM profile can also re-add grants (sudo profiles list). Restore from the backup if needed: sudo cp -p '$BAK' '$DB'"
    fi
    echo "PASS: removed $SERVICE grant for $CLIENT from $DB"
    ;;
  grant | deny)
    if [ "$CMD" = "grant" ]; then VAL=2; else VAL=0; fi
    echo "== setting $SERVICE for $CLIENT to auth_value=$VAL ($CMD) =="
    write_sql "$DB" "update access set auth_value=$VAL $WHERE;" || exit 1
    refresh_tccd
    GOT="$(read_rows "$DB" "select auth_value from access $WHERE;")"
    if [ "$GOT" != "$VAL" ]; then
      die "auth_value is '$GOT' after update (expected $VAL) — tccd may have overwritten it; re-run, or check System Settings -> Privacy & Security"
    fi
    if [ "$VAL" = "2" ]; then LABEL="allowed"; else LABEL="denied"; fi
    echo "PASS: $SERVICE for $CLIENT is now auth_value=$VAL ($LABEL) in $DB"
    ;;
esac
