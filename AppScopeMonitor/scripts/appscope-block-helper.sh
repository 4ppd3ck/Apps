#!/usr/bin/env bash
# appscope-block -- privileged helper used by AppScope Monitor to enforce
# connection/IP/app blocks. Installed root-owned by scripts/grant_block_*.sh
# and invoked (passwordless via sudo) ONLY with these commands:
#
#   appscope-block status
#   appscope-block add  ip  <ipv4> [port]
#   appscope-block del  ip  <ipv4> [port]
#   appscope-block add  app </path/to/executable>   (macOS only)
#   appscope-block del  app </path/to/executable>   (macOS only)
#
# All arguments are strictly validated (IPv4 octets, numeric ports, paths
# must exist and be absolute). The pf/iptables rules generated here can only
# DROP traffic -- this helper can never open, forward or translate anything.
set -u

STATE_DIR_MAC="/var/db/appscope-block"
STATE_DIR_LINUX="/var/lib/appscope-block"
STATE_MAC="$STATE_DIR_MAC/rules.conf"
STATE_LINUX="$STATE_DIR_LINUX/rules.conf"
ANCHOR="/etc/pf.anchors/appscope-block"
PFCONF="/etc/pf.conf"
SFW="/usr/libexec/ApplicationFirewall/socketfilterfw"

[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }

valid_ip() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o
  for o in ${ip//./ }; do
    [ "$o" -le 255 ] || return 1
  done
  return 0
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_path() {
  case "$1" in
    /*) [ -e "$1" ] ;;
    *) return 1 ;;
  esac
}

if [ "$(uname)" = "Darwin" ]; then
  STATE="$STATE_MAC"; STATE_DIR="$STATE_DIR_MAC"; OS="mac"
else
  STATE="$STATE_LINUX"; STATE_DIR="$STATE_DIR_LINUX"; OS="linux"
fi
mkdir -p "$STATE_DIR"
touch "$STATE"
chmod 600 "$STATE"

# ---------------------------------------------------------------- pf part --
regen_pf() {
  [ "$OS" = "mac" ] || return 0
  local tmp; tmp="$ANCHOR.tmp"
  mkdir -p "$(dirname "$ANCHOR")"
  : > "$tmp"
  local line t ip port
  while IFS='|' read -r t ip port; do
    [ "$t" = "ip" ] || continue
    if [ -n "$port" ]; then
      echo "block drop out proto tcp from any to $ip port $port" >> "$tmp"
      echo "block drop out proto udp from any to $ip port $port" >> "$tmp"
      echo "block drop in proto tcp from any to $ip port $port" >> "$tmp"
      echo "block drop in proto udp from any to $ip port $port" >> "$tmp"
    else
      echo "block drop from any to $ip" >> "$tmp"
      echo "block drop from $ip to any" >> "$tmp"
    fi
  done < "$STATE"
  mv "$tmp" "$ANCHOR"
  if ! grep -q 'anchor "appscope-block"' "$PFCONF" 2>/dev/null; then
    [ -f "$PFCONF" ] && cp -p "$PFCONF" "${PFCONF}.appscope.bak"
    printf '\n# added by AppScope Monitor (remove these 2 lines to uninstall)\nanchor "appscope-block"\nload anchor "appscope-block" from "%s"\n' "$ANCHOR" >> "$PFCONF"
  fi
  /sbin/pfctl -f "$PFCONF" >/dev/null 2>&1
  /sbin/pfctl -E >/dev/null 2>&1
}

# -------------------------------------------------------------- commands ---
cmd="${1:-}"; shift || true

case "$cmd" in
  status)
    n_ip=0
    if [ -s "$STATE" ]; then n_ip=$(grep -c '^ip|' "$STATE" || true); fi
    echo "no rules" >&2
    echo "active ip rules: $n_ip"
    exit 0 ;;

  add|del)
    action="$cmd"; what="${1:-}"; shift
    case "$what" in
      ip)
        ip="${1:-}"; port="${2:-}"
        valid_ip "$ip" || { echo "invalid ip: $ip"; exit 2; }
        [ -z "$port" ] || valid_port "$port" || { echo "invalid port: $port"; exit 2; }
        line="ip|$ip|$port"
        if [ "$action" = "add" ]; then
          grep -qxF "$line" "$STATE" || echo "$line" >> "$STATE"
        else
          grep -vxF "$line" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
        fi
        if [ "$OS" = "linux" ]; then
          IFS='|' read -r _ ip2 port2 <<<"$line"
          if [ "$action" = "add" ]; then
            if [ -n "$port2" ]; then
              /usr/sbin/iptables -I OUTPUT -p tcp -d "$ip2" --dport "$port2" -j DROP
              /usr/sbin/iptables -I INPUT  -p tcp -s "$ip2" --sport "$port2" -j DROP
            else
              /usr/sbin/iptables -I OUTPUT -d "$ip2" -j DROP
              /usr/sbin/iptables -I INPUT  -s "$ip2" -j DROP
            fi
          else
            if [ -n "$port2" ]; then
              /usr/sbin/iptables -D OUTPUT -p tcp -d "$ip2" --dport "$port2" -j DROP 2>/dev/null
              /usr/sbin/iptables -D INPUT  -p tcp -s "$ip2" --sport "$port2" -j DROP 2>/dev/null
            else
              /usr/sbin/iptables -D OUTPUT -d "$ip2" -j DROP 2>/dev/null
              /usr/sbin/iptables -D INPUT  -s "$ip2" -j DROP 2>/dev/null
            fi
          fi
        else
          regen_pf
        fi
        echo "ok" ;;

      app)
        path="${1:-}"
        if [ "$OS" != "mac" ]; then
          echo "app blocking not supported on this OS"; exit 3
        fi
        valid_path "$path" || { echo "invalid path: $path"; exit 2; }
        if [ "$action" = "add" ]; then
          "$SFW" setglobalstate on >/dev/null 2>&1
          if "$SFW" blockapp "$path" >/dev/null 2>&1; then
            grep -qxF "app|$path" "$STATE" || echo "app|$path" >> "$STATE"
            echo "ok"
          else
            echo "socketfilterfw refused $path"; exit 4
          fi
        else
          "$SFW" unblockapp "$path" >/dev/null 2>&1
          grep -vxF "app|$path" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
          echo "ok"
        fi ;;
      *)
        echo "unknown target: $what (use ip or app)"; exit 2 ;;
    esac ;;

  *)
    echo "usage: appscope-block {status|add|del} {ip <ipv4> [port]|app <path>}"
    exit 2 ;;
esac
