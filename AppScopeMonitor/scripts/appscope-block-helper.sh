#!/usr/bin/env bash
# appscope-block -- privileged helper used by AppScope Monitor to enforce
# connection/IP/app/country blocks. Installed root-owned by
# scripts/grant_block_*.sh and invoked (passwordless via sudo) ONLY with
# these commands:
#
#   appscope-block status
#   appscope-block add  ip  <ipv4> [port]
#   appscope-block del  ip  <ipv4> [port]
#   appscope-block add  app </path/to/executable>   (macOS only)
#   appscope-block del  app </path/to/executable>   (macOS only)
#   appscope-block add  country <CC> <<CIDR list on stdin>
#   appscope-block del  country <CC>
#   appscope-block add  list <label> <<CIDR list on stdin>
#   appscope-block del  list <label>
#
# Country CIDR lists arrive on stdin (thousands of networks cannot ride
# argv). Every line is validated as IPv4 CIDR; loopback, RFC1918,
# link-local, multicast and reserved ranges are silently dropped — this
# helper can never block the machine's own subnets or the dashboard's
# loopback API, and every generated rule is DROP-only.
set -u

STATE_DIR_MAC="/var/db/appscope-block"
STATE_DIR_LINUX="/var/lib/appscope-block"
STATE_MAC="$STATE_DIR_MAC/rules.conf"
STATE_LINUX="$STATE_DIR_LINUX/rules.conf"
ANCHOR="/etc/pf.anchors/appscope-block"
ANCHOR_CIDRS="$ANCHOR.cidrs"
PFCONF="/etc/pf.conf"
SFW="/usr/libexec/ApplicationFirewall/socketfilterfw"
IPSET="appscope_block"

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

valid_cidr() {
  local cidr="$1" net prefix
  net="${cidr%%/*}"; prefix="${cidr##*/}"
  [ "$net" != "$cidr" ] || return 1
  valid_ip "$net" || return 1
  [[ "$prefix" =~ ^[0-9]+$ ]] && [ "$prefix" -ge 1 ] && [ "$prefix" -le 32 ]
}

# protected_cidr: ranges this helper must never block (loopback, private,
# link-local, 0/8, multicast, reserved, broadcast).
protected_cidr() {
  local net="${1%%/*}"
  local o1 o2
  IFS=. read -r o1 o2 _ _ <<<"$net"
  case "$o1" in
    0|10|127|224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239|240|241|242|243|244|245|246|247|248|249|250|251|252|253|254|255) return 0 ;;
    169) [ "$o2" = 254 ] && return 0 ;;
    172) [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 0 ;;
    192) [ "$o2" = 168 ] && return 0 ;;
    100) [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 0 ;;
  esac
  return 1
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
  # country blocks: one pf table fed by a generated CIDR file, so replacing
  # a country's ranges is a file rewrite + pfctl reload (atomic, and tables
  # stay fast at tens of thousands of entries)
  local tmp_c n_country=0
  tmp_c="$ANCHOR_CIDRS.tmp"
  : > "$tmp_c"
  while IFS='|' read -r t a b; do
    case "$t" in country|list) ;;
      *) continue ;;
    esac
    echo "$b" >> "$tmp_c"
    n_country=$((n_country+1))
  done < "$STATE"
  if [ "$n_country" -gt 0 ]; then
    mv "$tmp_c" "$ANCHOR_CIDRS"
    echo "table <appscope_block_cn> persist file \"$ANCHOR_CIDRS\"" >> "$tmp"
    echo "block drop from <appscope_block_cn> to any" >> "$tmp"
    echo "block drop from any to <appscope_block_cn>" >> "$tmp"
  else
    rm -f "$tmp_c" "$ANCHOR_CIDRS"
  fi
  mv "$tmp" "$ANCHOR"
  if ! grep -q 'anchor "appscope-block"' "$PFCONF" 2>/dev/null; then
    [ -f "$PFCONF" ] && cp -p "$PFCONF" "${PFCONF}.appscope.bak"
    printf '\n# added by AppScope Monitor (remove these 2 lines to uninstall)\nanchor "appscope-block"\nload anchor "appscope-block" from "%s"\n' "$ANCHOR" >> "$PFCONF"
  fi
  /sbin/pfctl -f "$PFCONF" >/dev/null 2>&1
  /sbin/pfctl -E >/dev/null 2>&1
}

# -------------------------------------------------------- linux ipset part --
regen_linux_country() {
  [ "$OS" = "linux" ] || return 0
  command -v /usr/sbin/ipset >/dev/null 2>&1 || { echo "ipset not available"; return 1; }
  /usr/sbin/ipset -exist create "$IPSET" hash:net
  /usr/sbin/ipset flush "$IPSET"
  local n=0 t a cidr
  while IFS='|' read -r t a cidr; do
    case "$t" in country|list) ;;
      *) continue ;;
    esac
    /usr/sbin/ipset add "$IPSET" "$cidr" 2>/dev/null && n=$((n+1))
  done < "$STATE"
  if [ "$n" -gt 0 ]; then
    /usr/sbin/iptables -C OUTPUT -m set --match-set "$IPSET" dst -j DROP 2>/dev/null || \
      /usr/sbin/iptables -I OUTPUT -m set --match-set "$IPSET" dst -j DROP
    /usr/sbin/iptables -C INPUT -m set --match-set "$IPSET" src -j DROP 2>/dev/null || \
      /usr/sbin/iptables -I INPUT -m set --match-set "$IPSET" src -j DROP
  else
    /usr/sbin/iptables -D OUTPUT -m set --match-set "$IPSET" dst -j DROP 2>/dev/null
    /usr/sbin/iptables -D INPUT -m set --match-set "$IPSET" src -j DROP 2>/dev/null
    /usr/sbin/ipset destroy "$IPSET" 2>/dev/null
  fi
  return 0
}

# -------------------------------------------------------------- commands ---
cmd="${1:-}"; shift || true

case "$cmd" in
  status)
    n_ip=0; n_cidr=0
    if [ -s "$STATE" ]; then
      n_ip=$(grep -c '^ip|' "$STATE" || true)
      n_cidr=$(grep -cE '^(country|list)\|' "$STATE" || true)
    fi
    echo "no rules" >&2
    echo "active ip rules: $n_ip"
    echo "active country cidrs: $n_cidr"
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

      country)
        cc="${1:-}"
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || { echo "invalid country code: $cc"; exit 2; }
        cc="$(printf '%s' "$cc" | tr '[:lower:]' '[:upper:]')"
        if [ "$action" = "add" ]; then
          # CIDR list on stdin, one range per line; junk and protected
          # ranges are skipped, everything else is persisted per country
          n_added=0
          while IFS= read -r line; do
            line="${line//[[:space:]]/}"
            [ -n "$line" ] || continue
            valid_cidr "$line" || continue
            protected_cidr "$line" && continue
            grep -qxF "country|$cc|$line" "$STATE" || echo "country|$cc|$line" >> "$STATE"
            n_added=$((n_added+1))
          done
          if [ "$OS" = "linux" ]; then regen_linux_country; else regen_pf; fi
          echo "ok: $n_added cidrs for $cc"
        else
          grep -v "^country|${cc}|" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
          if [ "$OS" = "linux" ]; then regen_linux_country; else regen_pf; fi
          echo "ok"
        fi ;;
      list)
        label="${1:-}"
        [[ "$label" =~ ^[a-z0-9_-]{1,32}$ ]] || { echo "invalid list label: $label"; exit 2; }
        if [ "$action" = "add" ]; then
          n_added=0
          while IFS= read -r line; do
            line="${line//[[:space:]]/}"
            [ -n "$line" ] || continue
            valid_cidr "$line" || continue
            protected_cidr "$line" && continue
            grep -qxF "list|$label|$line" "$STATE" || echo "list|$label|$line" >> "$STATE"
            n_added=$((n_added+1))
          done
          if [ "$OS" = "linux" ]; then regen_linux_country; else regen_pf; fi
          echo "ok: $n_added cidrs for list $label"
        else
          grep -v "^list|${label}|" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
          if [ "$OS" = "linux" ]; then regen_linux_country; else regen_pf; fi
          echo "ok"
        fi ;;
      *)
        echo "unknown target: $what (use ip, app, country or list)"; exit 2 ;;
    esac ;;

  *)
    echo "usage: appscope-block {status|add|del} {ip <ipv4> [port]|app <path>|country <CC>|list <label>} < CIDR list"
    exit 2 ;;
esac
