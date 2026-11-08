#!/usr/bin/env bash
# appscope-block -- privileged helper used by AppScope Monitor to enforce
# connection/IP/app/country blocks. Installed root-owned by
# scripts/grant_block_*.sh and invoked (passwordless via sudo) ONLY with
# these commands:
#
#   appscope-block status
#   appscope-block version            (protocol version, no root needed)
#   appscope-block add  ip  <ipv4> [port]
#   appscope-block del  ip  <ipv4> [port]
#   appscope-block add  app </path/to/executable>   (macOS only)
#   appscope-block del  app </path/to/executable>   (macOS only)
#   appscope-block add  country <CC> <<CIDR list on stdin>
#   appscope-block del  country <CC>
#   appscope-block add  list <label> <<CIDR list on stdin>
#   appscope-block del  list <label>
#   appscope-block add  allowip <ipv4> [port]      (allow = exception that
#   appscope-block del  allowip <ipv4> [port]       overrides block rules)
#   appscope-block add  allowlist <label> <<CIDR list on stdin>
#   appscope-block del  allowlist <label>
#   appscope-block dns  on|off   (macOS: fixed pf rdr; Linux: iptables
#                                REDIRECT — loopback port 53 into the
#                                monitor's DNS shield on 127.0.0.1:5333)
#
# Country CIDR lists arrive on stdin (thousands of networks cannot ride
# argv). Every line is validated as IPv4 CIDR; loopback, RFC1918,
# link-local, multicast and reserved ranges are silently dropped — this
# helper can never block the machine's own subnets or the dashboard's
# loopback API, and every generated block rule is DROP-only. Allow rules
# generate pass rules instead: they only ever PERMIT, so they are not
# filtered against the protected ranges (and an allow for a private range
# is a harmless no-op — blocks can never target those anyway).
set -u

STATE_DIR_MAC="/var/db/appscope-block"
STATE_DIR_LINUX="/var/lib/appscope-block"
STATE_MAC="$STATE_DIR_MAC/rules.conf"
STATE_LINUX="$STATE_DIR_LINUX/rules.conf"
ANCHOR="/etc/pf.anchors/appscope-block"
ANCHOR_CIDRS="$ANCHOR.cidrs"
ANCHOR_ALLOW="$ANCHOR.allow"
PFCONF="/etc/pf.conf"
SFW="/usr/libexec/ApplicationFirewall/socketfilterfw"
IPSET="appscope_block"
IPSET_ALLOW="appscope_allow"
ALLOW_CHAIN="appscope_allow"

# protocol version: bumped when a verb the monitor gates on is added
# (2 = allowip/allowlist, 3 = dns manage: record + restore system DNS).
# `version` answers before the root check so the
# unelevated monitor can probe the installed helper.
HELPER_VERSION=3

[ "${1:-}" = "version" ] && { echo "$HELPER_VERSION"; exit 0; }

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

# merge_cidrs <prefix> <protected:1|0> — validate stdin CIDRs and append the
# ones not already in STATE as "<prefix>|<cidr>" lines, in ONE awk pass. The
# old loop ran a `grep` process per candidate line against the ever-growing
# STATE (16k+ lines): thousands of ranges made every startup O(N²) — tens of
# seconds of dashboard downtime before the port ever opened. n_added counts
# the valid input lines (dups included), matching the old loop's count.
merge_cidrs() {
  local prefix="$1" protected="$2" line
  [ -f "$STATE" ] || : > "$STATE"
  local tmp_in
  tmp_in=$(mktemp "$STATE_DIR/mergein.XXXXXX") || return 1
  while IFS= read -r line; do
    line="${line//[[:space:]]/}"
    [ -n "$line" ] || continue
    valid_cidr "$line" || continue
    [ "$protected" = "1" ] && protected_cidr "$line" && continue
    echo "${prefix}|${line}"
  done > "$tmp_in"
  n_added=$(wc -l < "$tmp_in" | tr -d ' ')
  # append only candidates not already present (in STATE or earlier in this
  # input — the old grep-per-line loop deduped both); FILENAME==ARGV[1] (not
  # NR==FNR) so an empty STATE still registers its (zero) lines
  awk 'FILENAME==ARGV[1] { seen[$0]=1; next } !seen[$0] { seen[$0]=1; print }' \
    "$STATE" "$tmp_in" >> "$STATE"
  rm -f "$tmp_in"
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
  # DNS shield: one fixed rdr pair while a "dns|on" line exists in STATE —
  # loopback port 53 (the system resolver) into the monitor's filter
  # listener on 127.0.0.1:5333. The addresses and ports are constants of
  # this helper; nothing user-supplied ever reaches the translation rules.
  if grep -q '^dns|' "$STATE"; then
    echo 'rdr pass on lo0 inet proto udp from any to 127.0.0.1 port 53 -> 127.0.0.1 port 5333' >> "$tmp"
    echo 'rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 53 -> 127.0.0.1 port 5333' >> "$tmp"
  fi
  # allow rules: pass-quick lines emitted AFTER every block rule. pf
  # evaluates top-down with last-match-wins, and `quick` stops the search
  # at the first hit — so an allow for one IP carves it out of any broader
  # block (e.g. a country CIDR set) no matter where both rules live.
  local n_allowip=0
  while IFS='|' read -r t ip port; do
    [ "$t" = "allowip" ] || continue
    n_allowip=$((n_allowip+1))
    if [ -n "$port" ]; then
      echo "pass quick out proto tcp from any to $ip port $port" >> "$tmp"
      echo "pass quick out proto udp from any to $ip port $port" >> "$tmp"
      echo "pass quick in proto tcp from any to $ip port $port" >> "$tmp"
      echo "pass quick in proto udp from any to $ip port $port" >> "$tmp"
    else
      echo "pass quick from any to $ip" >> "$tmp"
      echo "pass quick from $ip to any" >> "$tmp"
    fi
  done < "$STATE"
  local tmp_a n_allowcidr=0
  tmp_a="$ANCHOR_ALLOW.tmp"
  : > "$tmp_a"
  while IFS='|' read -r t a b; do
    [ "$t" = "allowlist" ] || continue
    echo "$b" >> "$tmp_a"
    n_allowcidr=$((n_allowcidr+1))
  done < "$STATE"
  if [ "$n_allowcidr" -gt 0 ]; then
    mv "$tmp_a" "$ANCHOR_ALLOW"
    echo "table <appscope_allow> persist file \"$ANCHOR_ALLOW\"" >> "$tmp"
    echo "pass quick from <appscope_allow> to any" >> "$tmp"
    echo "pass quick from any to <appscope_allow>" >> "$tmp"
  else
    rm -f "$tmp_a" "$ANCHOR_ALLOW"
  fi
  mv "$tmp" "$ANCHOR"
  if ! grep -q 'anchor "appscope-block"' "$PFCONF" 2>/dev/null; then
    [ -f "$PFCONF" ] && cp -p "$PFCONF" "${PFCONF}.appscope.bak"
    printf '\n# added by AppScope Monitor (remove these 2 lines to uninstall)\nanchor "appscope-block"\nload anchor "appscope-block" from "%s"\n' "$ANCHOR" >> "$PFCONF"
  fi
  ensure_rdr_anchor
  /sbin/pfctl -f "$PFCONF" >/dev/null 2>&1
  /sbin/pfctl -E >/dev/null 2>&1
}

# ensure_rdr_anchor makes pf.conf evaluate the anchor's translation rules:
# rdr lines inside a plain `anchor` are dead — they need an rdr-anchor
# directive, and pf.conf must keep every translation rule before every
# filter rule. So the rdr-anchor is inserted (once) right before the first
# filter anchor line. The load directive is order-independent; the anchor's
# single file feeds both the rdr-anchor and the anchor.
ensure_rdr_anchor() {
  [ "$OS" = "mac" ] || return 0
  [ -f "$PFCONF" ] || return 0
  grep -q 'rdr-anchor "appscope-block"' "$PFCONF" && return 0
  cp -p "$PFCONF" "${PFCONF}.appscope.bak" 2>/dev/null || true
  if grep -q '^anchor ' "$PFCONF"; then
    awk 'BEGIN{done=0} !done && /^anchor /{print "rdr-anchor \"appscope-block\""; done=1} {print}' \
      "$PFCONF" > "$PFCONF.tmp" && mv "$PFCONF.tmp" "$PFCONF"
  else
    printf 'rdr-anchor "appscope-block"\n' >> "$PFCONF"
  fi
}

# -------------------------------------------------------- linux ipset part --

# ensure_allow_chain creates the allow chain and its OUTPUT/INPUT jumps
# (idempotent). The jump is inserted at position 1 so it is evaluated
# before the DROP rules inserted the same way.
ensure_allow_chain() {
  [ "$OS" = "linux" ] || return 0
  /usr/sbin/iptables -N "$ALLOW_CHAIN" 2>/dev/null || true
  local dir
  for dir in OUTPUT INPUT; do
    /usr/sbin/iptables -C "$dir" -j "$ALLOW_CHAIN" 2>/dev/null || \
      /usr/sbin/iptables -I "$dir" 1 -j "$ALLOW_CHAIN"
  done
}

# reanchor_allow_jump keeps the allow chain's jump rules ABOVE every DROP
# rule in OUTPUT/INPUT: block rules insert themselves at position 1 too, so
# after each block insertion the jump must be moved back to the top or an
# allow exception would silently stop winning. No-op without allow rules.
reanchor_allow_jump() {
  [ "$OS" = "linux" ] || return 0
  grep -qE '^(allowip|allowlist)\|' "$STATE" || return 0
  local dir line jump_idx drop_idx i
  for dir in OUTPUT INPUT; do
    if ! /usr/sbin/iptables -C "$dir" -j "$ALLOW_CHAIN" 2>/dev/null; then
      /usr/sbin/iptables -I "$dir" 1 -j "$ALLOW_CHAIN"
      continue
    fi
    jump_idx=0; drop_idx=0; i=0
    while IFS= read -r line; do
      case "$line" in
        "-A $dir "*)
          i=$((i+1))
          case "$line" in
            *"-j $ALLOW_CHAIN") [ "$jump_idx" = 0 ] && jump_idx=$i ;;
            *"-j DROP")         [ "$drop_idx" = 0 ] && drop_idx=$i ;;
          esac ;;
      esac
    done < <(/usr/sbin/iptables -S "$dir" 2>/dev/null)
    if [ "$jump_idx" != 0 ] && [ "$drop_idx" != 0 ] && [ "$jump_idx" -gt "$drop_idx" ]; then
      /usr/sbin/iptables -D "$dir" -j "$ALLOW_CHAIN"
      /usr/sbin/iptables -I "$dir" 1 -j "$ALLOW_CHAIN"
    fi
  done
}

# regen_linux_allow rebuilds the appscope_allow ipset from every allowlist
# state line and keeps the matching ACCEPT rules inside the allow chain.
# allow-ip ACCEPT rules live in the same chain (they do not collide: the
# set rules match -m set, the ip rules match plain addresses).
regen_linux_allow() {
  [ "$OS" = "linux" ] || return 0
  command -v /usr/sbin/ipset >/dev/null 2>&1 || { echo "ipset not available"; return 1; }
  ensure_allow_chain
  /usr/sbin/ipset -exist create "$IPSET_ALLOW" hash:net
  /usr/sbin/ipset flush "$IPSET_ALLOW"
  local n=0 t a cidr
  while IFS='|' read -r t a cidr; do
    [ "$t" = "allowlist" ] || continue
    /usr/sbin/ipset add "$IPSET_ALLOW" "$cidr" 2>/dev/null && n=$((n+1))
  done < "$STATE"
  if [ "$n" -gt 0 ]; then
    /usr/sbin/iptables -C "$ALLOW_CHAIN" -m set --match-set "$IPSET_ALLOW" dst -j ACCEPT 2>/dev/null || \
      /usr/sbin/iptables -I "$ALLOW_CHAIN" -m set --match-set "$IPSET_ALLOW" dst -j ACCEPT
    /usr/sbin/iptables -C "$ALLOW_CHAIN" -m set --match-set "$IPSET_ALLOW" src -j ACCEPT 2>/dev/null || \
      /usr/sbin/iptables -I "$ALLOW_CHAIN" -m set --match-set "$IPSET_ALLOW" src -j ACCEPT
  else
    /usr/sbin/iptables -D "$ALLOW_CHAIN" -m set --match-set "$IPSET_ALLOW" dst -j ACCEPT 2>/dev/null
    /usr/sbin/iptables -D "$ALLOW_CHAIN" -m set --match-set "$IPSET_ALLOW" src -j ACCEPT 2>/dev/null
    /usr/sbin/ipset destroy "$IPSET_ALLOW" 2>/dev/null
  fi
  # nothing allowed at all anymore: tear the whole allow apparatus down
  if ! grep -qE '^(allowip|allowlist)\|' "$STATE"; then
    local dir
    for dir in OUTPUT INPUT; do
      /usr/sbin/iptables -D "$dir" -j "$ALLOW_CHAIN" 2>/dev/null
    done
    /usr/sbin/iptables -F "$ALLOW_CHAIN" 2>/dev/null
    /usr/sbin/iptables -X "$ALLOW_CHAIN" 2>/dev/null
  fi
  reanchor_allow_jump
  return 0
}

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
  # a DROP that was just inserted at position 1 may now sit above the
  # allow chain's jump — restore the allow-first order
  reanchor_allow_jump
  return 0
}

# set_dns_state_mac flips the fixed loopback-53 rdr (see regen_pf), applies
# managed system-DNS changes when asked, and flushes the resolver cache — a
# stale mDNSResponder cache would keep serving blocked domains until the
# TTLs run out.
set_dns_state_mac() {
  local val="$1" manage="${2:-}"
  if [ "$val" = "on" ]; then
    grep -qxF 'dns|on|' "$STATE" || echo 'dns|on|' >> "$STATE"
    if [ "$manage" = "manage" ]; then
      manage_dns_on
    fi
  else
    manage_dns_off
    grep -v '^dns|' "$STATE" > "$STATE.new" 2>/dev/null || true
    mv "$STATE.new" "$STATE"
  fi
  regen_pf
  dscacheutil -flushcache 2>/dev/null || true
  killall -HUP mDNSResponder 2>/dev/null || true
  return 0
}

# manage_dns_on records every network service's current DNS servers as
# dnsif|<service>|<old> STATE lines ("empty" = served by DHCP) and points
# them at the shield (127.0.0.1) — the one-click half of managed routing,
# so the user never edits System Settings by hand. getdnsservers prints one
# server per line; they are joined with spaces because setdnsservers takes
# the servers as separate arguments on restore. Services that error
# (dummy/VPN entries) are skipped. Services already recorded keep their
# original restore value.
manage_dns_on() {
  networksetup -listallnetworkservices 2>/dev/null | tail -n +2 |
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    case "$svc" in \**) continue ;; esac # disabled services carry an asterisk
    cur=$(networksetup -getdnsservers "$svc" 2>/dev/null) || continue
    case "$cur" in
      "There aren't any DNS Servers set"*) old="empty" ;;
      *) old=$(printf '%s' "$cur" | tr '\n' ' ') ;;
    esac
    if networksetup -setdnsservers "$svc" 127.0.0.1 2>/dev/null; then
      grep -qF "dnsif|$svc|" "$STATE" || echo "dnsif|$svc|$old" >> "$STATE"
    fi
  done
  return 0
}

# manage_dns_off restores exactly what manage_dns_on recorded and strips the
# dnsif records. No dnsif lines (manual route, or nothing recorded) = no-op.
manage_dns_off() {
  [ -s "$STATE" ] || return 0
  grep '^dnsif|' "$STATE" | while IFS='|' read -r _ svc old; do
    if [ "$old" = "empty" ]; then
      networksetup -setdnsservers "$svc" "empty" 2>/dev/null || true
    else
      # shellcheck disable=SC2086 — old is the space-joined server list
      networksetup -setdnsservers "$svc" $old 2>/dev/null || true
    fi
  done
  grep -v '^dnsif|' "$STATE" > "$STATE.new" 2>/dev/null || true
  mv "$STATE.new" "$STATE"
  return 0
}

# set_dns_state_linux is the iptables twin: a nat OUTPUT REDIRECT pair sends
# loopback port 53 (the system resolver) into the monitor's DNS shield on
# 127.0.0.1:5333 — the same fixed constants as the macOS rdr; nothing
# user-supplied ever reaches iptables.
set_dns_state_linux() {
  local val="$1" IPT proto
  IPT=/usr/sbin/iptables
  [ -x "$IPT" ] || IPT=$(command -v iptables) || { echo "iptables not available"; return 1; }
  if [ "$val" = "on" ]; then
    grep -qxF 'dns|on|' "$STATE" || echo 'dns|on|' >> "$STATE"
    for proto in udp tcp; do
      "$IPT" -t nat -C OUTPUT -o lo -p $proto -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports 5333 2>/dev/null || \
        "$IPT" -t nat -I OUTPUT 1 -o lo -p $proto -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports 5333
    done
  else
    grep -v '^dns|' "$STATE" > "$STATE.new" 2>/dev/null || true
    mv "$STATE.new" "$STATE"
    for proto in udp tcp; do
      "$IPT" -t nat -D OUTPUT -o lo -p $proto -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports 5333 2>/dev/null || true
    done
  fi
  # best-effort resolver cache flushes across the common setups
  resolvectl flush-caches 2>/dev/null || true
  nscd -i hosts 2>/dev/null || true
  return 0
}

# -------------------------------------------------------------- commands ---
cmd="${1:-}"; shift || true

case "$cmd" in
  status)
    n_ip=0; n_cidr=0; n_allowip=0; n_allowcidr=0; dns_state="off"
    if [ -s "$STATE" ]; then
      n_ip=$(grep -c '^ip|' "$STATE" || true)
      n_cidr=$(grep -cE '^(country|list)\|' "$STATE" || true)
      n_allowip=$(grep -c '^allowip|' "$STATE" || true)
      n_allowcidr=$(grep -c '^allowlist|' "$STATE" || true)
      grep -q '^dns|' "$STATE" && dns_state="on"
    fi
    echo "no rules" >&2
    echo "active ip rules: $n_ip"
    echo "active country cidrs: $n_cidr"
    echo "active allow ips: $n_allowip"
    echo "active allow cidrs: $n_allowcidr"
    echo "dns rdr: $dns_state"
    exit 0 ;;

  dns)
    val="${1:-}"; manage="${2:-}"
    case "$val" in
      on|off)
        if [ "$OS" = "mac" ]; then
          set_dns_state_mac "$val" "$manage" || exit 4
        elif [ "$OS" = "linux" ]; then
          if [ "$manage" = "manage" ]; then
            echo "note: managed system-DNS restore is macOS-only; system DNS left unchanged" >&2
          fi
          set_dns_state_linux "$val" || exit 4
        else
          echo "dns redirect is not supported on this OS"; exit 3
        fi
        echo "ok" ;;
      *) echo "dns wants on|off [manage]"; exit 2 ;;
    esac ;;

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
          # the DROPs were inserted at position 1: restore allow-first order
          reanchor_allow_jump
        else
          regen_pf
        fi
        echo "ok" ;;

      allowip)
        ip="${1:-}"; port="${2:-}"
        valid_ip "$ip" || { echo "invalid ip: $ip"; exit 2; }
        [ -z "$port" ] || valid_port "$port" || { echo "invalid port: $port"; exit 2; }
        line="allowip|$ip|$port"
        if [ "$action" = "add" ]; then
          grep -qxF "$line" "$STATE" || echo "$line" >> "$STATE"
        else
          grep -vxF "$line" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
        fi
        if [ "$OS" = "linux" ]; then
          IFS='|' read -r _ ip2 port2 <<<"$line"
          ensure_allow_chain
          if [ "$action" = "add" ]; then
            if [ -n "$port2" ]; then
              /usr/sbin/iptables -C "$ALLOW_CHAIN" -p tcp -d "$ip2" --dport "$port2" -j ACCEPT 2>/dev/null || \
                /usr/sbin/iptables -I "$ALLOW_CHAIN" -p tcp -d "$ip2" --dport "$port2" -j ACCEPT
              /usr/sbin/iptables -C "$ALLOW_CHAIN" -p tcp -s "$ip2" --sport "$port2" -j ACCEPT 2>/dev/null || \
                /usr/sbin/iptables -I "$ALLOW_CHAIN" -p tcp -s "$ip2" --sport "$port2" -j ACCEPT
            else
              /usr/sbin/iptables -C "$ALLOW_CHAIN" -d "$ip2" -j ACCEPT 2>/dev/null || \
                /usr/sbin/iptables -I "$ALLOW_CHAIN" -d "$ip2" -j ACCEPT
              /usr/sbin/iptables -C "$ALLOW_CHAIN" -s "$ip2" -j ACCEPT 2>/dev/null || \
                /usr/sbin/iptables -I "$ALLOW_CHAIN" -s "$ip2" -j ACCEPT
            fi
          else
            if [ -n "$port2" ]; then
              /usr/sbin/iptables -D "$ALLOW_CHAIN" -p tcp -d "$ip2" --dport "$port2" -j ACCEPT 2>/dev/null
              /usr/sbin/iptables -D "$ALLOW_CHAIN" -p tcp -s "$ip2" --sport "$port2" -j ACCEPT 2>/dev/null
            else
              /usr/sbin/iptables -D "$ALLOW_CHAIN" -d "$ip2" -j ACCEPT 2>/dev/null
              /usr/sbin/iptables -D "$ALLOW_CHAIN" -s "$ip2" -j ACCEPT 2>/dev/null
            fi
          fi
          reanchor_allow_jump
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
          merge_cidrs "country|$cc" 1
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
          merge_cidrs "list|$label" 1
          if [ "$OS" = "linux" ]; then regen_linux_country; else regen_pf; fi
          echo "ok: $n_added cidrs for list $label"
        else
          grep -v "^list|${label}|" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
          if [ "$OS" = "linux" ]; then regen_linux_country; else regen_pf; fi
          echo "ok"
        fi ;;
      allowlist)
        # allow lists are NOT filtered against the protected ranges: an
        # allow only ever permits, and permitting a private range is a
        # harmless no-op (blocks can never target those ranges anyway)
        label="${1:-}"
        [[ "$label" =~ ^[a-z0-9_-]{1,32}$ ]] || { echo "invalid allowlist label: $label"; exit 2; }
        if [ "$action" = "add" ]; then
          merge_cidrs "allowlist|$label" 0
          if [ "$OS" = "linux" ]; then regen_linux_allow; else regen_pf; fi
          echo "ok: $n_added cidrs for allowlist $label"
        else
          grep -v "^allowlist|${label}|" "$STATE" > "$STATE.new" 2>/dev/null || true
          mv "$STATE.new" "$STATE"
          if [ "$OS" = "linux" ]; then regen_linux_allow; else regen_pf; fi
          echo "ok"
        fi ;;
      *)
        echo "unknown target: $what (use ip, app, country, list, allowip or allowlist)"; exit 2 ;;
    esac ;;

  *)
    echo "usage: appscope-block {status|version|dns on|off [manage]|add|del} {ip <ipv4> [port]|app <path>|country <CC>|list <label>|allowip <ipv4> [port]|allowlist <label>} < CIDR list"
    exit 2 ;;
esac
