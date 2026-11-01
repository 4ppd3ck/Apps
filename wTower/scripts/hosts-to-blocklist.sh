#!/bin/sh
# Convert a HOSTS-style domain blocklist (e.g. MVPS HOSTS) into the IP/CIDR
# blocklist file AppScopeMonitor's "list" rule consumes (one IP or CIDR per
# line — see sample-blocklist.txt). Domains are resolved via DNS to their
# current IPv4 addresses, deduplicated to bare IPs (the monitor adds /32).
#
# Usage: hosts-to-blocklist.sh <HOSTS-file> <output-file> [parallelism]
#
# Caveats inherent to domain->IP blocking: results snapshot today's DNS, so
# re-run periodically (the monitor re-reads the file on every reconcile and
# IPolice re-reads it on every refresh — no sudo needed after the one-time
# Grant); and domains on shared CDNs resolve to shared IPs, which blocks
# everything else on those IPs too.
set -eu

in=${1:?usage: hosts-to-blocklist.sh <HOSTS-file> <output-file> [parallelism]}
out=${2:?usage: hosts-to-blocklist.sh <HOSTS-file> <output-file> [parallelism]}
par=${3:-50}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Strip comments, keep only the domain column (field 2) of "IP domain" lines.
tr -d '\r' < "$in" | sed -e 's/#.*//' | awk 'NF >= 2 && $2 ~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/ {print $2}' \
  | sort -u > "$tmp/domains"

# xargs runs /bin/sh children, so inline the resolver instead of exporting.
xargs -n 1 -P "$par" sh -c '
  ip=$(dig +short +time=2 +tries=1 A "$1" 2>/dev/null | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}$" | head -1)
  [ -n "$ip" ] && printf "%s\n" "$ip"
' _ < "$tmp/domains" | sort -u > "$tmp/ips"

# Drop obviously-unblockable ranges (the monitor filters these too, but a
# clean file keeps the pf table small): loopback, RFC1918, link-local, CGNAT.
# Each surviving IP is emitted as an explicit /32 — AppScopeMonitor's
# FilterSafeCIDRs drops bare IPs (ParseCIDRLine demands a prefix).
grep -vE '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|2[3-5][0-9]\.)' \
  "$tmp/ips" | sed 's|$|/32|' > "$out" || true

total=$(wc -l < "$tmp/domains" | tr -d ' ')
kept=$(wc -l < "$out" | tr -d ' ')
echo "resolved $kept unique public IPs from $total domains -> $out"
