#!/usr/bin/env bash
# ad_hostmap — discover AD hosts on a routed lab subnet and add them to /etc/hosts.
#
# Usage:
#   sudo ./ad_hostmap.sh 192.168.110.0/24
#   sudo ./ad_hostmap.sh --target 192.168.110.70
#   sudo ./ad_hostmap.sh --iface tun0
#   sudo ./ad_hostmap.sh --auto
#   sudo ./ad_hostmap.sh --restore
#
# Requires: nmap, nxc, python3, ip, getent

set -euo pipefail

VERSION="1.4.0"
HOSTS_FILE="/etc/hosts"
BLOCK_START="# BEGIN AD_HOSTMAP"
BLOCK_END="# END AD_HOSTMAP"
OLD_BLOCK_START="# BEGIN AD_LAB_HOSTS"
OLD_BLOCK_END="# END AD_LAB_HOSTS"
DEFAULT_OUTPUT="ad_hostmap-hosts.txt"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

die() { echo "[!] $*" >&2; exit 1; }

as_root() {
    if (( EUID == 0 )); then "$@"; else sudo "$@"; fi
}

usage() {
    cat <<EOF
ad_hostmap v$VERSION — discover AD hosts, update /etc/hosts, write IPs to file.

Usage:
  sudo ./ad_hostmap.sh <CIDR>              scan the given CIDR
  sudo ./ad_hostmap.sh --target <IP>       derive subnet from a known lab IP via routes
  sudo ./ad_hostmap.sh --iface <IFACE>     derive subnet from routes on an interface
  sudo ./ad_hostmap.sh --auto              auto-detect VPN interface (tun/tap/wg/ppp)
  sudo ./ad_hostmap.sh --restore           remove AD_HOSTMAP block from /etc/hosts

Options:
  -o, --output <FILE>   IPs output file (default: $DEFAULT_OUTPUT)
  -h, --help            show this help
  -v, --version         show version

The output file contains one IP per line. Pass it directly to NetExec:
  nxc smb $DEFAULT_OUTPUT -u <user> -p <pass>
EOF
}

# ─── args ────────────────────────────────────────────────────────────
MODE="scan"
NETWORK=""
TARGET_IP=""
IFACE=""
AUTO_MODE=0
OUTPUT_FILE="$DEFAULT_OUTPUT"

while (( $# )); do
    case "$1" in
        --restore)      MODE="restore"; shift;;
        --auto)         AUTO_MODE=1; shift;;
        --target|-t)    [[ $# -ge 2 ]] || die "--target requires an IP"; TARGET_IP="$2"; shift 2;;
        --iface|-i)     [[ $# -ge 2 ]] || die "--iface requires an interface"; IFACE="$2"; shift 2;;
        --output|-o)    [[ $# -ge 2 ]] || die "--output requires a path"; OUTPUT_FILE="$2"; shift 2;;
        --help|-h)      usage; exit 0;;
        --version|-v)   echo "ad_hostmap v$VERSION"; exit 0;;
        -*)             die "unknown option: $1";;
        *)              [[ -z "$NETWORK" ]] || die "only one CIDR allowed"; NETWORK="$1"; shift;;
    esac
done

# Mutual exclusion: pick one source of network truth.
mode_count=0
[[ -n "$NETWORK" ]]    && ((mode_count+=1))
[[ -n "$TARGET_IP" ]]  && ((mode_count+=1))
[[ -n "$IFACE" ]]      && ((mode_count+=1))
(( AUTO_MODE ))        && ((mode_count+=1))
(( mode_count > 1 ))   && die "choose only one: CIDR, --target, --iface, or --auto"

# ─── prereqs ─────────────────────────────────────────────────────────
if [[ "$MODE" == "restore" ]]; then
    required=(awk)
else
    required=(nmap nxc python3 awk ip getent)
fi
(( EUID != 0 )) && required+=(sudo)
for cmd in "${required[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing: $cmd"
done

# ─── network detection helpers ───────────────────────────────────────
detect_from_target() {
    local target="$1"
    ROUTES="$(ip route)" python3 - "$target" <<'PY'
import ipaddress, os, sys
target = ipaddress.ip_address(sys.argv[1])
matches = []
for line in os.environ.get("ROUTES", "").splitlines():
    parts = line.split()
    if not parts or parts[0] == "default": continue
    dest = parts[0]
    try:
        net = ipaddress.ip_network(dest if "/" in dest else dest + "/32", strict=False)
    except ValueError:
        continue
    if net.version == target.version and target in net:
        matches.append(net)
if matches:
    best = sorted(matches, key=lambda n: n.prefixlen, reverse=True)[0]
    # Floor at /22 (1024 hosts) — wider than that and we fall back to /24.
    # Ceiling at /30 — anything narrower is host-route noise.
    if best.prefixlen < 22 or best.prefixlen > 30:
        print(ipaddress.ip_network(f"{target}/24", strict=False))
    else:
        print(best)
else:
    print(ipaddress.ip_network(f"{target}/24", strict=False))
PY
}

detect_from_iface() {
    local dev="$1"
    ip link show "$dev" >/dev/null 2>&1 || die "interface not found: $dev"
    local routes iface_cidrs
    routes="$(ip route show dev "$dev" || true)"
    iface_cidrs="$(ip -o -4 addr show dev "$dev" scope global 2>/dev/null |
                   awk 'BEGIN{sep=""} {printf "%s%s", sep, $4; sep=","}')"
    [[ -n "$routes" ]] || die "no routes for interface: $dev"

    ROUTES="$routes" IFACE_CIDRS="$iface_cidrs" python3 - <<'PY'
import ipaddress, os, sys
iface_ips = []
for c in (x for x in os.environ.get("IFACE_CIDRS", "").split(",") if x):
    try: iface_ips.append(ipaddress.ip_interface(c).ip)
    except ValueError: pass

candidates = []
for line in os.environ.get("ROUTES", "").splitlines():
    parts = line.split()
    if not parts or parts[0] == "default": continue
    dest = parts[0]
    try:
        net = ipaddress.ip_network(dest if "/" in dest else dest + "/32", strict=False)
    except ValueError:
        continue
    if net.version != 4: continue
    if net.prefixlen == 32: continue            # host routes
    if not net.is_private: continue             # public ranges
    if any(ip in net for ip in iface_ips): continue  # the tunnel's own net
    # Floor at /22 (1024 hosts). /16 = 65k host scan = 30+ min on a VPN.
    if net.prefixlen < 22 or net.prefixlen > 30: continue
    candidates.append(net)

if not candidates:
    sys.exit("no private routed lab subnet behind this interface (within /22-/30)")

# Prefer /24 (typical lab), else the narrowest candidate.
preferred = [n for n in candidates if n.prefixlen == 24]
print(preferred[0] if preferred else sorted(candidates, key=lambda n: n.prefixlen, reverse=True)[0])
PY
}

detect_auto() {
    local ifaces=()
    mapfile -t ifaces < <(
        ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 |
        awk '/^(tun|tap|wg|ppp)[0-9]+$/'
    )
    (( ${#ifaces[@]} )) || die "auto mode: no VPN-style interfaces (tun/tap/wg/ppp)"

    local dev net
    for dev in "${ifaces[@]}"; do
        if net="$(detect_from_iface "$dev" 2>/dev/null)"; then
            echo "$net"; return 0
        fi
    done
    die "auto mode: VPN interface(s) found but no routed lab subnet behind them"
}

# ─── restore mode ────────────────────────────────────────────────────
if [[ "$MODE" == "restore" ]]; then
    tmp="$TMPDIR/hosts.restore"
    awk -v s="$BLOCK_START" -v e="$BLOCK_END" \
        -v os="$OLD_BLOCK_START" -v oe="$OLD_BLOCK_END" '
        $0 == s || $0 == os {skip=1; next}
        $0 == e || $0 == oe {skip=0; next}
        !skip {print}
    ' "$HOSTS_FILE" > "$tmp"
    as_root cp "$tmp" "$HOSTS_FILE"
    echo "[+] removed AD_HOSTMAP block"
    exit 0
fi

# ─── select network ──────────────────────────────────────────────────
echo "=== ad_hostmap v$VERSION ==="

if [[ -n "$TARGET_IP" ]]; then
    NETWORK="$(detect_from_target "$TARGET_IP")" || die "$NETWORK"
    echo "[*] target $TARGET_IP -> $NETWORK"
elif [[ -n "$IFACE" ]]; then
    NETWORK="$(detect_from_iface "$IFACE")" || die "$NETWORK"
    echo "[*] iface $IFACE -> $NETWORK"
elif (( AUTO_MODE )); then
    NETWORK="$(detect_auto)" || die "$NETWORK"
    echo "[*] auto -> $NETWORK"
elif [[ -n "$NETWORK" ]]; then
    NETWORK="$(python3 -c "import ipaddress, sys
try: print(ipaddress.ip_network('$NETWORK', strict=False))
except ValueError as e: sys.exit(f'invalid network: {e}')")" || die "$NETWORK"
    echo "[*] network $NETWORK"
else
    read -rp "Network/CIDR (e.g. 192.168.110.0/24): " NETWORK
    NETWORK="$(python3 -c "import ipaddress, sys
try: print(ipaddress.ip_network('$NETWORK', strict=False))
except ValueError as e: sys.exit(f'invalid network: {e}')")" || die "$NETWORK"
    echo "[*] network $NETWORK"
fi

# ─── live host discovery ─────────────────────────────────────────────
LIVE="$TMPDIR/live"
echo "[*] scanning $NETWORK"
as_root nmap -sn "$NETWORK" -oG - 2>/dev/null |
awk '
    function is_ip(s) { return s ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ }
    /Status: Up/ {
        if (is_ip($2)) { print $2; next }
        for (i=1; i<=NF; i++) {
            c=$i; gsub(/[()]/,"",c)
            if (is_ip(c)) { print c; next }
        }
    }' | awk '!seen[$0]++' > "$LIVE"

[[ -s "$LIVE" ]] || die "no live hosts on $NETWORK"
echo "[*] live hosts: $(wc -l < "$LIVE")"
sed 's/^/    /' "$LIVE"

# Write the IP-only file the user actually wants.
cp "$LIVE" "$OUTPUT_FILE"
echo "[*] IPs written to: $OUTPUT_FILE"

# ─── DC detection ────────────────────────────────────────────────────
DC_IP="$(as_root nmap -p88 -Pn --open -T4 -iL "$LIVE" -oG - 2>/dev/null |
    awk '
        function is_ip(s) { return s ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ }
        /Ports:.*88\/open/ {
            for (i=1; i<=NF; i++) {
                c=$i; gsub(/[()]/,"",c)
                if (is_ip(c)) { print c; exit }
            }
        }')"
[[ -n "$DC_IP" ]] && echo "[*] possible DC: $DC_IP"

# ─── resolve hostnames via SMB ───────────────────────────────────────
NXC="$TMPDIR/nxc_hosts"
nxc smb "$LIVE" --generate-hosts-file "$NXC" >/dev/null 2>&1 || true
[[ -s "$NXC" ]] || die "nxc returned no host entries"

# Clean nxc output: keep only lines starting with a valid IP.
awk 'NF >= 2 && $1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/' "$NXC" > "$NXC.clean"
mv "$NXC.clean" "$NXC"
[[ -s "$NXC" ]] || die "nxc output had no valid /etc/hosts entries"

# Domain extraction.
DOMAIN="$(awk '{
    for (i=2; i<=NF; i++) {
        if ($i ~ /\./) {
            n=split($i, a, ".")
            for (j=2; j<=n; j++) printf "%s%s", a[j], (j<n ? "." : "\n")
            exit
        }
    }}' "$NXC")"
[[ -n "$DOMAIN" ]] && echo "[*] domain: $DOMAIN"

echo "[*] mapped hosts:"
sed 's/^/    /' "$NXC"

# ─── update /etc/hosts ───────────────────────────────────────────────
HOSTNAMES="$TMPDIR/hostnames"
awk '{ for (i=2; i<=NF; i++) if ($i !~ /^#/) print $i }' "$NXC" | sort -u > "$HOSTNAMES"

backup="/etc/hosts.bak.$(date +%F_%H%M%S)"
as_root cp "$HOSTS_FILE" "$backup"
echo "[*] backup: $backup"

NEW_HOSTS="$TMPDIR/hosts.new"
awk -v s="$BLOCK_START" -v e="$BLOCK_END" \
    -v os="$OLD_BLOCK_START" -v oe="$OLD_BLOCK_END" '
    FNR == NR { names[$1] = 1; next }
    $0 == s || $0 == os { skip=1; next }
    $0 == e || $0 == oe { skip=0; next }
    skip { next }
    /^[[:space:]]*#/ || NF == 0 { print; next }
    {
        clean = $0
        sub(/[[:space:]]+#.*/, "", clean)
        n = split(clean, fields, /[[:space:]]+/)
        for (i=2; i<=n; i++) if (fields[i] in names) next
        print
    }
' "$HOSTNAMES" "$HOSTS_FILE" > "$NEW_HOSTS"

{
    echo "$BLOCK_START"
    cat "$NXC"
    echo "$BLOCK_END"
} >> "$NEW_HOSTS"

as_root cp "$NEW_HOSTS" "$HOSTS_FILE"

# ─── verify ──────────────────────────────────────────────────────────
fail=0
while read -r ip names; do
    [[ -z "${ip:-}" || "$ip" == \#* || -z "${names:-}" ]] && continue
    for name in $names; do
        [[ "$name" == \#* ]] && continue
        got="$(getent hosts "$name" | awk 'NR==1{print $1}')"
        if [[ "$got" == "$ip" ]]; then
            echo "    OK:   $name -> $got"
        else
            echo "    FAIL: $name -> ${got:-NO_RESULT} expected $ip"
            fail=1
        fi
    done
done < "$NXC"

(( fail )) && die "/etc/hosts updated but some entries did not resolve"
echo "[+] $(wc -l < "$NXC") hosts mapped — IPs in $OUTPUT_FILE"
