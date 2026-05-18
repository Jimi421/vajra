#!/usr/bin/env bash
# ad_hostmap — discover AD hosts on a subnet and add them to /etc/hosts.
#
# Usage:
#   sudo ./ad_hostmap.sh 192.168.110.0/24
#   sudo ./ad_hostmap.sh --target 192.168.110.70
#   sudo ./ad_hostmap.sh --iface tun0
#   sudo ./ad_hostmap.sh --auto
#   sudo ./ad_hostmap.sh --restore
#
# Requires:
#   nmap, nxc, python3, sudo, awk, ip, getent
#
# What it does:
#   1. Finds live hosts with nmap ping scan.
#   2. Uses NetExec to generate /etc/hosts-style AD host entries.
#   3. Removes old AD_HOSTMAP blocks.
#   4. Removes old AD_LAB_HOSTS blocks from earlier versions.
#   5. Removes stale matching hostnames outside the block.
#   6. Writes a fresh AD_HOSTMAP block.
#   7. Validates that each hostname resolves to the expected IP.

set -euo pipefail

# ─────────────────────────────────────────────────────────────
# Globals
# ─────────────────────────────────────────────────────────────

HOSTS_FILE="/etc/hosts"

BLOCK_START="# BEGIN AD_HOSTMAP"
BLOCK_END="# END AD_HOSTMAP"

OLD_BLOCK_START="# BEGIN AD_LAB_HOSTS"
OLD_BLOCK_END="# END AD_LAB_HOSTS"

TMPDIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

die() {
    echo "[!] $*" >&2
    exit 1
}

usage() {
    cat <<EOF
ad_hostmap — discover AD hosts on a subnet and add them to /etc/hosts.

Usage:
  sudo ./ad_hostmap.sh 192.168.110.0/24
  sudo ./ad_hostmap.sh --target 192.168.110.70
  sudo ./ad_hostmap.sh --iface tun0
  sudo ./ad_hostmap.sh --auto
  sudo ./ad_hostmap.sh --restore

Options:
  --target, -t IP     Auto-detect scan subnet from route to target IP.
  --iface, -i IFACE   Auto-detect scan subnet from a specific interface.
  --auto              Auto-detect subnet from VPN-style interface first, then default route.
  --restore           Remove AD_HOSTMAP and old AD_LAB_HOSTS managed blocks.
  -h, --help          Show this help.

Examples:
  sudo ./ad_hostmap.sh --target 192.168.110.70
  sudo ./ad_hostmap.sh --iface tun0
  sudo ./ad_hostmap.sh 192.168.110.0/24
EOF
}

# ─────────────────────────────────────────────────────────────
# Args
# ─────────────────────────────────────────────────────────────

MODE="scan"
NETWORK=""
AUTO_NETWORK=0
IFACE=""
TARGET_IP=""

while (( $# )); do
    case "$1" in
        --restore)
            MODE="restore"
            shift
            ;;
        --auto)
            AUTO_NETWORK=1
            shift
            ;;
        --iface|-i)
            [[ $# -ge 2 ]] || die "--iface requires an interface name, example: --iface tun0"
            IFACE="$2"
            AUTO_NETWORK=1
            shift 2
            ;;
        --target|-t)
            [[ $# -ge 2 ]] || die "--target requires an IP, example: --target 192.168.110.70"
            TARGET_IP="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            if [[ -n "$NETWORK" ]]; then
                die "only one network/CIDR argument is allowed"
            fi
            NETWORK="$1"
            shift
            ;;
    esac
done

# ─────────────────────────────────────────────────────────────
# Prereqs
# ─────────────────────────────────────────────────────────────

if [[ "$MODE" == "restore" ]]; then
    for cmd in sudo awk date cp; do
        command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
    done
else
    for cmd in nmap nxc python3 sudo awk ip getent sort wc date cp; do
        command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
    done
fi

# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

validate_network() {
    local input_network="$1"

    python3 - "$input_network" <<'PY'
import ipaddress
import sys

try:
    print(ipaddress.ip_network(sys.argv[1], strict=False))
except ValueError as e:
    sys.exit(f"invalid network: {e}")
PY
}

validate_ip() {
    local input_ip="$1"

    python3 - "$input_ip" <<'PY'
import ipaddress
import sys

try:
    print(ipaddress.ip_address(sys.argv[1]))
except ValueError as e:
    sys.exit(f"invalid IP: {e}")
PY
}

detect_network_from_iface() {
    local chosen_iface="$1"
    local iface_cidr=""

    if [[ -n "$chosen_iface" ]]; then
        iface_cidr="$(
            ip -o -4 addr show dev "$chosen_iface" scope global 2>/dev/null |
            awk 'NR==1 { print $4 }'
        )"

        [[ -n "$iface_cidr" ]] || die "could not find IPv4 address for interface: $chosen_iface"
    else
        # Prefer VPN-style interfaces first.
        iface_cidr="$(
            ip -o -4 addr show scope global |
            awk '$2 ~ /^(tun|tap|wg|ppp)[0-9]+$/ { print $4; exit }'
        )"

        # Fallback to default route interface.
        if [[ -z "$iface_cidr" ]]; then
            local default_iface

            default_iface="$(
                ip route show default |
                awk 'NR==1 {
                    for (i=1; i<=NF; i++) {
                        if ($i == "dev") {
                            print $(i+1)
                            exit
                        }
                    }
                }'
            )"

            [[ -n "$default_iface" ]] || die "could not determine default route interface"

            iface_cidr="$(
                ip -o -4 addr show dev "$default_iface" scope global |
                awk 'NR==1 { print $4 }'
            )"

            [[ -n "$iface_cidr" ]] || die "could not find IPv4 address for default interface: $default_iface"
        fi
    fi

    python3 - "$iface_cidr" <<'PY'
import ipaddress
import sys

print(ipaddress.ip_network(sys.argv[1], strict=False))
PY
}

detect_network_from_target() {
    local target="$1"

    ip route | python3 - "$target" <<'PY'
import ipaddress
import sys

target = ipaddress.ip_address(sys.argv[1])
routes = sys.stdin.read().splitlines()

matches = []

for line in routes:
    parts = line.split()
    if not parts:
        continue

    dest = parts[0]

    if dest == "default":
        continue

    try:
        if "/" not in dest:
            net = ipaddress.ip_network(dest + "/32", strict=False)
        else:
            net = ipaddress.ip_network(dest, strict=False)

        if target in net:
            matches.append(net)
    except ValueError:
        continue

if matches:
    best = sorted(matches, key=lambda n: n.prefixlen, reverse=True)[0]

    # Guardrail:
    # If route is huge, scan target /24 instead of something like 10.0.0.0/8.
    # If route is host-only /32, also scan target /24 for lab usefulness.
    if best.prefixlen < 24 or best.prefixlen > 30:
        print(ipaddress.ip_network(str(target) + "/24", strict=False))
    else:
        print(best)
else:
    # Common AD lab fallback.
    print(ipaddress.ip_network(str(target) + "/24", strict=False))
PY
}

backup_hosts_file() {
    local backup_file="/etc/hosts.bak.$(date +%F_%H%M%S)"

    echo "[*] Backing up /etc/hosts to: $backup_file"
    sudo cp "$HOSTS_FILE" "$backup_file"
}

# ─────────────────────────────────────────────────────────────
# Restore mode
# ─────────────────────────────────────────────────────────────

if [[ "$MODE" == "restore" ]]; then
    TMP_HOSTS="$TMPDIR/hosts.restore"

    echo "[*] Restore mode selected"
    backup_hosts_file

    awk -v start="$BLOCK_START" -v end="$BLOCK_END" \
        -v old_start="$OLD_BLOCK_START" -v old_end="$OLD_BLOCK_END" '
        $0 == start || $0 == old_start {
            skip = 1
            next
        }

        $0 == end || $0 == old_end {
            skip = 0
            next
        }

        !skip {
            print
        }
    ' "$HOSTS_FILE" > "$TMP_HOSTS"

    sudo cp "$TMP_HOSTS" "$HOSTS_FILE"

    echo "[+] Removed AD_HOSTMAP and old AD_LAB_HOSTS blocks from /etc/hosts"
    exit 0
fi

# ─────────────────────────────────────────────────────────────
# Network selection
# ─────────────────────────────────────────────────────────────

echo "=== AD Host Mapper ==="
echo

if [[ -n "$TARGET_IP" ]]; then
    TARGET_IP="$(validate_ip "$TARGET_IP")" || die "$TARGET_IP"
    NETWORK="$(detect_network_from_target "$TARGET_IP")"

    echo "[*] Target IP: $TARGET_IP"
    echo "[*] Auto-detected routed network: $NETWORK"

elif (( AUTO_NETWORK )); then
    NETWORK="$(detect_network_from_iface "$IFACE")"

    if [[ -n "$IFACE" ]]; then
        echo "[*] Interface: $IFACE"
    else
        echo "[*] Interface: auto"
    fi

    echo "[*] Auto-detected local network: $NETWORK"

elif [[ -n "$NETWORK" ]]; then
    NETWORK="$(validate_network "$NETWORK")" || die "$NETWORK"
    echo "[*] Network: $NETWORK"

else
    read -rp "Network/CIDR, example 192.168.110.0/24: " NETWORK
    NETWORK="$(validate_network "$NETWORK")" || die "$NETWORK"
    echo "[*] Network: $NETWORK"
fi

echo

# ─────────────────────────────────────────────────────────────
# Scan live hosts
# ─────────────────────────────────────────────────────────────

LIVE_HOSTS="$TMPDIR/live_hosts.txt"
NXC_HOSTS="$TMPDIR/nxc_hosts.txt"
NXC_HOSTS_CLEAN="$TMPDIR/nxc_hosts.clean"
HOSTNAMES="$TMPDIR/hostnames.txt"
TMP_HOSTS="$TMPDIR/hosts.new"

echo "[*] Discovering live hosts with nmap..."
sudo nmap -sn "$NETWORK" -oG - |
    awk '/Status: Up/ { print $2 }' > "$LIVE_HOSTS"

if [[ ! -s "$LIVE_HOSTS" ]]; then
    die "no live hosts found on $NETWORK"
fi

echo "[*] Live hosts found: $(wc -l < "$LIVE_HOSTS")"
sed 's/^/    /' "$LIVE_HOSTS"
echo

# ─────────────────────────────────────────────────────────────
# Optional DC hint via Kerberos
# ─────────────────────────────────────────────────────────────

echo "[*] Checking for possible domain controller via Kerberos port 88..."

DC_IP="$(
    sudo nmap -p88 -Pn --open -T4 -iL "$LIVE_HOSTS" -oG - 2>/dev/null |
    awk '/Ports: 88\/open/ { print $2; exit }'
)"

if [[ -n "$DC_IP" ]]; then
    echo "[*] Possible DC found: $DC_IP"
else
    echo "[*] No host with TCP/88 open detected"
fi

echo

# ─────────────────────────────────────────────────────────────
# Resolve hostnames with NetExec
# ─────────────────────────────────────────────────────────────

echo "[*] Resolving SMB hostnames with NetExec..."
nxc smb "$LIVE_HOSTS" --generate-hosts-file "$NXC_HOSTS" || true

if [[ ! -s "$NXC_HOSTS" ]]; then
    die "NetExec did not generate any host entries"
fi

# Keep only sane /etc/hosts-style lines:
# IP hostname [aliases...]
awk '
    NF >= 2 && $1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ {
        print
    }
' "$NXC_HOSTS" > "$NXC_HOSTS_CLEAN"

mv "$NXC_HOSTS_CLEAN" "$NXC_HOSTS"

if [[ ! -s "$NXC_HOSTS" ]]; then
    die "NetExec output had no valid host entries"
fi

echo
echo "[*] Generated host entries:"
cat "$NXC_HOSTS"
echo

# Extract domain from first FQDN.
DOMAIN="$(
    awk '
        {
            for (i=2; i<=NF; i++) {
                if ($i ~ /\./) {
                    n = split($i, a, ".")
                    for (j=2; j<=n; j++) {
                        printf "%s%s", a[j], (j<n ? "." : "\n")
                    }
                    exit
                }
            }
        }
    ' "$NXC_HOSTS"
)"

if [[ -n "$DOMAIN" ]]; then
    echo "[*] Detected domain: $DOMAIN"
fi

# Build hostname list for stale cleanup.
awk '
    {
        for (i=2; i<=NF; i++) {
            if ($i !~ /^#/) {
                print $i
            }
        }
    }
' "$NXC_HOSTS" | sort -u > "$HOSTNAMES"

echo "[*] Hostnames that will be refreshed:"
sed 's/^/    /' "$HOSTNAMES"
echo

# ─────────────────────────────────────────────────────────────
# Update /etc/hosts safely
# ─────────────────────────────────────────────────────────────

backup_hosts_file

echo "[*] Updating /etc/hosts..."

awk -v start="$BLOCK_START" -v end="$BLOCK_END" \
    -v old_start="$OLD_BLOCK_START" -v old_end="$OLD_BLOCK_END" '
    # First file: hostname list from new NetExec output.
    FNR == NR {
        names[$1] = 1
        next
    }

    # Remove current managed block.
    $0 == start || $0 == old_start {
        skip = 1
        next
    }

    $0 == end || $0 == old_end {
        skip = 0
        next
    }

    skip {
        next
    }

    # Preserve comments and blank lines.
    /^[[:space:]]*#/ || NF == 0 {
        print
        next
    }

    # Remove stale lines outside the block if they contain any hostname
    # we are about to refresh.
    {
        clean = $0
        sub(/[[:space:]]+#.*/, "", clean)

        n = split(clean, fields, /[[:space:]]+/)

        for (i=2; i<=n; i++) {
            if (fields[i] in names) {
                next
            }
        }

        print
    }
' "$HOSTNAMES" "$HOSTS_FILE" > "$TMP_HOSTS"

{
    echo "$BLOCK_START"
    cat "$NXC_HOSTS"
    echo "$BLOCK_END"
} >> "$TMP_HOSTS"

sudo cp "$TMP_HOSTS" "$HOSTS_FILE"

echo "[+] /etc/hosts updated"
echo

# ─────────────────────────────────────────────────────────────
# Validate
# ─────────────────────────────────────────────────────────────

echo "[*] Validation:"

FAIL=0

while read -r IP NAMES; do
    [[ -z "${IP:-}" ]] && continue
    [[ "$IP" == \#* ]] && continue
    [[ -z "${NAMES:-}" ]] && continue

    for NAME in $NAMES; do
        [[ "$NAME" == \#* ]] && continue

        GOT="$(
            getent hosts "$NAME" |
            awk 'NR==1 { print $1 }'
        )"

        if [[ "$GOT" == "$IP" ]]; then
            echo "    OK:   $NAME -> $GOT"
        else
            echo "    FAIL: $NAME -> ${GOT:-NO_RESULT} expected $IP"
            FAIL=1
        fi
    done
done < "$NXC_HOSTS"

echo

if (( FAIL )); then
    die "/etc/hosts updated, but some entries did not resolve correctly"
fi

echo "[+] $(wc -l < "$NXC_HOSTS") hosts mapped successfully"
echo "[+] Done."
