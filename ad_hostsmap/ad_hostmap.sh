#!/usr/bin/env bash
set -euo pipefail

LIVE_HOSTS="live_hosts.txt"
NXC_HOSTS="nxc_hosts.txt"

BLOCK_START="# BEGIN AD_LAB_HOSTS"
BLOCK_END="# END AD_LAB_HOSTS"

echo "=== AD Lab Host Mapper ==="
echo

read -rp "Enter target IP address, example 192.168.141.70: " TARGET_IP
read -rp "Enter CIDR range, example 24: " CIDR

# Basic IP validation
if [[ ! "$TARGET_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "[!] Invalid IP format: $TARGET_IP"
  exit 1
fi

# Basic CIDR validation
if [[ ! "$CIDR" =~ ^[0-9]+$ ]] || (( CIDR < 1 || CIDR > 32 )); then
  echo "[!] Invalid CIDR: $CIDR"
  exit 1
fi

# Make sure python3 exists
if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 is required but was not found."
  exit 1
fi

# Make sure nmap exists
if ! command -v nmap >/dev/null 2>&1; then
  echo "[!] nmap is required but was not found."
  exit 1
fi

# Make sure nxc exists
if ! command -v nxc >/dev/null 2>&1; then
  echo "[!] NetExec 'nxc' is required but was not found."
  exit 1
fi

# Convert IP + CIDR into network range without ipcalc
NETWORK="$(python3 - <<EOF
import ipaddress
try:
    print(ipaddress.ip_network("$TARGET_IP/$CIDR", strict=False))
except ValueError as e:
    print(f"ERROR: {e}")
    raise SystemExit(1)
EOF
)"

echo
echo "[*] Target IP: $TARGET_IP"
echo "[*] CIDR: /$CIDR"
echo "[*] Scanning network: $NETWORK"
echo

echo "[*] Discovering live hosts..."
sudo nmap -sn "$NETWORK" -oG - | awk '/Up$/{print $2}' | tee "$LIVE_HOSTS"

echo
echo "[*] Live hosts saved to: $LIVE_HOSTS"
echo

if [[ ! -s "$LIVE_HOSTS" ]]; then
  echo "[!] No live hosts found. Exiting."
  exit 1
fi

echo "[*] Using NetExec to resolve SMB hostnames..."
nxc smb "$LIVE_HOSTS" --generate-hosts-file "$NXC_HOSTS"

echo
echo "[*] Generated host entries:"
cat "$NXC_HOSTS"

if [[ ! -s "$NXC_HOSTS" ]]; then
  echo "[!] NetExec did not generate any host entries. Exiting."
  exit 1
fi

echo
echo "[*] Updating /etc/hosts safely..."

TMP_FILE="$(mktemp)"

# Remove old AD lab block if it exists
awk -v start="$BLOCK_START" -v end="$BLOCK_END" '
  $0 == start {skip=1; next}
  $0 == end {skip=0; next}
  !skip {print}
' /etc/hosts > "$TMP_FILE"

# Add fresh AD lab block
{
  echo "$BLOCK_START"
  cat "$NXC_HOSTS"
  echo "$BLOCK_END"
} >> "$TMP_FILE"

sudo cp "$TMP_FILE" /etc/hosts
rm "$TMP_FILE"

echo
echo "[+] /etc/hosts updated successfully."

echo
echo "[*] Quick validation:"
while read -r ip fqdn short extra; do
  [[ -z "${short:-}" ]] && continue
  echo -n "  $short -> "
  getent hosts "$short" | awk '{print $1}' || true
done < "$NXC_HOSTS"

echo
echo "[+] Done."
