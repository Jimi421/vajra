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

# Basic validation
if [[ ! "$TARGET_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "[!] Invalid IP format: $TARGET_IP"
  exit 1
fi

if [[ ! "$CIDR" =~ ^[0-9]+$ ]] || (( CIDR < 1 || CIDR > 32 )); then
  echo "[!] Invalid CIDR: $CIDR"
  exit 1
fi

# Convert IP + CIDR into network range using ipcalc
if ! command -v ipcalc >/dev/null 2>&1; then
  echo "[!] ipcalc is not installed."
  echo "Install it with:"
  echo "sudo apt install ipcalc -y"
  exit 1
fi

NETWORK="$(ipcalc "$TARGET_IP/$CIDR" | awk '/Network:/ {print $2}')"

echo
echo "[*] Target IP: $TARGET_IP"
echo "[*] CIDR: /$CIDR"
echo "[*] Scanning network: $NETWORK"
echo

echo "[*] Discovering live hosts..."
sudo nmap -sn "$NETWORK" -oG - | awk '/Up$/{print $2}' | tee "$LIVE_HOSTS"

echo
echo "[*] Using NetExec to resolve SMB hostnames..."
nxc smb "$LIVE_HOSTS" --generate-hosts-file "$NXC_HOSTS"

echo
echo "[*] Generated host entries:"
cat "$NXC_HOSTS"

echo
echo "[*] Updating /etc/hosts safely..."

TMP_FILE="$(mktemp)"

awk -v start="$BLOCK_START" -v end="$BLOCK_END" '
  $0 == start {skip=1; next}
  $0 == end {skip=0; next}
  !skip {print}
' /etc/hosts > "$TMP_FILE"

{
  echo "$BLOCK_START"
  cat "$NXC_HOSTS"
  echo "$BLOCK_END"
} >> "$TMP_FILE"

sudo cp "$TMP_FILE" /etc/hosts
rm "$TMP_FILE"

echo
echo "[+] /etc/hosts updated."

echo
echo "[*] Quick validation:"
while read -r ip fqdn short extra; do
  [ -z "${short:-}" ] && continue
  echo -n "  $short -> "
  getent hosts "$short" | awk '{print $1}' || true
done < "$NXC_HOSTS"

echo
echo "[+] Done."
