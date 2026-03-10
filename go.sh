#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  vajra/go.sh — per-target engagement setup
#  usage: source go.sh <target_ip>
#  must be sourced (not executed) to export vars
# ─────────────────────────────────────────────

if [[ $# -lt 1 ]]; then
  echo "[!] Usage: source go.sh <target_ip> [lhost] [lport]"
  return 1 2>/dev/null || exit 1
fi

# ── Variables ─────────────────────────────────
export IP="$1"
export LHOST="${2:-$(ip route get 1 2>/dev/null | awk '{print $7; exit}')}"
export LPORT="${3:-443}"
export DOMAIN="${4:-}"

# ── Folder structure ──────────────────────────
TARGET_DIR="$HOME/results/$IP"
mkdir -p "$TARGET_DIR"/{scans,exploits,loot,screenshots,tunnels}
cd "$TARGET_DIR" || return 1

# ── File descriptor limit ─────────────────────
ulimit -n 5000

# ── Banner ────────────────────────────────────
echo ""
echo "  ██╗   ██╗ █████╗      ██╗██████╗  █████╗ "
echo "  ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗"
echo "  ██║   ██║███████║     ██║██████╔╝███████║"
echo "  ╚██╗ ██╔╝██╔══██║██   ██║██╔══██╗██╔══██║"
echo "   ╚████╔╝ ██║  ██║╚█████╔╝██║  ██║██║  ██║"
echo "    ╚═══╝  ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"
echo ""
echo "  ┌──────────────────────────────────────┐"
printf "  │  IP     %-29s│\n" "$IP"
printf "  │  LHOST  %-29s│\n" "$LHOST"
printf "  │  LPORT  %-29s│\n" "$LPORT"
printf "  │  DIR    %-29s│\n" "$TARGET_DIR"
echo "  └──────────────────────────────────────┘"
echo ""

# ── Scan ──────────────────────────────────────
if command -v rustscan &>/dev/null; then
  echo "[*] rustscan starting in background → scans/rustscan.txt"
  rustscan -a "$IP" --ulimit 5000 -- -sV -sC -oN scans/rustscan.txt &>/dev/null &
  echo "[*] rustscan PID: $!"
else
  echo "[*] rustscan not found — falling back to nmap"
  echo "[*] nmap full TCP starting in background → scans/allports.txt"
  nmap -p- --min-rate 5000 -T4 --open "$IP" -oN scans/allports.txt &>/dev/null &
  echo "[*] nmap PID: $!"
fi

echo ""
echo "[+] Environment ready. Working dir: $TARGET_DIR"
echo "[+] ulimit -n: $(ulimit -n)"
echo ""
