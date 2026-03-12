#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  vajra/go.sh — per-target engagement setup
#  usage: source ~/tools/vajra/go.sh <target_ip> [label]
# ─────────────────────────────────────────────

if [[ $# -lt 1 ]]; then
  printf '[!] Usage: source ~/tools/vajra/go.sh <target_ip> [label]\n'
  return 1
fi

# ── Validate IP ───────────────────────────────
if [[ ! "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  printf '[!] Invalid IP address: %s\n' "$1"
  return 1
fi

# ── Variables ─────────────────────────────────
export IP="$1"
export LABEL="${2:-$IP}"
export LPORT="443"

export LHOST
LHOST=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')

if [[ -z "$LHOST" ]]; then
  printf '[!] tun0 not found — VPN connected?\n'
  printf '[!] Set manually: export LHOST=<your_ip>\n'
  return 1
fi

# ── Optional prompts ──────────────────────────
read -rp "  [?] SUBNET (enter to skip): " SUBNET
read -rp "  [?] DOMAIN (enter to skip): "  DOMAIN
export SUBNET DOMAIN

# ── Directory structure ───────────────────────
TARGET_DIR="$(pwd)/${LABEL}"

if [[ -d "$TARGET_DIR" ]]; then
  read -rp "  [?] ${LABEL} already exists — cd into it? [Y/n]: " _reply
  if [[ "${_reply:-Y}" =~ ^[Yy]$ ]]; then
    cd "$TARGET_DIR" || return 1
    printf '  [=] Resumed — now in %s\n' "$TARGET_DIR"
  fi
else
  read -rp "  [?] Create folder structure in $(pwd)/${LABEL}? [Y/n]: " _reply
  if [[ "${_reply:-Y}" =~ ^[Yy]$ ]]; then
    mkdir -p "${TARGET_DIR}"/{scans,exploits,loot,screenshots,tunnels}
    cd "$TARGET_DIR" || return 1
    printf '  [+] Folders created — now in %s\n' "$TARGET_DIR"
  else
    printf '  [=] Skipping folder creation\n'
  fi
fi

# ── File descriptor limit ─────────────────────
ulimit -n 5000

# ── Banner ────────────────────────────────────
printf '\n'
printf '  ██╗   ██╗ █████╗      ██╗██████╗  █████╗ \n'
printf '  ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗\n'
printf '  ██║   ██║███████║     ██║██████╔╝███████║\n'
printf '  ╚██╗ ██╔╝██╔══██║██   ██║██╔══██╗██╔══██║\n'
printf '   ╚████╔╝ ██║  ██║╚█████╔╝██║  ██║██║  ██║\n'
printf '    ╚═══╝  ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n'
printf '\n'
printf '  ┌──────────────────────────────────────┐\n'
printf '  │  IP     %-29s│\n' "$IP"
printf '  │  LABEL  %-29s│\n' "$LABEL"
printf '  │  SUBNET %-29s│\n' "${SUBNET:-not set}"
printf '  │  LHOST  %-29s│\n' "$LHOST"
printf '  │  LPORT  %-29s│\n' "$LPORT"
printf '  │  DOMAIN %-29s│\n' "${DOMAIN:-not set}"
printf '  │  DIR    %-29s│\n' "$TARGET_DIR"
printf '  └──────────────────────────────────────┘\n'
printf '\n'

# ── Scan ──────────────────────────────────────
if command -v rustscan &>/dev/null; then
  printf '[*] rustscan starting → %s/scans/rustscan.txt\n' "$TARGET_DIR"
  rustscan -a "$IP" --ulimit 5000 -- -sV -sC | tee "${TARGET_DIR}/scans/rustscan.txt"
else
  printf '[*] rustscan not found — falling back to nmap\n'
  nmap -p- --min-rate 5000 -T4 --open -sV -sC "$IP" -oN "${TARGET_DIR}/scans/allports.txt"
fi

printf '\n[+] Done. Working dir: %s\n' "$TARGET_DIR"
printf '[+] ulimit -n: %s\n\n' "$(ulimit -n)"

unset _reply
