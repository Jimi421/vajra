#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  vajra/go.sh — per-target engagement setup
#  usage: source go.sh <target_ip> [label]
#  label: optional folder name (default: $IP)
#  examples:
#    go.sh 10.10.10.10
#    go.sh 10.10.10.10 arctic
#    go.sh 10.10.10.10 lab-1
#  must be sourced to export vars into your shell
# ─────────────────────────────────────────────

# ── Guard: must be sourced, not executed ──────
# $0 is "bash" or "-bash" when sourced; the script name when executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  printf '[!] go.sh must be sourced, not executed:\n'
  printf '    source %s <target_ip> [label]\n' "${BASH_SOURCE[0]}"
  exit 1
fi

# ── Guard: require target IP ──────────────────
if [[ $# -lt 1 ]]; then
  printf '[!] Usage: source go.sh <target_ip> [label]\n'
  return 1
fi

# ── Validate IP format ────────────────────────
if [[ ! "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  printf '[!] Invalid IP address: %s\n' "$1"
  return 1
fi

# ── Variables ─────────────────────────────────
export IP="$1"
export LABEL="${2:-$IP}"
export LPORT="443"

# Detect tun0 IP — single process, no pipe fork
export LHOST
LHOST=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')

if [[ -z "$LHOST" ]]; then
  printf '[!] tun0 not found — is your VPN connected?\n'
  printf '[!] Set manually: export LHOST=<your_ip>\n'
  return 1
fi

# ── Optional prompts ──────────────────────────
# -r: no backslash interpretation
# -p: inline prompt (no separate echo needed)
read -rp "  [?] SUBNET (enter to skip): " SUBNET
read -rp "  [?] DOMAIN (enter to skip): "  DOMAIN
export SUBNET DOMAIN

# ── Directory structure ───────────────────────
# Use printf not echo for portability
local_dir="$(pwd)"          # capture once — pwd is a fork
TARGET_DIR="${local_dir}/${LABEL}"

if [[ -d "$TARGET_DIR" ]]; then
  read -rp "  [?] ${LABEL} already exists — cd into it? [Y/n]: " _reply
  if [[ "${_reply:-Y}" =~ ^[Yy]$ ]]; then
    cd "$TARGET_DIR" || return 1
    printf '  [=] Resumed — now in %s\n' "$TARGET_DIR"
  fi
else
  read -rp "  [?] Create folder structure in ${local_dir}/${LABEL}? [Y/n]: " _reply
  if [[ "${_reply:-Y}" =~ ^[Yy]$ ]]; then
    # brace expansion creates all subdirs in one mkdir call
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
# printf is faster and more portable than multiple echo calls
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
# command -v is POSIX-compliant tool check (faster than which)
if command -v rustscan &>/dev/null; then
  printf '[*] rustscan starting → scans/rustscan.txt\n'
  rustscan -a "$IP" --ulimit 5000 | tee "${TARGET_DIR}/scans/rustscan.txt"
else
  printf '[*] rustscan not found — falling back to nmap\n'
  printf '[*] nmap full TCP → scans/allports.txt\n'
  nmap -p- --min-rate 5000 -T4 --open "$IP" -oN "${TARGET_DIR}/scans/allports.txt"
fi

printf '\n[+] Environment ready. Working dir: %s\n' "$TARGET_DIR"
printf '[+] ulimit -n: %s\n\n' "$(ulimit -n)"

# ── Cleanup internal vars ─────────────────────
unset local_dir _reply
