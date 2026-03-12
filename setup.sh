#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  vajra/setup.sh — one-time Kali environment config
#  run once on a fresh box: bash setup.sh
# ─────────────────────────────────────────────

set -uo pipefail

info()  { printf '[*] %s\n' "$*"; }
ok()    { printf '[+] %s\n' "$*"; }
skip()  { printf '[=] %s\n' "$*"; }
warn()  { printf '[!] %s\n' "$*" >&2; }

# ── Guard: must NOT be sourced ────────────────
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  warn "setup.sh should be executed, not sourced:"
  warn "  bash ~/tools/vajra/setup.sh"
  return 1
fi

printf '\n'
info "vajra setup starting..."
printf '\n'

# ── Helper: add line to .bashrc if not present ──
add_to_bashrc() {
  local line="$1"
  if ! grep -qF "$line" ~/.bashrc; then
    printf '%s\n' "$line" >> ~/.bashrc
    ok "Added: $line"
  else
    skip "Already in .bashrc: $line"
  fi
}

# ── ulimit ────────────────────────────────────
add_to_bashrc 'ulimit -n 5000'

# ── Aliases ───────────────────────────────────
printf '\n'
info "Wiring aliases into ~/.bashrc..."

add_to_bashrc "alias pyfix='python3 ~/tools/vajra/pyfix.py'"
add_to_bashrc "alias ll='ls -lah'"
add_to_bashrc "alias ports='ss -tulnp'"
# myip — function avoids metacharacter escaping issues in .bashrc
if ! grep -q "myip()" ~/.bashrc; then
  printf 'myip() { ip -4 addr show tun0 2>/dev/null | grep -oP "(?<=inet )[.0-9]+"; }\n' >> ~/.bashrc
  ok "Added: myip()"
else
  skip "Already in .bashrc: myip()"
fi
add_to_bashrc "alias serve='python3 -m http.server 8000'"
add_to_bashrc "alias listen='sudo nc -lvnp 443'"
add_to_bashrc "alias sp='searchsploit'"
add_to_bashrc "alias spm='searchsploit -m'"
add_to_bashrc "alias spx='searchsploit -x'"

# ── Tool check ────────────────────────────────
printf '\n'
info "Checking tools..."

readonly TOOLS=(
  nmap
  rustscan
  gobuster
  feroxbuster
  ffuf
  evil-winrm
  impacket-secretsdump
  ligolo-ng
  crackmapexec
  bloodhound
)
MISSING=()

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    printf '  [+] %-25s found\n' "$tool"
  else
    printf '  [!] %-25s MISSING\n' "$tool"
    MISSING+=("$tool")
  fi
done

# ── Install missing tools ─────────────────────
if [[ ${#MISSING[@]} -gt 0 ]]; then
  printf '\n'
  info "Installing missing tools..."
  sudo apt-get update -qq

  for tool in "${MISSING[@]}"; do
    case "$tool" in
      rustscan)
        info "Installing rustscan from GitHub..."
        tmp="$(mktemp -d)"
        if curl -sLo "${tmp}/rustscan.deb" \
            "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb"; then
          sudo dpkg -i "${tmp}/rustscan.deb" && ok "rustscan installed"
        else
          warn "rustscan download failed — install manually"
        fi
        rm -rf "$tmp"
        ;;
      ligolo-ng)
        warn "ligolo-ng — install manually: https://github.com/nicocha30/ligolo-ng"
        ;;
      impacket-secretsdump)
        sudo apt-get install -y -qq python3-impacket impacket-scripts \
          && ok "impacket installed" || warn "impacket install failed"
        ;;
      bloodhound)
        sudo apt-get install -y -qq bloodhound \
          && ok "bloodhound installed" || warn "bloodhound install failed"
        ;;
      *)
        sudo apt-get install -y -qq "$tool" \
          && ok "${tool} installed" || warn "Could not auto-install ${tool}"
        ;;
    esac
  done
fi

# ── Wordlist check ────────────────────────────
printf '\n'
info "Checking wordlists..."

readonly WORDLISTS=(
  "/usr/share/wordlists/rockyou.txt"
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
  "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
  "/usr/share/seclists/Passwords/Common-Credentials/best110.txt"
)

missing_wordlists=0
for wl in "${WORDLISTS[@]}"; do
  if [[ -f "$wl" ]]; then
    printf '  [+] %s\n' "$wl"
  else
    printf '  [!] MISSING: %s\n' "$wl"
    (( missing_wordlists++ )) || true
  fi
done

if [[ ! -d /usr/share/seclists ]]; then
  info "Installing seclists..."
  sudo apt-get install -y -qq seclists && ok "seclists installed" || warn "seclists install failed"
fi

if [[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f /usr/share/wordlists/rockyou.txt ]]; then
  info "Decompressing rockyou..."
  sudo gunzip /usr/share/wordlists/rockyou.txt.gz && ok "rockyou decompressed"
fi

# ── Tools dir ─────────────────────────────────
mkdir -p ~/tools
ok "~/tools/ ready"

# ── Done ──────────────────────────────────────
printf '\n'
ok "Setup complete."
printf '    Reload shell: source ~/.bashrc\n'
printf '    Usage:        cd <target_dir> && source ~/tools/vajra/go.sh <target_ip>\n'
printf '\n'