#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  vajra/setup.sh — one-time Kali environment config
#  run once on a fresh box: bash setup.sh
# ─────────────────────────────────────────────

# set -u  : treat unset variables as errors
# set -o pipefail : catch failures inside pipes
# NOT set -e : we handle errors per-command so one
#              failure doesn't abort the whole setup
set -uo pipefail

# ── Helpers ───────────────────────────────────
info()    { printf '[*] %s\n' "$*"; }
ok()      { printf '[+] %s\n' "$*"; }
skip()    { printf '[=] %s\n' "$*"; }
warn()    { printf '[!] %s\n' "$*" >&2; }

# ── Guard: must NOT be sourced ────────────────
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  warn "setup.sh should be executed, not sourced:"
  warn "  bash ~/tools/vajra/setup.sh"
  return 1
fi

printf '\n'
info "vajra setup starting..."
printf '\n'

# ── Permanent ulimit in .bashrc ───────────────
if ! grep -q "ulimit -n 5000" ~/.bashrc; then
  printf 'ulimit -n 5000\n' >> ~/.bashrc
  ok "ulimit -n 5000 added to ~/.bashrc"
else
  skip "ulimit already in ~/.bashrc"
fi

# ── Aliases ───────────────────────────────────
ALIAS_FILE="${HOME}/.config/vajra/aliases.sh"
mkdir -p "${HOME}/.config/vajra"

# Note: heredoc uses single-quoted delimiter 'ALIASES' so nothing
# inside expands at write time — aliases are written literally.
# The awk $2 is safe because it only expands when the alias runs.
cat > "$ALIAS_FILE" << 'ALIASES'
# ── vajra aliases ─────────────────────────────

# vajra — per-target engagement setup
# aliased so 'source' is implicit — vars export into current shell
alias go.sh='source ~/tools/vajra/go.sh'

# System shortcuts
alias ll='ls -lah'
alias ports='ss -tulnp'

# tun0 IP — useful when you need $LHOST quickly
alias myip='ip -4 addr show tun0 2>/dev/null | awk "/inet /{split(\$2,a,\"/\"); print a[1]; exit}"'

# HTTP server — serve current directory for file delivery
alias serve='python3 -m http.server 8000'

# Listener — quick nc on 443
alias listen='sudo nc -lvnp 443'

# Feroxbuster — web directory brute against $IP
alias fero='feroxbuster -u "http://${IP}" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o scans/ferox.txt'

# Searchsploit shortcuts
# Note: 'sp' not 'ss' — ss is a system tool (socket stats) on Kali
alias sp='searchsploit'
alias spm='searchsploit -m'
alias spx='searchsploit -x'
ALIASES

if ! grep -q "vajra/aliases.sh" ~/.bashrc; then
  printf '[ -f ~/.config/vajra/aliases.sh ] && source ~/.config/vajra/aliases.sh\n' >> ~/.bashrc
  ok "aliases wired into ~/.bashrc"
else
  skip "aliases already in ~/.bashrc"
fi

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

# Install seclists if any are missing
if [[ ! -d /usr/share/seclists ]]; then
  info "Installing seclists..."
  sudo apt-get install -y -qq seclists && ok "seclists installed" || warn "seclists install failed"
fi

# Decompress rockyou if still gzipped
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
printf '    Usage:        cd <target_dir> && go.sh <target_ip>\n'
printf '\n'
