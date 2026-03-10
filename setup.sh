#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  vajra/setup.sh — one-time Kali environment config
#  run once on a fresh box: bash setup.sh
# ─────────────────────────────────────────────

set -e

echo "[*] vajra setup starting..."
echo ""

# ── Permanent ulimit in .bashrc ───────────────
if ! grep -q "ulimit -n 5000" ~/.bashrc; then
  echo "ulimit -n 5000" >> ~/.bashrc
  echo "[+] ulimit -n 5000 added to ~/.bashrc"
else
  echo "[=] ulimit already in ~/.bashrc"
fi

# ── Aliases ───────────────────────────────────
ALIAS_FILE="$HOME/.config/vajra/aliases.sh"
mkdir -p "$HOME/.config/vajra"

cat > "$ALIAS_FILE" << 'ALIASES'
# ── vajra aliases ────────────────────────────
alias ll='ls -lah'
alias ports='ss -tulnp'
alias myip='ip -4 addr show tun0 2>/dev/null | awk "/inet /{print \$2}" | cut -d/ -f1'

# vajra — per-target engagement setup
alias go.sh='source ~/tools/vajra/go.sh'

# HTTP server — serve current directory
alias serve='python3 -m http.server 8000'

# Quick listener
alias listen='sudo nc -lvnp 443'

# Feroxbuster quick web enum
alias fero='feroxbuster -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o scans/ferox.txt'

# Searchsploit — copy to CWD
alias ss='searchsploit'
alias ssm='searchsploit -m'
alias ssx='searchsploit -x'
ALIASES

if ! grep -q "vajra/aliases.sh" ~/.bashrc; then
  echo "[ -f ~/.config/vajra/aliases.sh ] && source ~/.config/vajra/aliases.sh" >> ~/.bashrc
  echo "[+] aliases sourced from ~/.config/vajra/aliases.sh"
else
  echo "[=] aliases already wired in ~/.bashrc"
fi

# ── Tool check ────────────────────────────────
echo ""
echo "[*] Checking tools..."
TOOLS=(nmap rustscan gobuster feroxbuster ffuf evil-winrm impacket-secretsdump ligolo-ng crackmapexec bloodhound)
MISSING=()

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    printf "  [+] %-25s found\n" "$tool"
  else
    printf "  [!] %-25s MISSING\n" "$tool"
    MISSING+=("$tool")
  fi
done

# ── Install missing tools ─────────────────────
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  echo "[*] Installing missing tools..."
  sudo apt-get update -qq

  for tool in "${MISSING[@]}"; do
    case "$tool" in
      rustscan)
        echo "[*] Installing rustscan..."
        curl -sLO https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb
        sudo dpkg -i rustscan_amd64.deb && rm rustscan_amd64.deb
        ;;
      ligolo-ng)
        echo "[!] ligolo-ng — install manually from https://github.com/nicocha30/ligolo-ng"
        ;;
      bloodhound)
        sudo apt-get install -y -qq bloodhound
        ;;
      impacket-secretsdump)
        sudo apt-get install -y -qq python3-impacket impacket-scripts
        ;;
      *)
        sudo apt-get install -y -qq "$tool" 2>/dev/null || echo "[!] Could not auto-install $tool"
        ;;
    esac
  done
fi

# ── Wordlist check ────────────────────────────
echo ""
echo "[*] Checking wordlists..."
WORDLISTS=(
  "/usr/share/wordlists/rockyou.txt"
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
  "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
  "/usr/share/seclists/Passwords/Common-Credentials/best110.txt"
)

for wl in "${WORDLISTS[@]}"; do
  if [[ -f "$wl" ]]; then
    printf "  [+] %s\n" "$wl"
  else
    printf "  [!] MISSING: %s\n" "$wl"
  fi
done

if [[ ! -d /usr/share/seclists ]]; then
  echo "[*] Installing seclists..."
  sudo apt-get install -y -qq seclists
fi

if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
  echo "[*] Decompressing rockyou..."
  sudo gunzip /usr/share/wordlists/rockyou.txt.gz
fi

# ── Tools dir ─────────────────────────────────
mkdir -p ~/tools
echo "[+] ~/tools/ ready"

# ── Done ──────────────────────────────────────
echo ""
echo "[+] Setup complete. Reload shell or run: source ~/.bashrc"
echo "[+] Usage: cd <target_dir> && go.sh <target_ip>"
echo ""
