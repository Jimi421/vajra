#!/usr/bin/env bash
# setup.sh — OSCP toolkit installer
# Idempotent: re-running is safe. Re-downloads only what's missing
# unless --force is passed.
#
# Usage:
#   ./setup.sh              # install into $HOME/oscp-tools
#   ./setup.sh --force      # refresh everything (git pulls, re-downloads)
#   ./setup.sh --core       # only core/exam-day tools, skip the rest
#   OSCP_TOOLS_DIR=/opt/tools ./setup.sh   # custom location

set -u

# ─── config ──────────────────────────────────────────────────────────
: "${OSCP_TOOLS_DIR:=$HOME/oscp-tools}"
FORCE=0
CORE_ONLY=0
LOG="$OSCP_TOOLS_DIR/setup.log"

# colors
if [ -t 1 ]; then
    R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[36m'; N=$'\033[0m'
else
    R=''; G=''; Y=''; B=''; N=''
fi

# stats
ok=0; skip=0; fail=0

# ─── arg parsing ─────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --core)  CORE_ONLY=1 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# //;s/^#//'
            exit 0
            ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

# ─── setup ───────────────────────────────────────────────────────────
mkdir -p "$OSCP_TOOLS_DIR" || { echo "Cannot create $OSCP_TOOLS_DIR"; exit 1; }
: > "$LOG"

echo "${B}[+]${N} Target:  $OSCP_TOOLS_DIR"
echo "${B}[+]${N} Mode:    $([ "$FORCE" = 1 ] && echo "force-refresh" || echo "incremental")$([ "$CORE_ONLY" = 1 ] && echo " (core only)")"
echo "${B}[+]${N} Log:     $LOG"
echo "${B}[+]${N} Starting..."
echo

# ─── helpers ─────────────────────────────────────────────────────────
log() { echo "$@" >> "$LOG"; }

# clone_or_pull <category> <name> <url>
clone_or_pull() {
    local cat="$1" name="$2" url="$3"
    local dir="$OSCP_TOOLS_DIR/$cat/$name"
    local label="$cat/$name"

    mkdir -p "$OSCP_TOOLS_DIR/$cat"
    log "=== $label === $url"

    if [ -d "$dir/.git" ]; then
        if [ "$FORCE" = 1 ]; then
            printf "${B}[..]${N}   %-40s (git pull) " "$label"
            if (cd "$dir" && git pull --ff-only 2>>"$LOG" >>"$LOG"); then
                echo "${G}OK${N}"; ((ok++))
            else
                echo "${R}FAIL${N}"; ((fail++))
            fi
        else
            echo "${Y}[SKIP]${N} $label (already cloned; --force to update)"
            ((skip++))
        fi
    else
        printf "${B}[..]${N}   %-40s (git clone) " "$label"
        if git clone --depth=1 "$url" "$dir" 2>>"$LOG" >>"$LOG"; then
            echo "${G}OK${N}"; ((ok++))
        else
            echo "${R}FAIL${N}"; ((fail++))
        fi
    fi
}

# download_file <category> <filename> <url>
download_file() {
    local cat="$1" name="$2" url="$3"
    local path="$OSCP_TOOLS_DIR/$cat/$name"
    local label="$cat/$name"

    mkdir -p "$OSCP_TOOLS_DIR/$cat"
    log "=== $label === $url"

    if [ -f "$path" ] && [ "$FORCE" != 1 ]; then
        echo "${Y}[SKIP]${N} $label (exists; --force to refresh)"
        ((skip++))
        return
    fi

    printf "${B}[..]${N}   %-40s (download)  " "$label"
    if curl -sL --fail "$url" -o "$path" 2>>"$LOG"; then
        # mark executable if it looks like one
        case "$name" in
            *.exe|*.dll) ;;
            *) chmod +x "$path" 2>/dev/null ;;
        esac
        echo "${G}OK${N}"; ((ok++))
    else
        echo "${R}FAIL${N} (see log)"; ((fail++))
        rm -f "$path"  # don't leave half-downloaded files
    fi
}

# copy_local <category> <filename> — copies from ./tools/$filename
copy_local() {
    local cat="$1" name="$2"
    local src="$(dirname "$0")/tools/$name"
    local dst="$OSCP_TOOLS_DIR/$cat/$name"
    local label="$cat/$name"

    mkdir -p "$OSCP_TOOLS_DIR/$cat"

    if [ ! -f "$src" ]; then
        echo "${R}[FAIL]${N} $label (source not found: $src)"; ((fail++))
        return
    fi

    if [ -f "$dst" ] && [ "$FORCE" != 1 ]; then
        echo "${Y}[SKIP]${N} $label (exists; --force to refresh)"; ((skip++))
        return
    fi

    cp "$src" "$dst" && chmod +x "$dst" 2>/dev/null
    echo "${G}[OK]${N}   $label (copied)"
    ((ok++))
}

# ─── CORE TOOLS (always installed) ───────────────────────────────────
echo "${B}── recon ──${N}"
clone_or_pull recon linpeas https://github.com/peass-ng/PEASS-ng.git
download_file recon kerbrute_linux_amd64 \
    https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
download_file recon nmap-vulners.nse \
    https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse

echo
echo "${B}── privesc-linux ──${N}"
clone_or_pull privesc-linux PwnKit https://github.com/ly4k/PwnKit.git
clone_or_pull privesc-linux linux-exploit-suggester https://github.com/mzet-/linux-exploit-suggester.git
clone_or_pull privesc-linux linux-smart-enumeration https://github.com/diego-treitos/linux-smart-enumeration.git
download_file privesc-linux pspy64 \
    https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
download_file privesc-linux pspy32 \
    https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32

echo
echo "${B}── privesc-windows ──${N}"
clone_or_pull privesc-windows PowerUp \
    https://github.com/PowerShellMafia/PowerSploit.git
download_file privesc-windows PrintSpoofer64.exe \
    https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe
download_file privesc-windows PrintSpoofer32.exe \
    https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer32.exe
download_file privesc-windows GodPotato-NET4.exe \
    https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe
download_file privesc-windows winPEASx64.exe \
    https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe
download_file privesc-windows winPEASany.exe \
    https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe
download_file privesc-windows winPEAS.bat \
    https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat

echo
echo "${B}── ad ──${N}"
download_file ad Rubeus.exe \
    https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
download_file ad SharpHound.exe \
    https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound-v2.5.13.zip
download_file ad mimikatz.exe \
    https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
clone_or_pull ad impacket-examples https://github.com/fortra/impacket.git
clone_or_pull ad BloodHound.py https://github.com/dirkjanm/BloodHound.py.git
clone_or_pull ad PetitPotam https://github.com/topotam/PetitPotam.git
clone_or_pull ad PKINITtools https://github.com/dirkjanm/PKINITtools.git

echo
echo "${B}── pivoting ──${N}"
download_file pivoting chisel_linux_amd64.gz \
    https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_linux_amd64.gz
download_file pivoting chisel_windows_amd64.gz \
    https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_windows_amd64.gz
download_file pivoting ligolo-ng_proxy.tar.gz \
    https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.7.4_linux_amd64.tar.gz
download_file pivoting ligolo-ng_agent_linux.tar.gz \
    https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.7.4_linux_amd64.tar.gz
download_file pivoting ligolo-ng_agent_windows.zip \
    https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.7.4_windows_amd64.zip
clone_or_pull pivoting sshuttle https://github.com/sshuttle/sshuttle.git

# ─── EXTENDED TOOLS (skip with --core) ───────────────────────────────
if [ "$CORE_ONLY" != 1 ]; then
    echo
    echo "${B}── web ──${N}"
    clone_or_pull web webshells https://github.com/tennc/webshell.git
    clone_or_pull web PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings.git
    download_file web php-reverse-shell.php \
        https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
    clone_or_pull web nishang https://github.com/samratashok/nishang.git

    echo
    echo "${B}── shells ──${N}"
    clone_or_pull shells revshells-offline https://github.com/0dayCTF/reverse-shell-generator.git

    echo
    echo "${B}── recon-extras ──${N}"
    clone_or_pull recon-extras gobuster-wordlists https://github.com/danielmiessler/SecLists.git
fi

# ─── CUSTOM SCRIPTS (always installed) ───────────────────────────────
echo
echo "${B}── custom (your scripts) ──${N}"
copy_local custom zodiac.sh
copy_local custom colors.sh
copy_local custom brute-tcp-template.sh
copy_local custom exploit-template.py

# ─── done ────────────────────────────────────────────────────────────
echo
echo "${B}[+]${N} ${G}$ok OK${N} / ${Y}$skip SKIP${N} / ${R}$fail FAIL${N}"
echo "${B}[+]${N} Tree: $OSCP_TOOLS_DIR"
echo "${B}[+]${N} Log:  $LOG"

if [ "$fail" -gt 0 ]; then
    echo
    echo "${R}[!]${N} Some downloads failed. Common causes:"
    echo "    - Network/VPN issues (retry with: ./setup.sh)"
    echo "    - Release URL changed (check the project's releases page)"
    echo "    - GitHub rate-limited you (wait ~1hr or set GITHUB_TOKEN)"
    echo "    See $LOG for the exact errors."
    exit 1
fi

# Suggest next steps
echo
echo "${B}[+]${N} Add to your shell rc for quick access:"
echo "      export OSCP_TOOLS=$OSCP_TOOLS_DIR"
echo "      alias serve='cd \$OSCP_TOOLS && python3 -m http.server 8000'"
