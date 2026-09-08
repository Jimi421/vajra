#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  ligolo_setup.sh — the boring Kali-side plumbing around Ligolo-NG
#  part of vajra toolkit
#
#  Ligolo itself is interactive (your notes own that). This just
#  handles the sudo-heavy tun interface + route work that's identical
#  every engagement and easy to fat-finger.
#
#  usage:
#    ./ligolo_setup.sh up   [iface]              create + bring up (default: tunnel1)
#    ./ligolo_setup.sh route <subnet> [iface]    add a route through the tunnel
#    ./ligolo_setup.sh unroute <subnet> [iface]  remove one route
#    ./ligolo_setup.sh status                    show tun ifaces + ligolo routes
#    ./ligolo_setup.sh down [iface]              tear down (routes + iface)
#
#  examples:
#    ./ligolo_setup.sh up                        # tunnel1, ready for the proxy
#    ./ligolo_setup.sh route 172.16.5.0/24       # route internal subnet
#    ./ligolo_setup.sh up tunnel2                # second tun for a double-pivot
#    ./ligolo_setup.sh route 10.10.20.0/24 tunnel2
#    ./ligolo_setup.sh down                      # clean up when done
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; D='\033[0;90m'; N='\033[0m'
ok(){   echo -e "${G}[+]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[-]${N} $*" >&2; }

DEFAULT_IFACE="tunnel1"

need_root(){
  if [[ $EUID -ne 0 ]]; then
    # re-exec the exact command under sudo so the user isn't prompted twice
    exec sudo -E "$0" "$@"
  fi
}

iface_exists(){ ip link show "$1" &>/dev/null; }

subnet_ok(){
  # crude CIDR sanity: x.x.x.x/nn
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]
}

cmd_up(){
  local iface="${1:-$DEFAULT_IFACE}"
  need_root up "$iface"
  if iface_exists "$iface"; then
    warn "$iface already exists — bringing it up (idempotent)"
  else
    info "creating tun interface: ${iface}"
    ip tuntap add user root mode tun "$iface"
    ok "created ${iface}"
  fi
  ip link set "$iface" up
  ok "${iface} is UP"
  echo
  info "next steps (your ligolo notes own these):"
  echo -e "  ${D}# start the proxy (separate terminal):${N}"
  echo -e "  ${C}sudo ./ligolo-ng-proxy-linux-amd64 --selfcert${N}"
  echo -e "  ${D}# connect the agent from the target, then in the proxy:${N}"
  echo -e "  ${C}session${N}  →  ${C}start --tun ${iface}${N}"
  echo -e "  ${D}# then add the internal subnet:${N}"
  echo -e "  ${C}./ligolo_setup.sh route <SUBNET> ${iface}${N}"
}

cmd_route(){
  local subnet="${1:-}" iface="${2:-$DEFAULT_IFACE}"
  [[ -z "$subnet" ]] && { err "usage: $0 route <subnet> [iface]"; exit 1; }
  subnet_ok "$subnet" || { err "'$subnet' doesn't look like a CIDR (e.g. 172.16.5.0/24)"; exit 1; }
  need_root route "$subnet" "$iface"
  iface_exists "$iface" || { err "$iface doesn't exist — run: $0 up $iface"; exit 1; }
  if ip route show | grep -q "^${subnet} dev ${iface}"; then
    warn "route ${subnet} → ${iface} already present"
  else
    ip route add "$subnet" dev "$iface"
    ok "routed ${subnet} → ${iface}"
  fi
  echo
  info "verify reachability through the tunnel:"
  echo -e "  ${C}nxc smb ${subnet} --generate-hosts-file tunnel_hosts.txt${N}"
  echo -e "  ${D}# or a quick ping sweep once the agent session is bound${N}"
}

cmd_unroute(){
  local subnet="${1:-}" iface="${2:-$DEFAULT_IFACE}"
  [[ -z "$subnet" ]] && { err "usage: $0 unroute <subnet> [iface]"; exit 1; }
  need_root unroute "$subnet" "$iface"
  if ip route show | grep -q "^${subnet} dev ${iface}"; then
    ip route del "$subnet" dev "$iface"
    ok "removed route ${subnet} → ${iface}"
  else
    warn "no such route ${subnet} → ${iface}"
  fi
}

cmd_status(){
  echo -e "${C}=== tun interfaces ===${N}"
  ip -br link show type tun 2>/dev/null | grep -v '^tun0' || echo -e "  ${D}none (besides tun0/VPN)${N}"
  echo
  echo -e "${C}=== ligolo routes (dev tunnel*/ligolo*) ===${N}"
  ip route show | grep -E 'dev (tunnel|ligolo)' || echo -e "  ${D}none${N}"
  echo
  echo -e "${C}=== your VPN (tun0) ===${N}"
  ip -br addr show tun0 2>/dev/null || echo -e "  ${D}tun0 not up${N}"
}

cmd_down(){
  local iface="${1:-$DEFAULT_IFACE}"
  need_root down "$iface"
  if ! iface_exists "$iface"; then
    warn "$iface doesn't exist — nothing to tear down"; return
  fi
  # remove any routes pointing at this iface first
  local routes
  routes=$(ip route show | awk -v i="$iface" '$0 ~ "dev "i {print $1}')
  if [[ -n "$routes" ]]; then
    while read -r s; do
      [[ -n "$s" ]] && ip route del "$s" dev "$iface" && ok "removed route $s"
    done <<< "$routes"
  fi
  ip link set "$iface" down
  ip tuntap del mode tun "$iface"
  ok "tore down ${iface} (interface + routes)"
}

usage(){
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

main(){
  local action="${1:-}"; shift || true
  case "$action" in
    up)      cmd_up "$@";;
    route)   cmd_route "$@";;
    unroute) cmd_unroute "$@";;
    status)  cmd_status "$@";;
    down)    cmd_down "$@";;
    ""|-h|--help|help) usage;;
    *) err "unknown action: $action"; echo; usage; exit 1;;
  esac
}
main "$@"
