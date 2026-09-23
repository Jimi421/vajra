# ⚡ Vajra

*The thunderbolt — a personal offensive-security toolkit for AD-focused pentesting and OSCP-style labs.*

**Recon → Enumeration → Priv-Esc → Lateral → Loot.** Mostly stdlib-only Python and dependency-light Bash/PowerShell. The whole kit follows one rule: **run it → copy/catch the result.** Every tool prints the exact next command so you're never stuck grepping output at 2am.

> ⚠️ **Authorized use only.** Everything here runs against environments you own or have explicit written permission to test — labs, CTFs, and scoped engagements. Using them anywhere else is illegal, and how you use them is on you.

---

## Why "Vajra"?

In Vedic tradition the *vajra* is Indra's weapon: a thunderbolt that's both indestructible and irresistible. That's the goal — a small, sharp arsenal where each tool does one job, does it reliably, and hands you the next move.

---

## ⚙️ Workflow & Environment

| Tool | What it does |
| --- | --- |
| **setup.sh** | One-time Kali config. Wires aliases and a `myip()` helper into `.bashrc`, bumps the file-descriptor limit, and checks the core toolset is installed (nmap, rustscan, feroxbuster, ffuf, evil-winrm, impacket, ligolo-ng, bloodhound…). |
| **go.sh** | Per-target engagement setup. `source go.sh <ip> [label]` auto-detects `tun0` for LHOST, sets LPORT, builds a clean `scans/exploits/loot/screenshots/tunnels` folder tree, and prints an at-a-glance target banner. |
| **pyfix.py** | Python 2 → 3 exploit converter. Detects Py2 signatures in an exploit-db script and refactors it (`print`, `raw_input`, `urllib2`, `except E, e`, etc.). `--dry-run`, `--inplace`, or writes `*_py3.py`. Turns dead exploits into working ones. |

---

## 🔍 Recon & Initial Access

| Tool | What it does |
| --- | --- |
| **ad_hostmap** | Scans a routed lab subnet, flags the likely DC via Kerberos (88), resolves hostnames over SMB, and writes them straight into `/etc/hosts`. VPN auto-detect (`--auto`), automatic backups, and a clean `--restore`. Drops an IP list ready to feed NetExec. |
| **web_server** (`fileserver.py`) | Zero-dependency, stdlib-only HTTP file server for fast transfers onto a target. |
| **webshell_forge** (`v1.2.0`) | Stack-aware webshell forge (PHP / ASP / ASPX / JSP / CFM / CGI). Stamps a shell into every executable extension with upload-filter bypass variants, writes an `ffuf` wordlist to find which one runs, generates a PHP connect-back (`shellx`) with LHOST/LPORT baked in, and has an encoder mode for injection through hostile boundaries. Menu-driven — just run it. |
| **webshell_extension_changer.sh** | Clones a payload across PHP/CGI bypass extensions (`.phtml`, `.phar`, `.php5`, `.shtml`, `.cgi`…), plus double-extension and case tricks, and emits a filename wordlist + ready-to-run ffuf line. |

---

## 🧭 AD Enumeration

| Tool | What it does |
| --- | --- |
| **ADScoutPS** | Read-only PowerShell AD enumeration module. Native .NET/LDAP, never modifies objects. One command (`Invoke-ADScout`) collects everything into CSV/JSON with a `summary.md` report: recursive group expansion, privileged-membership review, delegation and stale-host hints, SPN accounts, and GPO/OU/ACL/interesting-ACE collection. |

---

## ⬆️ Privilege Escalation & Lateral Movement

| Tool | What it does |
| --- | --- |
| **power_shellz** | Windows operator kit. **Se-privilege abuse** scripts turn a dangerous token into impact: `SeRestore`/`SeTakeOwnership` → SYSTEM shell, `SeBackup` → SAM/NTDS hashes, `SeDebug` → LSASS. Three **lateral-movement paths** (DCOM over 135, WinRM, CIM) so when one's blocked the next is ready, plus `encode.py` for a paste-ready base64 PowerShell reverse shell. Fire-and-forget: start your listener first. |
| **lateral_check** | Two-stage credential validator for spraying safely. Stage 1 confirms the cred negotiates via `impacket-rdp_check`; stage 2 uses NetExec (SMB/WinRM/RDP) to classify *what* the access means. Outputs `pwned.txt` (local admin), `access.txt` (any access), and a full `results.csv` — and stops after N consecutive failures so you don't lock the account. |

---

## ↔️ Pivoting

| Tool | What it does |
| --- | --- |
| **ligolo_setup.sh** | The boring, easy-to-fat-finger Kali-side plumbing around Ligolo-ng. `up` / `route` / `unroute` / `status` / `down`, idempotent tun setup, and multi-tunnel support for double pivots. |

---

## 💥 Loot Parsing

Every parser follows the same idea: **dump to a file → run the script → copy the printed command.** No manual grep / cut / awk.

| Tool | What it does |
| --- | --- |
| **parse_ntds** | Turns `secretsdump` / NTDS.dit output into aligned user + NT-hash files and prints the pass-the-hash spray line. Flags the **RID 500** hash (own the box) and **krbtgt** (golden ticket), and emits a crackable-hashes file for hashcat. |
| **parse_mimi** | Parses raw mimikatz output into clean, filterable credentials. |
| **secrets_dump_parser** (`sd_triage.py`) | Ranks secretsdump output into cleartext creds, usable hashes, what's worth cracking, and ready-to-paste NetExec spray lines. |
| **parse_blood** | Pulls usernames out of a BloodHound export into a spray-ready `users.txt`. |
| **peas_parse** (`peas_triage.py`) | Triages linPEAS/winPEAS dumps — ranks the findings that matter (token privs, ACL abuse, SUID, sudo, caps, kerberoastable, creds-in-files) with an abuse hint for each. `--min high` to cut the noise. |

---

## 🚀 Quick Start

```bash
git clone https://github.com/Jimi421/vajra.git
cd vajra
bash setup.sh                       # one-time Kali config

# per target:
source go.sh 10.10.10.5 boxname     # dirs + LHOST/LPORT + banner
```

Map an AD lab into `/etc/hosts`, then spray:

```bash
sudo ./ad_hostsmap/ad_hostmap.sh --auto
nxc smb ad_hostmap-hosts.txt -u <user> -p <pass>
```

Each tool has its own README/`-h`. Start there.

---

## 🧰 Requirements

Varies by tool; the common ones:

- Linux attack host (Kali / Parrot)
- `python3` — stdlib only for most tools
- `nmap`, `nxc` (NetExec), `impacket` — for host mapping, spraying, and parsing
- PowerShell — for `ADScoutPS` and `power_shellz`

---

## ⚖️ Legal & Scope

For **authorized security testing and education only**. Read-only where it says read-only; nothing destructive by design. Get permission in writing before you point any of it at a system you don't own.

---

*Built and battle-tested in OSCP-style labs. ⚡*
