<h1 align="center">⚡ Vajra</h1> <p align="center"> <em>The thunderbolt — a personal offensive-security toolkit for AD-focused pentesting and OSCP-style labs.</em> </p> <p align="center"> <strong>Recon → Enumeration → Exploitation → Post-Ex → Pivot</strong><br> Mostly stdlib-only Python and dependency-light Bash. Built to be dropped onto a box and just work. </p>

⚠️ Authorized use only. Every tool here is for environments you own or have explicit written permission to test — labs, CTFs, and sanctioned engagements. Using them anywhere else is illegal. You are responsible for how you use this.

Why "Vajra"?

In Vedic tradition the vajra is Indra's weapon: a thunderbolt that is both indestructible and irresistible. That's the goal here — a small, sharp arsenal that does one job per tool and does it reliably under pressure, when you're deep in a lab at 2am and need it to just run.

🗂️ The Arsenal
🔍 Recon & Initial Access
Tool	What it does
ad_hostmap	Bash. Scans a routed lab subnet, flags the likely DC via Kerberos (88), resolves hostnames over SMB, and writes them straight into /etc/hosts. VPN auto-detect (--auto), backups, and a clean --restore.
web_server (fileserver.py)	Zero-dependency, stdlib-only HTTP file server for fast transfers onto a target — no python -m http.server limitations.
webshell_forge	Stack-aware webshell generator (PHP / ASP / ASPX / JSP / CFM / CGI). cmd and reverse templates, tun0 auto-LHOST, upload-filter bypass variants (double-ext, case, trailing, magic-byte), ffuf wordlist output, and an encoder mode for command injection through hostile boundaries.
webshell_extension_changer.sh	Bulk-rename webshell payloads across extensions to defeat upload filters.
🧭 Enumeration
Tool	What it does
ADScoutPS	Read-only PowerShell AD enumeration module. Native .NET/LDAP, never modifies objects. One-command collection (Invoke-ADScout) with CSV/JSON exports, a summary.md report, recursive group expansion, privileged-membership review, delegation and stale-host hints, and GPO/OU/ACL/interesting-ACE collection.
power_shellz	Collection of PowerShell scripts and payloads for on-host enumeration and execution.
💥 Post-Exploitation & Loot Parsing
Tool	What it does
parse_mimi	Parses raw mimikatz output into clean, filterable creds.
parse_ntds	Parses NTDS dumps into usable hash/user lists.
secrets_dump_parser	Cleans up secretsdump.py output for triage and cracking.
parse_blood	Post-processes BloodHound data for quick answers.
peas_parse	Cuts linPEAS/winPEAS noise down to the findings that matter.
↔️ Lateral Movement & Pivoting
Tool	What it does
lateral_check	Fast checks for lateral-movement opportunities across mapped hosts.
ligolo_setup.sh	One-shot setup for Ligolo-ng tunneling so you can pivot into internal subnets.
🚀 Quick Start
bash
git clone https://github.com/Jimi421/vajra.git
cd vajra
./setup.sh          # install / stage the toolkit

Example — map an AD lab straight into /etc/hosts:

bash
sudo ./ad_hostsmap/ad_hostmap.sh --auto
nxc smb ad_hostmap-hosts.txt -u <user> -p <pass>

Example — serve a file onto a target:

bash
python3 web_server/fileserver.py

Each tool has its own usage. Run a script with -h/--help, or check its folder for details.

🧰 Requirements

Varies by tool, but the common ones:

Linux attack host (Kali / ParrotOS)
python3 (stdlib only for most tools)
nmap, nxc (NetExec) — for ad_hostmap
PowerShell on the target/host running ADScoutPS
⚖️ Legal & Scope

This toolkit is for authorized security testing and education only. Read-only where it says read-only; destructive nowhere by design. Get permission in writing before you point any of it at a system you don't own.

<p align="center"><sub>Built and battle-tested in OSCP-style labs. ⚡</sub></p>
