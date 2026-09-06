#!/usr/bin/env python3
"""
peas_triage.py  v1.0  —  triage linpeas / winpeas output from the CLI.

Paste-free workflow. Run it against a saved PEAS dump and it ranks the
findings that actually matter (token privs, ACL abuse, SUID, sudo, caps,
kerberoastable, creds-in-files, ...) with the abuse hint for each.

  cat peas.txt        | python3 peas_triage.py
  python3 peas_triage.py peas.txt
  python3 peas_triage.py peas.txt --min high        # only high+critical
  python3 peas_triage.py peas.txt --no-color

stdlib only. Strips ANSI colour from PEAS automatically. Runs locally —
no network, nothing uploaded.
"""
import sys, re, argparse

ANSI = re.compile(r'\x1b\[[0-9;]*m')
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
SEV_COLOR = {"critical": "91", "high": "93", "medium": "96", "info": "90"}

PRIV_NOTE = {
    "SeImpersonatePrivilege": "Potato (SigmaPotato/PrintSpoofer/GodPotato) -> SYSTEM",
    "SeAssignPrimaryTokenPrivilege": "Potato -> SYSTEM",
    "SeBackupPrivilege": "Read any file incl. NTDS.dit / SAM hive",
    "SeRestorePrivilege": "Write any file -> replace a service binary",
    "SeDebugPrivilege": "Dump LSASS -> plaintext creds / hashes",
    "SeTakeOwnershipPrivilege": "Take ownership of any file/object",
    "SeLoadDriverPrivilege": "Load a kernel driver -> kernel exploit",
    "SeTcbPrivilege": "Act as the OS — near-SYSTEM",
    "SeCreateTokenPrivilege": "Forge tokens with any privilege",
}
CRIT_PRIVS = list(PRIV_NOTE)
ACL_RIGHTS = ["GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
              "AllExtendedRights", "ForceChangePassword"]

# ── detectors: (id, label, severity, tab, fn(line)->bool) ───────────────
# fn runs per-line; matched lines are collected under the finding.
def _has(*subs):
    return lambda l: any(s.lower() in l.lower() for s in subs)

DETECTORS = [
    # ---- Windows ----
    ("token_privs", "Dangerous Token Privileges", "critical", "potatoes/wincreds",
     lambda l: any(p in l for p in CRIT_PRIVS) and "Enabled" in l),
    ("ad_acl", "AD Object Control (ACL Abuse)", "critical", "adattack",
     lambda l: any(r in l for r in ACL_RIGHTS)),
    ("autologon", "AutoLogon Credentials", "critical", "wincreds",
     _has("DefaultPassword", "AutoAdminLogon")),
    ("always_install", "AlwaysInstallElevated", "critical", "winsvc",
     _has("AlwaysInstallElevated") ),
    ("unquoted", "Unquoted Service Paths", "high", "winsvc",
     lambda l: "unquoted" in l.lower() or ("no quotes" in l.lower() and ".exe" in l.lower())),
    ("writable_service", "Writable / Modifiable Services", "high", "winsvc",
     lambda l: ("service" in l.lower() and any(t in l for t in
               ("FullControl", "WRITE_DAC", "SERVICE_ALL_ACCESS", "Everyone", "Authenticated Users")))),
    ("saved_creds", "Saved Credentials / Vaults", "high", "wincreds",
     _has("cmdkey", "Credential Manager", "vault", ".kdbx", "unattend", "sysprep", "Groups.xml", "cpassword")),
    ("kerberoast", "Kerberoastable Accounts (SPN)", "high", "kerberoast",
     _has("servicePrincipalName", "MSSQLSvc/", "HTTP/", "kerberoast")),
    ("writable_hklm", "Writable HKLM Registry Keys", "medium", "winsvc",
     lambda l: "HKLM" in l and any(t in l for t in ("FullControl", "Write", "Everyone"))),
    ("interesting_files", "Interesting Files", "medium", "winenum",
     _has("Desktop\\", "ConsoleHost_history", "transcript", ".config", "web.config", ".kdbx")),
    # ---- Linux ----
    ("lin_caps", "Dangerous Capabilities", "critical", "suid",
     lambda l: "cap_setuid" in l or "cap_dac_read_search" in l or ("=ep" in l and "cap_" in l)),
    ("lin_writable_sensitive", "Writable /etc/passwd or /etc/shadow", "critical", "linloot",
     lambda l: ("/etc/passwd" in l or "/etc/shadow" in l) and ("Writable" in l or "W " in l or "(w)" in l.lower())),
    ("lin_sudo", "sudo -l Entries", "critical", "sudo",
     lambda l: "NOPASSWD" in l or "(ALL" in l or "(root)" in l),
    ("lin_suid_custom", "Unusual / Custom SUID Binary", "high", "suid",
     lambda l: "-rws" in l and not any(x in l for x in
               ("/bin/mount", "/bin/su", "/bin/ping", "/usr/bin/passwd", "/usr/bin/sudo",
                "/bin/umount", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd"))),
    ("lin_writable_cron", "Writable Cron / Cron PATH Hijack", "high", "cron/wildcard",
     lambda l: ("cron" in l.lower() and ("Writable" in l or "* * *" in l)) or "PATH=" in l and "cron" in l.lower()),
    ("lin_group", "Root-Equivalent Group Membership", "high", "linloot",
     lambda l: bool(re.search(r'\b(docker|lxd|lxc|disk|adm|wheel)\b', l)) and
               ("group" in l.lower() or "groups" in l.lower() or "id=" in l.lower() or "uid=" in l.lower())),
    ("lin_nfs", "NFS no_root_squash", "high", "linloot",
     _has("no_root_squash")),
    ("lin_ssh_keys", "Readable SSH Private Keys", "high", "linloot",
     lambda l: "BEGIN OPENSSH PRIVATE KEY" in l or "BEGIN RSA PRIVATE KEY" in l or "id_rsa" in l),
    ("lin_creds", "Credentials in Files", "high", "linloot/codereview",
     lambda l: bool(re.search(r'(?<!NO)(password|passwd|pwd|secret|api[_-]?key|db_pass|connectionstring)\s*[=:]\s*\S', l, re.I)) and 'NOPASSWD' not in l),
    ("lin_internal", "Localhost-Only Services", "medium", "localhost/discovery",
     lambda l: "127.0.0.1:" in l and "LISTEN" in l.upper()),
    ("lin_kernel", "Kernel Version (exploit-suggester)", "info", "kernelexp",
     lambda l: l.strip().lower().startswith("linux ") and "gnu/linux" not in l.lower()),
    ("lin_dotfiles", "History & Dotfiles", "info", "linloot",
     _has(".bash_history", ".zsh_history", ".mysql_history", ".gitconfig")),
]


def strip_ansi(t): return ANSI.sub("", t)


def triage(lines):
    results = {}  # id -> (label, sev, tab, [lines])
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        for fid, label, sev, tab, fn in DETECTORS:
            try:
                if fn(line):
                    results.setdefault(fid, (label, sev, tab, []))[3].append(line.strip())
            except Exception:
                pass
    return results


def main():
    ap = argparse.ArgumentParser(description="Triage linpeas/winpeas output.")
    ap.add_argument("file", nargs="?", help="PEAS output file (or pipe via stdin)")
    ap.add_argument("--min", choices=["critical", "high", "medium", "info"],
                    default="info", help="minimum severity to show")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--max", type=int, default=8, help="max lines shown per finding")
    a = ap.parse_args()

    data = open(a.file, errors="ignore").read() if a.file else sys.stdin.read()
    lines = strip_ansi(data).splitlines()

    def col(t, c):
        return t if a.no_color else f"\x1b[{c}m{t}\x1b[0m"

    res = triage(lines)
    if not res:
        print(col("[!] no findings matched — check the file is real PEAS output.", "93"))
        return

    minlvl = SEV_ORDER[a.min]
    shown = sorted(res.items(), key=lambda kv: (SEV_ORDER[kv[1][1]], kv[0]))
    shown = [x for x in shown if SEV_ORDER[x[1][1]] <= minlvl]

    print(col(f"\n=== peas_triage — {len(shown)} finding types ===\n", "36"))
    counts = {}
    for fid, (label, sev, tab, hits) in shown:
        counts[sev] = counts.get(sev, 0) + 1
        tag = col(f"[{sev.upper():8}]", SEV_COLOR[sev])
        note = PRIV_NOTE_hint(fid, hits)
        print(f"{tag} {col(label, '1')}   {col('→ tab: ' + tab, '90')}")
        if note:
            print(f"           {col(note, '92')}")
        for h in dict.fromkeys(hits[:a.max]):   # dedupe, cap
            print(f"           {col('·', '90')} {h[:120]}")
        if len(hits) > a.max:
            print(col(f"           … {len(hits) - a.max} more", "90"))
        print()

    summ = "  ".join(col(f"{k}:{v}", SEV_COLOR[k]) for k, v in
                     sorted(counts.items(), key=lambda x: SEV_ORDER[x[0]]))
    print(col("summary: ", "36") + summ)


def PRIV_NOTE_hint(fid, hits):
    """Return the abuse hint for a finding (token privs get per-priv notes)."""
    if fid == "token_privs":
        found = [PRIV_NOTE[p] for p in CRIT_PRIVS if any(p in h for h in hits)]
        return " / ".join(dict.fromkeys(found)) if found else None
    HINTS = {
        "ad_acl": "GenericAll=own it · WriteDacl=grant yourself DCSync · GenericWrite=set SPN/kerberoast",
        "autologon": "plaintext creds in registry — reuse everywhere",
        "always_install": "msfvenom -f msi → msiexec /quiet /i evil.msi = SYSTEM",
        "unquoted": "drop your exe at the first writable space-gap",
        "writable_service": "sc config <svc> binPath= <cmd> ; sc stop/start",
        "saved_creds": "cmdkey /list → runas /savecred ; GPP cpassword → gpp-decrypt",
        "kerberoast": "GetUserSPNs -request → hashcat -m 13100",
        "lin_caps": "cap_setuid → python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'",
        "lin_writable_sensitive": "add a root line to /etc/passwd (openssl passwd)",
        "lin_sudo": "GTFOBins the allowed binary → root",
        "lin_suid_custom": "GTFOBins the binary / strings+ltrace for PATH hijack",
        "lin_writable_cron": "append to the script, or wildcard-inject the globbed dir",
        "lin_group": "docker/lxd = mount host & chroot ; disk = debugfs /dev/sda",
        "lin_nfs": "mount from Kali as root, drop SUID bash",
        "lin_ssh_keys": "chmod 600, ssh in as that user",
        "lin_creds": "spray the cred across users + services",
        "lin_internal": "root service on loopback — exploit on-box, no tunnel needed",
        "lin_kernel": "run linux-exploit-suggester against this version",
    }
    return HINTS.get(fid)


if __name__ == "__main__":
    main()
