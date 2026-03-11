#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────
#  pyfix.py — Python 2 → 3 exploit converter
#  part of vajra toolkit: github.com/jimi421/vajra
#
#  usage:
#    pyfix exploit.py            # convert and save as exploit_py3.py
#    pyfix exploit.py --dry-run  # show diff without writing
#    pyfix exploit.py --inplace  # overwrite original (careful)
#    pyfix exploit.py -o out.py  # specify output path
# ─────────────────────────────────────────────────────────────────

import sys
import re
import subprocess
import difflib
import argparse
from pathlib import Path

try:
    from lib2to3.refactor import RefactoringTool, get_fixers_from_package
    HAS_2TO3 = True
except ImportError:
    HAS_2TO3 = False

# ── ANSI colors ───────────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[0m"

def info(msg):  print(f"{B}[*]{W} {msg}")
def ok(msg):    print(f"{G}[+]{W} {msg}")
def warn(msg):  print(f"{Y}[!]{W} {msg}")
def err(msg):   print(f"{R}[-]{W} {msg}")


# ── DETECTION ─────────────────────────────────────────────────────

PY2_SIGNATURES = [
    (r'\bprint\s+"',                        "print statement (double quote)"),
    (r"\bprint\s+'",                        "print statement (single quote)"),
    (r'\bprint\s+[A-Za-z_\(]',             "print statement"),
    (r'\braw_input\s*\(',                   "raw_input()"),
    (r'\bxrange\s*\(',                      "xrange()"),
    (r'\bimport\s+urllib2\b',               "urllib2 import"),
    (r'\bimport\s+httplib\b',               "httplib import"),
    (r'\bimport\s+cookielib\b',             "cookielib import"),
    (r'\bimport\s+ConfigParser\b',          "ConfigParser import"),
    (r'\bimport\s+cPickle\b',               "cPickle import"),
    (r'\bexcept\s+\w+\s*,\s*\w+\s*:',      "except E, e syntax"),
    (r'\bhas_key\s*\(',                     ".has_key()"),
    (r'\biteritems\s*\(',                   ".iteritems()"),
    (r'\bitervalues\s*\(',                  ".itervalues()"),
    (r'\biterkeys\s*\(',                    ".iterkeys()"),
    (r'\bunicode\s*\(',                     "unicode()"),
    (r'\bbasestring\b',                     "basestring"),
    (r'\breduce\s*\(',                      "reduce() (moved to functools)"),
    (r'^\s*exec\s+[^(]',                    "exec statement"),
]

def detect_python_version(code):
    hits = []
    for pattern, label in PY2_SIGNATURES:
        if re.search(pattern, code, re.MULTILINE):
            hits.append(label)
    if hits:
        return "python2", hits
    if re.search(r'print\s*\(|input\s*\(|urllib\.request', code):
        return "python3", []
    return "unknown", []


# ── FIXERS ────────────────────────────────────────────────────────

def fix_shebang(code):
    lines = code.splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        lines[0] = "#!/usr/bin/env python3\n"
    elif lines:
        lines.insert(0, "#!/usr/bin/env python3\n")
    return "".join(lines)


def fix_urllib_imports(code):
    """urllib2, httplib, cookielib, etc → urllib.* / http.*"""
    replacements = [
        # Imports
        (r'import urllib2\b',                   'import urllib.request\nimport urllib.error'),
        (r'import httplib\b',                   'import http.client'),
        (r'import cookielib\b',                 'import http.cookiejar'),
        (r'import ConfigParser\b',              'import configparser'),
        (r'import cPickle\b',                   'import pickle'),
        (r'import Queue\b',                     'import queue'),
        (r'import HTMLParser\b',                'import html.parser'),
        (r'from urllib2 import',                'from urllib.request import'),
        # Usage
        (r'\burllib2\.urlopen\b',               'urllib.request.urlopen'),
        (r'\burllib2\.Request\b',               'urllib.request.Request'),
        (r'\burllib2\.HTTPError\b',             'urllib.error.HTTPError'),
        (r'\burllib2\.URLError\b',              'urllib.error.URLError'),
        (r'\burllib2\.build_opener\b',          'urllib.request.build_opener'),
        (r'\burllib2\.HTTPCookieProcessor\b',   'urllib.request.HTTPCookieProcessor'),
        (r'\burllib\.quote\b',                  'urllib.parse.quote'),
        (r'\burllib\.urlencode\b',              'urllib.parse.urlencode'),
        (r'\bhttplib\.',                        'http.client.'),
        (r'\bcookielib\.',                      'http.cookiejar.'),
        (r'\bConfigParser\.',                   'configparser.'),
        (r'\bcPickle\.',                        'pickle.'),
    ]
    for pattern, replacement in replacements:
        code = re.sub(pattern, replacement, code)
    return code


def fix_print_statements(code):
    """print x → print(x) — handles most common exploit patterns"""
    lines = content_lines = code.splitlines()
    result = []
    print_re = re.compile(r'^(\s*)print\s+(.*)')
    for line in lines:
        m = print_re.match(line)
        if m:
            indent = m.group(1)
            rest = m.group(2).strip()
            # Already a function call — skip
            if rest.startswith('('):
                result.append(line)
                continue
            result.append(f'{indent}print({rest})')
        else:
            result.append(line)
    return "\n".join(result)
def fix_except_syntax(code):
    """except ExcType, e: → except ExcType as e:"""
    return re.sub(
        r'except\s+([A-Za-z_][A-Za-z0-9_.]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*:',
        r'except \1 as \2:',
        code
    )


def fix_has_key(code):
    """d.has_key(k) → k in d"""
    return re.sub(r'(\w+)\.has_key\((.+?)\)', r'\2 in \1', code)


def fix_dict_methods(code):
    """.iteritems() → .items() etc"""
    code = re.sub(r'\.iteritems\(\)', '.items()', code)
    code = re.sub(r'\.itervalues\(\)', '.values()', code)
    code = re.sub(r'\.iterkeys\(\)', '.keys()', code)
    return code


def fix_reduce(code):
    """reduce() → functools.reduce() — add import if needed"""
    if re.search(r'\breduce\s*\(', code) and 'functools' not in code:
        # Add import at top after existing imports
        code = re.sub(
            r'(^import .+$)',
            r'\1\nimport functools',
            code, count=1, flags=re.MULTILINE
        )
    code = re.sub(r'\breduce\s*\(', 'functools.reduce(', code)
    return code


def fix_exec_statement(code):
    """exec code → exec(code)"""
    return re.sub(r'^\s*exec\s+([^(].+)$',
                  lambda m: m.group(0).replace('exec ', 'exec(', 1).rstrip() + ')',
                  code, flags=re.MULTILINE)


def fix_unicode_basestring(code):
    code = re.sub(r'\bunicode\s*\(', 'str(', code)
    code = re.sub(r'\bbasestring\b', 'str', code)
    return code


def fix_hex_byte_strings(code):
    """
    Exploit shellcode strings need to be bytes.
    "\\x90\\x90..." → b"\\x90\\x90..."
    Handles multi-line shellcode arrays.
    """
    # Single-line hex strings not already prefixed with b
    # Match strings containing \\x hex escapes
    # Double-quoted hex strings — not already prefixed with b/r/B/R
    code = re.sub(
        r'(?<![brBR])"((?:\\x[0-9a-fA-F]{2})+(?:[^"\\]|\\[^x]|\\x[0-9a-fA-F]{2})*)"',
        lambda m: f'b"{m.group(1)}"',
        code
    )
    # Single-quoted hex strings
    code = re.sub(
        r"(?<![brBR])'((?:\\x[0-9a-fA-F]{2})+(?:[^'\\]|\\[^x]|\\x[0-9a-fA-F]{2})*)'",
        lambda m: f"b'{m.group(1)}'",
        code
    )
    return code


def fix_padding_strings(code):
    """
    "A" * N  →  b"A" * N
    "\\x41" * N  →  b"\\x41" * N
    Also handles: offset + "A" patterns
    """
    # "A" * <number or variable>
    code = re.sub(r'(?<![brBR])"([A-Za-z\\x0-9]{1,8})"\s*\*\s*(\w+)',
                  r'b"\1" * \2', code)
    code = re.sub(r"(?<![brBR])'([A-Za-z\\x0-9]{1,8})'\s*\*\s*(\w+)",
                  r"b'\1' * \2", code)
    return code


def fix_string_concat_bytes(code):
    """
    Flag mixed str + bytes concatenation patterns common in exploits:
    offset + jmp_esp + shellcode where some are str, some bytes.
    We can't fully auto-fix this without type inference, but we can
    insert a comment flagging the line for manual review.
    """
    # Look for lines that concatenate likely-bytes vars with +
    suspect = re.compile(
        r'^(.*(offset|padding|shellcode|payload|retn|nop|jmp)\s*\+.*)$',
        re.MULTILINE | re.IGNORECASE
    )
    lines = code.splitlines()
    result = []
    for line in lines:
        result.append(line)
        if suspect.match(line) and '# pyfix:' not in line:
            result.append('    # pyfix: verify all operands are bytes (b"...") — mixed str+bytes will crash')
    return "\n".join(result)


def fix_socket_send(code):
    """
    s.send("string") → s.send(b"string") or s.send("string".encode())
    s.sendall("string") → s.sendall(b"string")
    """
    # send("literal string") → send(b"literal string")
    code = re.sub(r'\.send\("(.*?)"\)',     r'.send(b"\1")', code)
    code = re.sub(r"\.send\('(.*?)'\)",     r".send(b'\1')", code)
    code = re.sub(r'\.sendall\("(.*?)"\)',  r'.sendall(b"\1")', code)
    code = re.sub(r"\.sendall\('(.*?)'\)",  r".sendall(b'\1')", code)
    # send(variable) — can't know type, flag it
    code = re.sub(
        r'\.send\(([A-Za-z_][A-Za-z0-9_]*)\)',
        lambda m: f'.send({m.group(1)})  # pyfix: ensure {m.group(1)} is bytes',
        code
    )
    return code


def fix_requests_verify(code):
    """
    Add verify=False to requests calls targeting self-signed certs.
    Only adds if not already present.
    """
    for method in ('get', 'post', 'put', 'patch', 'delete', 'head'):
        pattern = rf'requests\.{method}\(([^)]+)\)'
        def add_verify(m):
            args = m.group(1)
            if 'verify' in args:
                return m.group(0)
            return f'requests.{method}({args}, verify=False)'
        code = re.sub(pattern, add_verify, code)
    return code


# ── LIB2TO3 ───────────────────────────────────────────────────────

def convert_with_2to3(code, filename):
    if not HAS_2TO3:
        warn("lib2to3 not available — skipping automated conversion")
        return code
    try:
        fixers = get_fixers_from_package("lib2to3.fixes")
        tool = RefactoringTool(fixers, options={"print_function": True})
        converted = str(tool.refactor_string(code, filename))
        return converted
    except Exception as e:
        warn(f"lib2to3 failed: {e} — continuing with manual fixers only")
        return code


# ── SYNTAX VERIFICATION ───────────────────────────────────────────

def verify_syntax(filepath):
    try:
        result = subprocess.run(
            ["python3", "-m", "py_compile", str(filepath)],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return True, None
        return False, result.stderr
    except FileNotFoundError:
        return False, "python3 not found"


def check_runtime_hazards(code):
    """
    Check for patterns that compile OK but crash at runtime.
    Returns list of (line_number, warning) tuples.
    """
    hazards = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        # str + bytes concat
        if re.search(r'["\'][A-Za-z0-9 ]+["\'].*\+.*b["\']', line):
            hazards.append((i, "possible str + bytes concat"))
        if re.search(r'b["\'].*\+.*["\'][A-Za-z0-9 ]+["\']', line):
            hazards.append((i, "possible bytes + str concat"))
        # .encode() on already-bytes
        if re.search(r'b["\'].*["\']\.encode\(\)', line):
            hazards.append((i, ".encode() called on bytes literal"))
        # decode without encode
        if re.search(r'\.recv\(\d+\)\s*$', line):
            hazards.append((i, ".recv() returns bytes — decode if comparing to str"))
    return hazards


# ── DIFF ──────────────────────────────────────────────────────────

def show_diff(original, converted, filename):
    diff = list(difflib.unified_diff(
        original.splitlines(keepends=True),
        converted.splitlines(keepends=True),
        fromfile=f"{filename} (original)",
        tofile=f"{filename} (converted)",
        n=2
    ))
    if not diff:
        ok("No changes needed")
        return
    for line in diff:
        if line.startswith('+') and not line.startswith('+++'):
            print(f"{G}{line}{W}", end='')
        elif line.startswith('-') and not line.startswith('---'):
            print(f"{R}{line}{W}", end='')
        elif line.startswith('@@'):
            print(f"{C}{line}{W}", end='')
        else:
            print(line, end='')


# ── PIPELINE ─────────────────────────────────────────────────────

def process(code, filename, add_verify=False):
    """Run all fixers in order. Returns converted code."""
    info("Running lib2to3 base conversion")
    code = convert_with_2to3(code, filename)

    info("Fixing shebang")
    code = fix_shebang(code)

    info("Fixing urllib/httplib/cookielib imports")
    code = fix_urllib_imports(code)

    info("Fixing print statements")
    code = fix_print_statements(code)

    info("Fixing except syntax")
    code = fix_except_syntax(code)

    info("Fixing .has_key() / .iteritems()")
    code = fix_has_key(code)
    code = fix_dict_methods(code)

    info("Fixing unicode/basestring")
    code = fix_unicode_basestring(code)

    info("Fixing exec statement")
    code = fix_exec_statement(code)

    info("Fixing hex/shellcode byte strings")
    code = fix_hex_byte_strings(code)

    info("Fixing padding strings (A * N)")
    code = fix_padding_strings(code)

    info("Fixing socket send encoding")
    code = fix_socket_send(code)

    info("Flagging mixed str+bytes concat")
    code = fix_string_concat_bytes(code)

    if add_verify:
        info("Adding requests verify=False")
        code = fix_requests_verify(code)

    return code


# ── MAIN ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='pyfix',
        description='Python 2 → 3 exploit converter (vajra toolkit)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pyfix exploit.py                  # convert → exploit_py3.py
  pyfix exploit.py --dry-run        # show diff without writing
  pyfix exploit.py --inplace        # overwrite original
  pyfix exploit.py -o fixed.py      # custom output path
  pyfix exploit.py --verify-only    # detect version + syntax check only
  pyfix exploit.py --add-verify     # also add requests verify=False
        """
    )
    parser.add_argument('file', help='exploit script to convert')
    parser.add_argument('--dry-run',      action='store_true', help='show diff, do not write')
    parser.add_argument('--inplace',      action='store_true', help='overwrite original file')
    parser.add_argument('--verify-only',  action='store_true', help='detect and syntax check only')
    parser.add_argument('--add-verify',   action='store_true', help='add requests verify=False to all POST/GET calls')
    parser.add_argument('-o', '--output', help='output file path')
    args = parser.parse_args()

    filepath = Path(args.file)
    if not filepath.exists():
        err(f"File not found: {filepath}")
        sys.exit(1)

    original = filepath.read_text(errors='replace')

    # ── Detect ───────────────────────────────────────────────────
    version, hits = detect_python_version(original)
    print()
    if version == "python2":
        ok(f"Detected: Python 2")
        info(f"Signatures found:")
        for h in hits:
            print(f"    {Y}→{W} {h}")
    elif version == "python3":
        ok("Detected: Python 3 — script may not need conversion")
    else:
        warn("Version unclear — attempting conversion anyway")
    print()

    if args.verify_only:
        # Just syntax check the original
        tmp = filepath.parent / (filepath.stem + "_check.py")
        tmp.write_text(original)
        ok_flag, err_msg = verify_syntax(tmp)
        tmp.unlink()
        if ok_flag:
            ok("Syntax: CLEAN")
        else:
            err("Syntax errors found:")
            print(err_msg)
        sys.exit(0)

    if version == "python3" and not args.dry_run:
        warn("Script appears to be Python 3 already.")
        resp = input("    Convert anyway? [y/N]: ").strip().lower()
        if resp != 'y':
            sys.exit(0)

    # ── Convert ──────────────────────────────────────────────────
    converted = process(original, str(filepath), add_verify=args.add_verify)
    print()

    # ── Dry run — show diff and exit ─────────────────────────────
    if args.dry_run:
        info("Diff (original → converted):")
        print()
        show_diff(original, converted, filepath.name)
        print()
        info("Dry run complete — no files written")
        sys.exit(0)

    # ── Determine output path ─────────────────────────────────────
    if args.inplace:
        out_path = filepath
    elif args.output:
        out_path = Path(args.output)
    else:
        out_path = filepath.parent / (filepath.stem + "_py3.py")

    # ── Write ─────────────────────────────────────────────────────
    out_path.write_text(converted)
    ok(f"Saved → {out_path}")

    # ── Syntax verify ─────────────────────────────────────────────
    info("Verifying syntax")
    ok_flag, err_msg = verify_syntax(out_path)
    if ok_flag:
        ok("Syntax: CLEAN")
    else:
        err("Syntax errors — manual review needed:")
        print(err_msg)

    # ── Runtime hazard scan ───────────────────────────────────────
    hazards = check_runtime_hazards(converted)
    if hazards:
        print()
        warn(f"Runtime hazards detected ({len(hazards)}) — review before running:")
        for lineno, msg in hazards:
            print(f"    {Y}line {lineno:>4}{W}: {msg}")
    else:
        ok("No runtime hazards detected")

    # ── Summary ───────────────────────────────────────────────────
    print()
    info(f"Original:  {filepath}")
    info(f"Converted: {out_path}")
    changes = sum(1 for a, b in zip(original.splitlines(), converted.splitlines()) if a != b)
    info(f"Lines changed: ~{changes}")
    print()
    ok("Done. Review pyfix: comments before running the exploit.")
    print()


if __name__ == "__main__":
    main()
