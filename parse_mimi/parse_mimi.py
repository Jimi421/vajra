#!/usr/bin/env python3
"""
parse_mimi.py  v1.0  —  Mimikatz output parser
Handles: sekurlsa::logonpasswords, lsadump::sam, lsadump::dcsync

Outputs (written next to the input file, or to --outdir):
  <stem>_crack.txt      raw NTLM hashes  →  hashcat -m 1000 / john --format=nt
  <stem>_ref.txt        domain\\user:hash →  reference table, also john user:hash
  <stem>_cleartext.txt  user:pass:domain →  all plaintext (wdigest + credman)

Usage:
  python3 parse_mimi.py mimikatz.txt
  python3 parse_mimi.py mimikatz.txt -o /tmp/loot
  cat mimikatz.txt | python3 parse_mimi.py -
  python3 parse_mimi.py mimikatz.txt -f sam    # force format
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

NULL_NTLM = {
    '00000000000000000000000000000000',
    'aad3b435b51404eeaad3b435b51404ee',  # LM placeholder that leaks into NTLM fields
}
NTLM_RE = re.compile(r'^[0-9a-fA-F]{32}$')

ANSI   = sys.stdout.isatty()
GREEN  = '\033[92m' if ANSI else ''
YELLOW = '\033[93m' if ANSI else ''
CYAN   = '\033[96m' if ANSI else ''
DIM    = '\033[2m'  if ANSI else ''
RESET  = '\033[0m'  if ANSI else ''
BOLD   = '\033[1m'  if ANSI else ''

# ── Data model ───────────────────────────────────────────────────────────────

class Cred:
    __slots__ = ('username', 'domain', 'ntlm', 'cleartext', 'source')

    def __init__(self, username='', domain='', ntlm='', cleartext='', source=''):
        self.username  = username.strip()
        self.domain    = domain.strip()
        self.ntlm      = ntlm.strip().lower()
        self.cleartext = cleartext.strip()
        self.source    = source

    @property
    def valid_ntlm(self) -> bool:
        return bool(NTLM_RE.match(self.ntlm)) and self.ntlm not in NULL_NTLM

    @property
    def has_cleartext(self) -> bool:
        return bool(self.cleartext) and self.cleartext != '(null)'

    @property
    def display_name(self) -> str:
        return f'{self.domain}\\{self.username}' if self.domain else self.username

# ── Format detection ─────────────────────────────────────────────────────────

def detect_format(text: str) -> str:
    if 'Authentication Id' in text or 'sekurlsa::logonpasswords' in text:
        return 'sekurlsa'
    if 'SAM Username' in text or 'lsadump::dcsync' in text:
        return 'dcsync'
    if 'Hash NTLM' in text or 'lsadump::sam' in text or 'SAMKey' in text:
        return 'sam'
    return 'unknown'

# ── Helpers ───────────────────────────────────────────────────────────────────

def star_kvs(text: str) -> dict[str, str]:
    """Extract all '* Key : Value' pairs from a block. First match wins per key."""
    out: dict[str, str] = {}
    for m in re.finditer(r'\*\s+(\w+)\s*:\s*(.+)', text):
        key = m.group(1).lower()
        if key not in out:
            out[key] = m.group(2).strip()
    return out

# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_sekurlsa(text: str) -> list[Cred]:
    """Parse sekurlsa::logonpasswords output."""
    creds: list[Cred] = []
    blocks = re.split(r'(?=Authentication Id\s*:)', text)

    for block in blocks:
        if 'Authentication Id' not in block:
            continue

        # Session-level username/domain from the top of the block
        sess_user = sess_domain = ''
        for line in block.splitlines()[:10]:
            m = re.match(r'\s*User Name\s*:\s*(.+)', line)
            if m: sess_user = m.group(1).strip()
            m = re.match(r'\s*Domain\s*:\s*(.+)', line)
            if m: sess_domain = m.group(1).strip()

        # Split into named subsections.
        # Headers look like: "        msv :"  (6-10 space indent, word, colon, nothing else)
        parts = re.split(r'(?m)^[ \t]{6,10}(\w+)\s*:\s*$', block)
        # parts = [preamble, sec_name, sec_content, sec_name, sec_content, ...]

        i = 1
        while i + 1 < len(parts):
            sec_name    = parts[i].strip().lower()
            sec_content = parts[i + 1]
            i += 2

            # msv — primary NTLM hashes
            if sec_name == 'msv':
                kvs      = star_kvs(sec_content)
                username = kvs.get('username', sess_user)
                domain   = kvs.get('domain',   sess_domain)
                ntlm     = kvs.get('ntlm', '')
                if username:
                    creds.append(Cred(username=username, domain=domain,
                                      ntlm=ntlm, source='msv'))

            # wdigest — cleartext if WDigest is enabled (pre-KB2871997)
            elif sec_name == 'wdigest':
                kvs = star_kvs(sec_content)
                pw  = kvs.get('password', '(null)')
                if pw and pw != '(null)':
                    creds.append(Cred(
                        username=kvs.get('username', sess_user),
                        domain=kvs.get('domain',   sess_domain),
                        cleartext=pw, source='wdigest'))

            # credman — saved RDP/app passwords (the gold — check first)
            elif sec_name == 'credman':
                for entry in re.split(r'\[\d+\]', sec_content):
                    kvs      = star_kvs(entry)
                    username = kvs.get('username', '')
                    domain   = kvs.get('domain',   '')
                    pw       = kvs.get('password', '(null)')
                    if username and pw and pw != '(null)':
                        creds.append(Cred(username=username, domain=domain,
                                          cleartext=pw, source='credman'))

    return creds


def parse_sam(text: str) -> list[Cred]:
    """Parse lsadump::sam output."""
    creds: list[Cred] = []
    # Each account starts with a RID line
    for block in re.split(r'RID\s*:\s*\S+.*\n', text):
        user_m = re.search(r'(?:^|\n)\s*(?:User|Sam Username)\s*:\s*(.+)', block)
        ntlm_m = re.search(r'Hash NTLM\s*:\s*([0-9a-fA-F]{32})', block)
        if user_m:
            creds.append(Cred(
                username=user_m.group(1).strip(),
                ntlm=ntlm_m.group(1) if ntlm_m else '',
                source='sam'))
    return creds


def parse_dcsync(text: str) -> list[Cred]:
    """Parse lsadump::dcsync output."""
    creds: list[Cred] = []
    for block in re.split(r'\*\*\s*SAM ACCOUNT\s*\*\*', text):
        user_m   = re.search(r'SAM Username\s*:\s*(.+)',    block)
        ntlm_m   = re.search(r'Hash NTLM\s*:\s*([0-9a-fA-F]{32})', block)
        domain_m = re.search(r'Object Domain\s*:\s*(.+)',   block)
        if user_m:
            creds.append(Cred(
                username=user_m.group(1).strip(),
                domain=domain_m.group(1).strip() if domain_m else '',
                ntlm=ntlm_m.group(1) if ntlm_m else '',
                source='dcsync'))
    return creds

# ── Output ────────────────────────────────────────────────────────────────────

def write_outputs(creds: list[Cred], outdir: Path,
                  stem: str) -> tuple[Path, Path, Path]:
    seen_hashes: set[str] = set()
    seen_refs:   set[str] = set()
    crack_lines:     list[str] = []
    ref_lines:       list[str] = []
    cleartext_lines: list[str] = []

    for c in creds:
        if c.valid_ntlm:
            if c.ntlm not in seen_hashes:
                seen_hashes.add(c.ntlm)
                crack_lines.append(c.ntlm)
            ref_key = f'{c.username.lower()}:{c.ntlm}'
            if ref_key not in seen_refs:
                seen_refs.add(ref_key)
                ref_lines.append(f'{c.display_name}:{c.ntlm}')
        if c.has_cleartext:
            line = f'{c.display_name}:{c.cleartext}  [{c.source}]'
            if line not in cleartext_lines:
                cleartext_lines.append(line)

    crack_path     = outdir / f'{stem}_crack.txt'
    ref_path       = outdir / f'{stem}_ref.txt'
    cleartext_path = outdir / f'{stem}_cleartext.txt'

    for path, lines in [(crack_path, crack_lines),
                        (ref_path, ref_lines),
                        (cleartext_path, cleartext_lines)]:
        path.write_text('\n'.join(lines) + ('\n' if lines else ''))

    return crack_path, ref_path, cleartext_path


def print_summary(creds: list[Cred], fmt: str,
                  crack_path: Path, ref_path: Path,
                  cleartext_path: Path) -> None:

    ntlm_creds   = [c for c in creds if c.valid_ntlm]
    clear_creds  = [c for c in creds if c.has_cleartext]
    unique_hashes = {c.ntlm for c in ntlm_creds}

    print(f'\n{BOLD}parse_mimi  —  format: {fmt}{RESET}')
    print('─' * 62)
    print(f'  {CYAN}NTLM hashes {RESET}: {len(unique_hashes)} unique  '
          f'({len(ntlm_creds)} total entries)')
    print(f'  {GREEN}Cleartext   {RESET}: {len(clear_creds)} found')
    print()

    # Cleartext first — always highest priority
    if clear_creds:
        print(f'{YELLOW}── CLEARTEXT ────────────────────────────────────────────{RESET}')
        for c in clear_creds:
            tag = f'{DIM}[{c.source}]{RESET}'
            print(f'  {GREEN}{c.display_name:<35}{RESET}  '
                  f'{BOLD}{c.cleartext}{RESET}  {tag}')
        print()

    # NTLM table
    if ntlm_creds:
        seen: set[str] = set()
        print(f'{YELLOW}── NTLM HASHES ──────────────────────────────────────────{RESET}')
        print(f'  {"USER":<35}  {"HASH":<32}  SRC')
        print(f'  {"-"*34}  {"-"*32}  {"-"*7}')
        for c in ntlm_creds:
            key = f'{c.username.lower()}:{c.ntlm}'
            if key in seen:
                continue
            seen.add(key)
            name = c.display_name
            if len(name) > 34:
                name = name[:31] + '...'
            print(f'  {name:<35}  {c.ntlm:<32}  {DIM}{c.source}{RESET}')
        print()

    print(f'{YELLOW}── OUTPUT FILES ─────────────────────────────────────────{RESET}')
    print(f'  {crack_path}')
    print(f'  {ref_path}')
    print(f'  {cleartext_path}')
    print()
    print(f'  {DIM}hashcat -m 1000 {crack_path.name} '
          f'/usr/share/wordlists/rockyou.txt{RESET}')
    print(f'  {DIM}hashcat -m 1000 {crack_path.name} --show{RESET}')
    print(f'  {DIM}john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt '
          f'{crack_path.name}{RESET}')
    print()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Parse mimikatz output into hashcat-ready files.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('infile',
                    help='mimikatz output file (use - for stdin)')
    ap.add_argument('-o', '--outdir', default=None,
                    help='output directory (default: same dir as input)')
    ap.add_argument('-f', '--format',
                    choices=['sekurlsa', 'sam', 'dcsync', 'auto'],
                    default='auto',
                    help='force input format (default: auto-detect)')
    args = ap.parse_args()

    if args.infile == '-':
        text   = sys.stdin.read()
        stem   = 'mimikatz'
        outdir = Path('.')
    else:
        inpath = Path(args.infile)
        if not inpath.exists():
            sys.exit(f'File not found: {inpath}')
        text   = inpath.read_text(errors='replace')
        stem   = inpath.stem
        outdir = inpath.parent

    if args.outdir:
        outdir = Path(args.outdir)
        outdir.mkdir(parents=True, exist_ok=True)

    fmt = args.format if args.format != 'auto' else detect_format(text)
    if fmt == 'unknown':
        print(f'Warning: could not detect format — trying sekurlsa parser',
              file=sys.stderr)
        fmt = 'sekurlsa'

    parsers = {
        'sekurlsa': parse_sekurlsa,
        'sam':      parse_sam,
        'dcsync':   parse_dcsync,
    }
    creds = parsers[fmt](text)

    if not creds:
        print('No credentials parsed. Check format with -f flag.')
        sys.exit(1)

    crack_path, ref_path, cleartext_path = write_outputs(creds, outdir, stem)
    print_summary(creds, fmt, crack_path, ref_path, cleartext_path)


if __name__ == '__main__':
    main()
