# vajra — credential parsing tools

Two scripts that turn messy dump output into ready-to-use files + the exact
next command. Both follow the same idea: **dump to a file → run the script →
copy the printed command.** No manual grep / cut / awk.

---

## parse_ntds.py — secretsdump / NTDS.dit → spray-ready

Turns `impacket-secretsdump` output into aligned user/hash files and prints the
pass-the-hash spray command.

### Use it
```bash
# 1. dump to a file
impacket-secretsdump -ntds NTDS.DIT -system SYSTEM LOCAL > dump.txt

# 2. parse it (pass --dc to bake the IP into the printed command)
python3 parse_ntds.py dump.txt --dc <DC-ip>

# 3. copy the nxc line it prints, run it, look for [+]
```

Or pipe straight in, no file:
```bash
impacket-secretsdump -ntds NTDS.DIT -system SYSTEM LOCAL | python3 parse_ntds.py -
```

### Files it writes (next to the input)
| file | contents | use |
|------|----------|-----|
| `<stem>_users.txt` | one username per line | spray `-u` |
| `<stem>_nt.txt`    | one NT hash per line (aligned with users) | spray `-H` |
| `<stem>_ref.txt`   | `user:hash` pairs | reference / `john --username` |
| `<stem>_crack.txt` | unique NT hashes (empty-password hash excluded) | `hashcat -m 1000` |

### What it prints
- the **spray command** ready to paste:
  `nxc smb <DC> -u <stem>_users.txt -H <stem>_nt.txt --no-bruteforce --continue-on-success`
- the **RID 500** hash flagged for pass-the-hash (own the DC)
- **krbtgt** hash flagged for a golden ticket
- the crack command (optional — AD hashes rarely fall)

### Flags
- `--dc <ip>`   fill the DC IP into the printed commands
- `--machines`  keep `COMPUTER$` accounts (default: dropped)
- `-o <dir>`    write output files somewhere else
- `-`           read from stdin instead of a file

### Reading the spray results
| result | meaning |
|--------|---------|
| `[+] user` | hash VALID — this account is a foothold |
| `(Pwn3d!)` | valid AND local admin — jackpot |
| `STATUS_LOGON_FAILURE` | stale hash (backup predates a password change) |
| `STATUS_PASSWORD_EXPIRED` | valid but forced reset — can't use directly |
| `STATUS_ACCOUNT_DISABLED` | dead account, ignore |

> A backup NTDS is a **snapshot**. Administrator + most users may be stale, but
> 1–2 accounts almost always still have valid hashes — those are your way in.
> Don't stop when Administrator fails. Spray the whole list.

---

## parse_mimi.py — mimikatz output → cracking-ready

Auto-detects `sekurlsa::logonpasswords`, `lsadump::sam`, and `lsadump::dcsync`.

### Use it
```bash
# save mimikatz output to a file (or pipe it), then:
python3 parse_mimi.py mimi.txt
cat mimi.txt | python3 parse_mimi.py -
python3 parse_mimi.py mimi.txt -f sam        # force format if auto-detect misses
```

### Files it writes
| file | contents | use |
|------|----------|-----|
| `<stem>_crack.txt`     | raw NTLM hashes | `hashcat -m 1000` / `john --format=nt` |
| `<stem>_ref.txt`       | `domain\user:hash` | reference table / `john user:hash` |
| `<stem>_cleartext.txt` | `user:pass:domain` | wdigest + credman plaintext |

### What it prints
- **cleartext first** (wdigest / credman) — highest-value loot, needs no cracking
- the NTLM hash table (user → hash → source)
- the hashcat / john commands ready to paste

### Flags
- `-o <dir>`  output directory
- `-f <fmt>`  force `sekurlsa` / `sam` / `dcsync`
- `-`         read from stdin

---

## The workflow both scripts serve

```
dump  →  save to file  →  run parser  →  copy printed command  →  spray / crack
```

- **NTLM hashes from NTDS/secretsdump** → `parse_ntds.py` → pass-the-hash spray
- **mimikatz on a live host** → `parse_mimi.py` → cleartext + PtH + crack

### Golden rule
**Don't crack AD hashes — pass them.** Domain accounts use strong passwords;
rockyou almost always exhausts with zero real hits. The raw NT hash is enough to
authenticate (pass-the-hash). Only crack when you specifically need the plaintext
(e.g. to reuse on a web login or SSH).
