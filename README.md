# vajra

Kali setup and per-target engagement scripts for OSCP.  
Clone, run once, go fast.

```bash
git clone git@github.com:jimi421/vajra.git ~/tools/vajra
bash ~/tools/vajra/setup.sh
```

After setup, `go.sh` is available as an alias from anywhere:

```bash
cd ~/labs/access
go.sh 10.10.10.10
```

---

## Scripts

### `setup.sh` — run once on a fresh box

- Adds `ulimit -n 5000` permanently to `.bashrc`
- Installs and checks tools: nmap, rustscan, gobuster, feroxbuster, ffuf, evil-winrm, impacket, ligolo-ng, crackmapexec, bloodhound
- Checks and installs seclists + rockyou
- Wires aliases into `.bashrc`

```bash
bash setup.sh
```

---

### `go.sh` — run per target

Takes an IP, exports environment variables, builds the results folder, sets ulimit, and fires a background scan immediately.

**Must be sourced** to export variables into your shell. After running `setup.sh`, the `go.sh` alias handles this automatically. Drops folder structure in your **current directory** — navigate to your target folder first:

```bash
cd ~/labs/machine1
go.sh 10.10.10.10
```

Or call it directly:

```bash
source ~/tools/vajra/go.sh 10.10.10.10
```

What it does:
- Exports `$IP`, `$LHOST`, `$LPORT`
- Creates `~/results/$IP/{scans,exploits,loot,screenshots,tunnels}`
- `cd` into the target dir
- `ulimit -n 5000`
- Launches rustscan (or nmap fallback) in background → `scans/`
- Prints a summary banner so you can verify vars at a glance

---

## Aliases (loaded via `setup.sh`)

| alias | command |
|-------|---------|
| `serve` | `python3 -m http.server 8000` |
| `listen` | `sudo nc -lvnp 443` |
| `results` | `cd ~/results` |
| `myip` | detect tun0/eth0 IP |
| `ports` | `ss -tulnp` |
| `fero` | feroxbuster with raft-medium against `$IP` |
| `ss` / `ssm` / `ssx` | searchsploit / mirror / examine |

---

## Results folder structure

```
~/results/
└── <target_ip>/
    ├── scans/
    ├── exploits/
    ├── loot/
    ├── screenshots/
    └── tunnels/
```

---

## Note

`go.sh` must be **sourced**, not executed, so the exports persist in your shell:

```bash
# correct
source ~/vajra/go.sh 10.10.10.10

# also correct
. ~/vajra/go.sh 10.10.10.10

# wrong — variables won't persist
bash ~/vajra/go.sh 10.10.10.10
```
