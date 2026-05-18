# AD Hostmap

`ad_hostmap.sh` is a Bash operator utility for Active Directory labs. It discovers live hosts on a routed lab subnet, resolves SMB hostnames with NetExec, and safely updates `/etc/hosts` so you can start AD enumeration using clean hostnames like `DC1`, `WEB04`, and `CLIENT75`.

Built for OSCP-style AD labs, internal lab environments, and authorized assessments.

---

## Why This Tool Exists

In AD labs, hostname resolution matters.

You may be able to ping an IP directly:

```bash
ping 192.168.110.70
```

But hostname-based tools may fail if `/etc/hosts` is stale:

```bash
ping DC1
nxc smb DC1
nxc ldap DC1
evil-winrm -i DC1
```

A common problem is an old entry like this:

```text
192.168.141.70     DC1.corp.com corp.com DC1
```

while the current lab is actually:

```text
192.168.110.70     DC1.corp.com corp.com DC1
```

`ad_hostmap.sh` fixes this by rebuilding your AD host mappings automatically.

---

## Features

- Discovers live hosts with `nmap`
- Resolves SMB hostnames with NetExec `nxc`
- Updates `/etc/hosts` with a managed AD host block
- Removes stale hostname entries outside the managed block
- Removes older `AD_LAB_HOSTS` blocks from previous versions
- Backs up `/etc/hosts` before every write
- Uses route-based subnet detection instead of relying on the `tun0` IP
- Supports target IP mode
- Supports interface route mode
- Supports automatic VPN route mode
- Supports manual CIDR mode
- Includes restore mode
- Validates hostname resolution after updating

---

## Requirements

Required tools:

```text
nmap
nxc
python3
awk
ip
getent
sudo
```

Install common dependencies:

```bash
sudo apt update
sudo apt install -y nmap python3
```

Install NetExec if needed:

```bash
pipx install git+https://github.com/Pennyw0rth/NetExec
```

Verify tools:

```bash
command -v nmap
command -v nxc
command -v python3
command -v ip
command -v getent
```

---

## Installation

Clone or create the tool folder:

```bash
mkdir -p ~/Projects/dev/scripts/oscp_tools/ad_hostmap
cd ~/Projects/dev/scripts/oscp_tools/ad_hostmap
```

Create the script:

```bash
nano ad_hostmap.sh
```

Paste the script, then make it executable:

```bash
chmod +x ad_hostmap.sh
```

Optional: symlink it into your PATH:

```bash
sudo ln -sf "$PWD/ad_hostmap.sh" /usr/local/bin/ad_hostmap
```

Now you can run:

```bash
ad_hostmap --help
```

---

## Usage

### Best Mode: Target IP

Use this when you know one live lab IP, usually the domain controller.

```bash
sudo ./ad_hostmap.sh --target 192.168.110.70
```

Short version:

```bash
sudo ./ad_hostmap.sh -t 192.168.110.70
```

This mode checks your route table and derives the routed lab subnet.

Example:

```text
[*] Mode: target route detection
[*] Target IP: 192.168.110.70
[*] Selected scan network: 192.168.110.0/24
```

This is the recommended mode for most AD labs.

---

### Interface Route Mode

Use this when you know the VPN interface:

```bash
sudo ./ad_hostmap.sh --iface tun0
```

Short version:

```bash
sudo ./ad_hostmap.sh -i tun0
```

Important: this does **not** use the `tun0` IP address as the lab subnet.

Instead, it checks routes behind `tun0`.

That matters because your tunnel IP may be something like:

```text
10.10.14.5/23
```

while your actual AD lab subnet is routed behind it:

```text
192.168.110.0/24 dev tun0
```

---

### Auto Mode

Use this when you want the script to find a VPN-style interface automatically:

```bash
sudo ./ad_hostmap.sh --auto
```

The script looks for interfaces like:

```text
tun0
tap0
wg0
ppp0
```

Then it checks for private routed lab networks behind them.

---

### Manual CIDR Mode

Use this when you already know the subnet:

```bash
sudo ./ad_hostmap.sh 192.168.110.0/24
```

---

### Restore Mode

Remove managed AD hostmap blocks from `/etc/hosts`:

```bash
sudo ./ad_hostmap.sh --restore
```

This removes:

```text
# BEGIN AD_HOSTMAP
# END AD_HOSTMAP
```

It also removes older blocks from previous versions:

```text
# BEGIN AD_LAB_HOSTS
# END AD_LAB_HOSTS
```

It does not wipe your entire `/etc/hosts` file.

---

### Help Menu

```bash
./ad_hostmap.sh --help
```

Version check:

```bash
./ad_hostmap.sh --version
```

---

## Example Workflow

Start with one known DC IP:

```bash
ping -c 3 192.168.110.70
```

Run AD Hostmap:

```bash
sudo ./ad_hostmap.sh --target 192.168.110.70
```

Validate resolution:

```bash
getent hosts DC1
getent hosts DC1.corp.com
ping -c 3 DC1
```

Start enumeration:

```bash
nxc smb DC1
nxc ldap DC1
nmap -sV -sC -p- --open DC1
```

---

## Example Output

```text
=== AD Host Mapper v1.2.0 ===

[*] Mode: target route detection
[*] Target IP: 192.168.110.70
[*] Selected scan network: 192.168.110.0/24

[*] Discovering live hosts with nmap...
[*] Live hosts found: 4
    192.168.110.70
    192.168.110.72
    192.168.110.75
    192.168.110.254

[*] Checking for possible domain controller via Kerberos TCP/88...
[*] Possible DC found: 192.168.110.70

[*] Resolving SMB hostnames with NetExec...

[*] Generated host entries:
192.168.110.70     DC1.corp.com corp.com DC1
192.168.110.72     WEB04.corp.com WEB04
192.168.110.75     CLIENT75.corp.com CLIENT75

[*] Detected domain: corp.com

[*] Hostnames that will be refreshed:
    CLIENT75
    CLIENT75.corp.com
    DC1
    DC1.corp.com
    WEB04
    WEB04.corp.com
    corp.com

[*] Backing up /etc/hosts to: /etc/hosts.bak.2026-05-18_154500
[*] Updating /etc/hosts...
[+] /etc/hosts updated

[*] Validation:
    OK:   DC1.corp.com -> 192.168.110.70
    OK:   corp.com -> 192.168.110.70
    OK:   DC1 -> 192.168.110.70
    OK:   WEB04.corp.com -> 192.168.110.72
    OK:   WEB04 -> 192.168.110.72
    OK:   CLIENT75.corp.com -> 192.168.110.75
    OK:   CLIENT75 -> 192.168.110.75

[+] 3 hosts mapped successfully
[+] Done.
```

---

## What Gets Added to `/etc/hosts`

The script writes a managed block like this:

```text
# BEGIN AD_HOSTMAP
192.168.110.70     DC1.corp.com corp.com DC1
192.168.110.72     WEB04.corp.com WEB04
192.168.110.75     CLIENT75.corp.com CLIENT75
# END AD_HOSTMAP
```

Every run removes the old managed block and writes a fresh one.

---

## Stale Hostname Cleanup

The script also removes stale hostname lines outside the managed block.

For example, if `/etc/hosts` contains:

```text
192.168.141.70     DC1.corp.com corp.com DC1
```

and the new scan finds:

```text
192.168.110.70     DC1.corp.com corp.com DC1
```

the stale `192.168.141.70` line is removed.

This prevents Linux from resolving `DC1` to the wrong IP.

---

## Why Route-Based Detection Matters

The VPN interface IP is not always the lab subnet.

For example, `tun0` may have this address:

```text
10.10.14.5/23
```

But your AD lab network may be routed behind it:

```text
192.168.110.0/24 dev tun0
```

Older logic that scans based on the interface IP would scan the wrong network.

This tool uses the route table so it can find the actual routed lab subnet.

Check routes manually with:

```bash
ip route | grep tun0
```

Example:

```text
192.168.110.0/24 dev tun0 scope link
10.10.14.0/23 dev tun0 proto kernel scope link src 10.10.14.5
```

In this case, the tool should scan:

```text
192.168.110.0/24
```

not:

```text
10.10.14.0/23
```

---

## Troubleshooting

### IP Works but Hostname Fails

Example:

```bash
ping 192.168.110.70
ping DC1
```

If the IP works but the hostname fails, check resolution:

```bash
getent hosts DC1
grep -n "DC1" /etc/hosts
```

Then rerun:

```bash
sudo ./ad_hostmap.sh --target 192.168.110.70
```

---

### NetExec Generates No Hosts

If you see:

```text
[!] NetExec did not generate any host entries
```

Check SMB manually:

```bash
nxc smb 192.168.110.70
```

Scan for SMB:

```bash
nmap -p445 --open 192.168.110.0/24
```

Possible causes:

- Wrong subnet
- Lab machines are still booting
- SMB is blocked
- VPN route issue
- NetExec is not installed
- NetExec is not in your PATH

---

### Auto Mode Picks Nothing

If auto mode fails:

```bash
sudo ./ad_hostmap.sh --auto
```

Use target mode instead:

```bash
sudo ./ad_hostmap.sh --target 192.168.110.70
```

Target mode is usually the most reliable.

---

### Interface Mode Finds No Lab Route

Check routes:

```bash
ip route show dev tun0
```

If you do not see the lab subnet routed through `tun0`, use target mode:

```bash
sudo ./ad_hostmap.sh --target 192.168.110.70
```

---

### Restore `/etc/hosts`

Remove managed blocks:

```bash
sudo ./ad_hostmap.sh --restore
```

List backups:

```bash
ls -lah /etc/hosts.bak.*
```

Restore manually if needed:

```bash
sudo cp /etc/hosts.bak.YYYY-MM-DD_HHMMSS /etc/hosts
```

---

## Useful Validation Commands

```bash
getent hosts DC1
getent hosts DC1.corp.com
ping -c 3 DC1
grep -n "DC1\|WEB04\|CLIENT75\|AD_HOSTMAP\|AD_LAB_HOSTS" /etc/hosts
```

---

## Operator Workflow

Recommended AD lab startup flow:

```bash
ip route
ping -c 3 <known-DC-IP>
sudo ./ad_hostmap.sh --target <known-DC-IP>
getent hosts DC1
nxc smb DC1
nxc ldap DC1
```

Example:

```bash
ip route
ping -c 3 192.168.110.70
sudo ./ad_hostmap.sh --target 192.168.110.70
getent hosts DC1
nxc smb DC1
nxc ldap DC1
```

This sets you up cleanly before deeper enumeration.

---

## Related AD Enum Commands

After mapping hosts, useful next commands include:

```bash
nxc smb DC1
nxc smb DC1 --shares
nxc smb DC1 -u '' -p ''
nxc smb DC1 -u guest -p ''
nxc ldap DC1
nmap -sV -sC -p- --open DC1
enum4linux-ng DC1
```

With credentials:

```bash
nxc smb DC1 -u USER -p PASS
nxc ldap DC1 -u USER -p PASS
bloodhound-python -d corp.com -u USER -p PASS -ns DC1 -c All
```

---

## Safety and Scope

This tool is for:

- Personal AD labs
- OSCP-style lab environments
- Internal training environments
- Authorized assessments

Do not run this against networks you do not own or do not have permission to test.

---

## Suggested Toolkit Structure

```text
oscp_tools/
└── ad_hostmap/
    ├── ad_hostmap.sh
    └── README.md
```

Optional symlink:

```bash
sudo ln -sf "$PWD/ad_hostmap.sh" /usr/local/bin/ad_hostmap
```

Then run it from anywhere:

```bash
sudo ad_hostmap --target 192.168.110.70
```

---

## Version Notes

### v1.2.0 — Route-Aware Stable

- Added route-based interface detection
- Fixed `tun0` IP vs lab subnet issue
- Added target IP detection mode
- Added stale hostname cleanup outside managed block
- Added old `AD_LAB_HOSTS` cleanup
- Added `/etc/hosts` backups
- Added validation output
- Added restore mode
- Added full help menu

---

## Goal

The goal is simple:

```text
VPN up
Hostmap clean
AD enum starts smoothly
```

`ad_hostmap.sh` removes hostname-resolution friction so you can move directly into enumeration with confidence.
