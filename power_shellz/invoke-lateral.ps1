<#
.SYNOPSIS
    Invoke-Lateral — interactive WinRM/PSRemoting helper.

    Run it with no arguments and it prompts for hostname, username, and password
    (password masked), builds the PSCredential, opens the session, and either
    drops you into an interactive remote prompt or runs a command.

    Wraps the standard "Get-Credential won't prompt in a non-interactive shell"
    workaround so you're not retyping the four-line incantation on every hop.

.NOTES
    Any prompt can be pre-filled by passing the matching parameter, e.g.:
      .\Invoke-Lateral.ps1 -ComputerName files04.corp.com
    will only prompt for username + password.
#>

param(
    [string]$ComputerName,
    [string]$Username,
    [string]$Password,        # optional; if omitted you'll be prompted (masked)
    [string]$Command,
    [switch]$OneShot,         # run a command and exit instead of interactive session
    [switch]$Keep             # keep session open as $LatSession after one-shot
)

Write-Host ""
Write-Host "  -- Invoke-Lateral --" -ForegroundColor Cyan
Write-Host ""

# --- prompt for anything not passed as a parameter ---
if (-not $ComputerName) {
    $ComputerName = Read-Host "? target hostname or IP"
}
if (-not $Username) {
    $Username = Read-Host "? username (e.g. jen or corp.com\jen)"
}

# Password: if passed as plaintext param, convert; otherwise prompt masked.
if ($Password) {
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
} else {
    $secure = Read-Host "? password" -AsSecureString
}

if (-not $ComputerName -or -not $Username -or -not $secure) {
    Write-Host "[!] hostname, username and password are all required." -ForegroundColor Red
    exit 1
}

# --- build credential object ---
# Read-Host -AsSecureString already gives a SecureString, so no plaintext
# round-trip needed -- this is cleaner (and safer) than the by-hand version.
$cred = New-Object System.Management.Automation.PSCredential($Username, $secure)

Write-Host ""
Write-Host "[*] Credential built for $Username" -ForegroundColor Cyan
Write-Host "[*] Connecting to $ComputerName ..." -ForegroundColor Cyan

# --- open the session ---
try {
    $session = New-PSSession -ComputerName $ComputerName -Credential $cred -ErrorAction Stop
} catch {
    Write-Host "[!] Session failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Common causes:" -ForegroundColor DarkGray
    Write-Host "    - WinRM not listening on target (5985/5986)" -ForegroundColor DarkGray
    Write-Host "    - creds invalid, or user not in Remote Management Users" -ForegroundColor DarkGray
    Write-Host "    - non-domain target not in TrustedHosts" -ForegroundColor DarkGray
    Write-Host "      (fix: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$ComputerName')" -ForegroundColor DarkGray
    exit 1
}

Write-Host "[+] Session established to $ComputerName." -ForegroundColor Green
Write-Host ""

# --- one-shot command mode (only if -OneShot) ---
if ($OneShot) {
    if (-not $Command) {
        $Command = @'
Write-Host "=== whoami ===" ; whoami
Write-Host "=== groups/privs ===" ; whoami /all
Write-Host "=== host ===" ; hostname
Write-Host "=== networks (pivot surface) ===" ; ipconfig /all | Select-String "IPv4|Subnet|Gateway|Description"
Write-Host "=== local admins ===" ; Get-LocalGroupMember Administrators -EA SilentlyContinue
'@
    }
    $sb = [ScriptBlock]::Create($Command)
    Write-Host "[*] Running command on $ComputerName ...`n" -ForegroundColor Cyan
    Invoke-Command -Session $session -ScriptBlock $sb

    if ($Keep) {
        $global:LatSession = $session
        Write-Host "`n[*] Session kept open as `$LatSession" -ForegroundColor Yellow
    } else {
        Remove-PSSession $session
        Write-Host "`n[*] Session closed." -ForegroundColor DarkGray
    }
    return
}

# --- default: interactive session ---
Write-Host "[*] Entering interactive session -- type 'exit' to leave." -ForegroundColor Cyan
Write-Host ""
Enter-PSSession -Session $session

# Control returns here after you 'exit' the remote prompt.
Remove-PSSession $session
Write-Host ""
Write-Host "[*] Session closed." -ForegroundColor DarkGray

<#
DOUBLE-HOP REMINDER
A session opened here will NOT delegate creds to a THIRD host by default
(Kerberos won't forward the ticket). If from this box you try to reach
another using the same creds and get access-denied, that's why -- not bad
creds. Workarounds: re-run this script from the current box targeting the
next one (fresh creds per hop), use CredSSP, or pass creds explicitly in an
inner Invoke-Command rather than relying on the session token to delegate.
#>
