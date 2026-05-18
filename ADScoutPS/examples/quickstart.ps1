Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
Test-ADScoutEnvironment
Invoke-ADScout -Preset Quick
Get-ADScoutFinding -SkipAclSweep | Format-Table Severity,Category,Title,Target -AutoSize
