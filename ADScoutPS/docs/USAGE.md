# ADScoutPS Usage Guide

## Recommended first run

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. .\ADScout.ps1 -LoadOnly
Test-ADScoutEnvironment
Invoke-ADScout -Preset Quick
Get-ADScoutFinding -SkipAclSweep | Format-Table Severity,Category,Title,Target -AutoSize
```

## GUI views

```powershell
Invoke-ADScout -Gui -View Findings -SkipAclSweep
Invoke-ADScout -Gui -View PrivilegedGroups
Invoke-ADScout -Gui -View Users
```

## Report

```powershell
Invoke-ADScout -Preset Standard -Report -SkipAclSweep
```
