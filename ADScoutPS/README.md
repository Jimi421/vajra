# ADScoutPS v0.3 Easy Mode

ADScoutPS is a read-only PowerShell Active Directory enumeration module for authorized labs, internal assessments, and OSCP-style practice environments.

It uses native .NET/PowerShell LDAP access. It does **not** modify AD objects.

## What changed in v0.3

- Added `-Server` and `-Credential` support across major functions
- Added one-command collection with `Invoke-ADScout`
- Added output folder generation with CSV/JSON exports
- Added `summary.md` report
- Added recursive group membership expansion
- Added privileged membership review
- Added delegation computer hints
- Added legacy/old computer hints
- Added GPO, OU, linked GPO, ACL, and interesting ACE collection

## Install / Load

From the folder that contains `ADScoutPS`:

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

Temporary script policy for the current PowerShell process if needed:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Fastest usage

```powershell
Invoke-ADScout
```

This creates a results folder like:

```text
ADScout-Results-20260430-151500
```

Open `summary.md` first.

## Target a specific domain controller

```powershell
Invoke-ADScout -Server dc01.corp.local
```

## Use alternate authorized credentials

```powershell
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred
```

## JSON output instead of CSV

```powershell
Invoke-ADScout -Format Json
```

## Skip ACL sweep if you want a faster first run

```powershell
Invoke-ADScout -SkipAclSweep
```

## Individual commands

```powershell
Get-ADScoutDomainInfo
Get-ADScoutUser | Select-Object -First 10
Get-ADScoutGroup
Get-ADScoutComputer
Find-ADScoutSPNAccount
Find-ADScoutAdminGroup
Get-ADScoutGPO
Get-ADScoutOU
Get-ADScoutLinkedGPO
```

## ACL / ACE review

```powershell
Find-ADScoutInterestingAce
```

Review a specific object:

```powershell
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
Find-ADScoutInterestingAce -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

## Recursive group members

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive
```

## Suggested workflow

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
Invoke-ADScout -SkipAclSweep
Invoke-ADScout
```

Run `-SkipAclSweep` first for speed, then run full collection once basic connectivity looks good.

## Safety / scope

Use only in environments you own or are authorized to assess. This module is intended for read-only enumeration and learning.
