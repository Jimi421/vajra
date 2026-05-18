# ADScoutPS

> **One file. No RSAT. No ActiveDirectory module. No dependencies.**  
> Drop it. Load it. Get answers.

---

## What it does

ADScoutPS is a PowerShell Active Directory enumeration and findings toolkit built for operators. Drop it on any domain-connected Windows box and load it — collection runs automatically, session data is stored, and every analysis function is ready to go.

```powershell
Import-Module .\ADScoutPS.ps1 -LabMode
Get-QuickWins
```

**It has two modes and they work together:**

**Auto mode** — load it and it collects. `Get-QuickWins` immediately surfaces the highest-value attack paths in priority order. Every result includes a ready-to-run verify command. No setup, no variables, no threading data between commands.

**Manual enumeration** — every collection and analysis function is exposed individually. Query users, groups, computers, ACLs, Kerberos targets, delegation, GPOs, trusts, and group membership exactly how you want. Pipe, filter, and combine like any other PowerShell tool.

**What makes it an operator tool:**

- **`Get-QuickWins`** — ranked attack paths. DA members and adminCount=1 accounts surface first in every category. Credentials in readable fields hit priority 1. Each result tells you what it is, why it matters, and the exact command to verify it.
- **`Get-PathHints`** — chained multi-hop attack paths across collected data. Connects ACEs, group membership, SPNs, delegation, and DCSync rights into full exploitation chains without re-querying LDAP.
- **`Find-LocalAdmin`** — live SMB scan. Checks every domain computer and tells you where your current user has local admin access right now.
- **`Find-Passwords`** — sweeps nine AD string fields on every user and computer account, not just description. `physicalDeliveryOfficeName`, `info`, `comment`, `homeDirectory`, `scriptPath`, and more. Catches credentials and flags that narrow field checks miss.
- **Normalized findings** — every finding includes severity, evidence, plain-language explanation, recommended action, and a copy-paste verify command. Not raw data — operator-ready output.
- **Offline snapshots** — export a full collection with `Export-Run`, reload it anywhere with `Import-Run`. Full findings and path hints with zero domain connectivity.
- **LabMode** — expands credential scanning to include CTF flag patterns for OSCP, HTB, and lab environments.
- **ACL analysis** — reads ACLs directly from AD using `System.DirectoryServices`. Every ACE resolved: GUIDs converted to human-readable right names, SIDs resolved for locale-safe filtering. Works on non-English AD deployments.

**Authorized use only. Use only in environments where you have explicit written permission.**

---

## Quick start

```powershell
# Standard lab run -- auto-collects on load
Import-Module .\ADScoutPS.ps1 -LabMode
Get-QuickWins

# Full run with ACL sweep
Import-Module .\ADScoutPS.ps1 -Preset Deep -LabMode
Get-QuickWins
Get-PathHints

# Load only, collect manually with options
Import-Module .\ADScoutPS.ps1 -LoadOnly
Collect -Preset Standard -LabMode -Server dc01.corp.local
Get-QuickWins
```

---

## The operator workflow

```powershell
# Load -- collection runs automatically
Import-Module .\ADScoutPS.ps1 -LabMode

# Shortest path to DA -- start here
Get-QuickWins

# Full findings with context and summary banner
Get-Findings | Get-Summary

# Chained multi-hop attack paths
Get-PathHints

# Browse results in interactive GUI
Show-Gui
Show-Gui -View PrivilegedGroups
Show-Gui -View Users

# Drill into specifics
Get-Members -Identity 'Domain Admins' -Recursive
Find-ASREP
Find-SPNs | Where-Object AdminCount -eq 1
Find-LocalAdmin
Get-ADACL -Identity 'Domain Admins'
Find-Passwords
Find-Interesting

# Export snapshot for offline analysis -- no domain needed
Export-Run -Path .\snapshot.json

# --- On another box, fully offline ---
Import-Module .\ADScoutPS.ps1 -LoadOnly
Import-Run -Path .\snapshot.json
Get-QuickWins
Get-PathHints
```

---

## `Get-QuickWins`

The primary operator function. No noise. Just what's worth trying, in priority order.

```powershell
Get-QuickWins
```

| Priority | Category | What it means |
|---|---|---|
| 1 | Credential Exposure | Password or flag in a readable AD field — instant win |
| 2 | AS-REP Roast | DA members and adminCount=1 accounts first |
| 3 | Kerberoast | DA members and adminCount=1 accounts first |
| 4 | Unconstrained Delegation | Coerce a DC to authenticate here, capture the TGT |
| 5 | DCSync | Non-standard principal with replication rights |
| 6 | ACL Attack Path | Abusable ACE on a privileged group, DA, krbtgt, or DC |
| 7 | Targeted Kerberoast | GenericWrite on a user — set a SPN and Kerberoast |
| 8 | Privilege Path | Nested group membership path to Domain Admins |
| 9 | GPO Abuse | Write access to a GPO linked to a privileged OU |

Each result prints `Target`, `Why`, `Evidence`, and a ready-to-run `ManualVerify` command.

---

## Aliases

Short aliases available after loading. Full function names always work too.

| Alias | Full name |
|---|---|
| `Collect` | `Invoke-ADScoutCollection` |
| `Get-QuickWins` | `Get-ADScoutQuickWins` |
| `Get-Findings` | `Get-ADScoutFinding` |
| `Get-PathHints` | `Get-ADScoutPathHint` |
| `Get-Summary` | `Get-ADScoutSummary` |
| `Get-Users` | `Get-ADScoutUser` |
| `Get-Groups` | `Get-ADScoutGroup` |
| `Get-Computers` | `Get-ADScoutComputer` |
| `Get-DCs` | `Get-ADScoutDomainController` |
| `Get-Trusts` | `Get-ADScoutDomainTrust` |
| `Get-Policy` | `Get-ADScoutPasswordPolicy` |
| `Get-GPOs` | `Get-ADScoutGPO` |
| `Get-OUs` | `Get-ADScoutOU` |
| `Get-Members` | `Get-ADScoutGroupMember` |
| `Get-ADACL` | `Get-ADScoutObjectAcl` |
| `Find-ASREP` | `Find-ADScoutASREPAccount` |
| `Find-SPNs` | `Find-ADScoutSPNAccount` |
| `Find-Shadow` | `Find-ADScoutShadowCredential` |
| `Find-Passwords` | `Find-ADScoutPasswordInDescription` |
| `Find-Delegation` | `Find-ADScoutDelegationHint` |
| `Find-DCSync` | `Find-ADScoutDCSyncRight` |
| `Find-AclPaths` | `Find-ADScoutAclAttackPath` |
| `Find-LocalAdmin` | `Find-ADScoutLocalAdminAccess` |
| `Find-Interesting` | `Find-ADScoutInterestingAce` |
| `Show-Gui` | `Show-ADScoutFindingsGui` |
| `Export-Run` | `Export-ADScoutRun` |
| `Import-Run` | `Import-ADScoutRun` |

---

## Presets

| Preset | What it collects | ACL sweep |
|---|---|---|
| `Quick` | Users, groups, computers, DCs, Kerberos, delegation, shadow creds, machine account quota, DCSync, password policy, LAPS, stale computers | No |
| `Standard` | Quick + GPOs, OUs, trusts, linked GPOs, privileged group report, cross-forest enumeration | No |
| `Deep` | Standard + ACL sweep: AdminSDHolder ACEs, GPO write permissions, targeted Kerberoast paths, ACL attack paths | Yes |

```powershell
# Add ACL sweep to Standard
Collect -Preset Standard -IncludeAclSweep

# Deep without ACL sweep
Collect -Preset Deep -SkipAclSweep
```

ACL sweep is slower on large domains. In OSCP/PEN-200 labs the cost is negligible.

---

## LabMode

```powershell
Import-Module .\ADScoutPS.ps1 -LabMode
```

Expands `Find-Passwords` to also match CTF-style flag patterns: `OS{`, `HTB{`, `FLAG{`. In normal mode only production credential keywords are used.

---

## Findings

Every finding includes:

| Field | Description |
|---|---|
| `Severity` | Critical / High / Medium / Low / Info |
| `Category` | Finding category |
| `Title` | Short finding name |
| `Target` | The specific account, group, or object |
| `Evidence` | Raw data that triggered the finding |
| `WhyItMatters` | Plain-language risk explanation |
| `RecommendedReview` | What to do about it |
| `ManualVerify` | Copy-paste command to confirm the finding |
| `DistinguishedName` | Full DN of the affected object |

```powershell
# All findings with summary banner
Get-Findings | Get-Summary

# Critical only
Get-Findings | Where-Object Severity -eq 'Critical'

# Copy-paste verify commands for every Critical finding
Get-Findings | Where-Object Severity -eq 'Critical' | Select-Object Title, Target, ManualVerify | Format-List

# Browse findings in GUI
Show-Gui
```

---

## Finding coverage

| Category | Finding | Severity | Needs ACL sweep |
|---|---|---|---|
| Credential Exposure | Password/flag in readable AD field | Critical | No |
| Authentication | AS-REP roast candidate | Critical | No |
| Delegation | Unconstrained delegation on non-DC | Critical | No |
| Replication Rights | Non-standard DCSync right | Critical | No |
| Persistence | Non-standard ACE on AdminSDHolder | Critical | Yes |
| ACL Attack Path | Abusable ACE on privileged object | Critical | Yes |
| GPO Abuse | GPO write linked to privileged OU | Critical | Yes |
| Domain Configuration | Machine account quota non-zero | High | No |
| Kerberos | SPN-bearing user (Kerberoast candidate) | High/Medium | No |
| Kerberos | Targeted Kerberoast path | High | Yes |
| Shadow Credentials | msDS-KeyCredentialLink present | High/Medium | No |
| Delegation | RBCD configured | High | No |
| Password Policy | Min length < 12 or lockout disabled | High | No |
| Account Flags | PASSWD_NOTREQD / USE_DES_KEY_ONLY | High/Medium | No |
| Trusts | Bidirectional trust without SID filtering | High | No |
| Delegation | KCD configured | Medium | No |
| Privilege Hygiene | adminCount=1 object | Medium | No |
| Endpoint Hygiene | No visible LAPS metadata | Medium | No |
| Endpoint Hygiene | Stale computer account (>90 days) | Low | No |

---

## Path chain engine

Walks relationships across collected data to find multi-hop paths to DA without re-querying LDAP.

```powershell
Get-PathHints
Get-PathHints -From 'helpdesk'
Get-PathHints -To 'Domain Admins'
Get-PathHints | Sort-Object ChainSeverity | Format-List
```

Chain types: `ACE->Kerberoast`, `ACE->DA`, `ACE->Tier0`, `SPN->Privesc`, `ASREP->Privesc`, `GPOWrite->Tier0`, `DCSync->CredDump`.

Each chain returns: `ChainSeverity`, `ChainType`, `Principal`, `Hops`, `TerminalImpact`, `NextCommand`.

---

## GUI

Interactive `Out-GridView` browser for any collected dataset. Supports live filtering, sorting, and column selection.

```powershell
Show-Gui                          # findings dashboard
Show-Gui -View PrivilegedGroups   # privileged group members
Show-Gui -View Delegation         # delegation review
Show-Gui -View Users              # all users
Show-Gui -View Computers          # all computers
Show-Gui -View All                # opens multiple windows
```

Falls back to `Format-Table` if `Out-GridView` is unavailable (Server Core, PS 7 without the GUI module).

---

## Full function reference

### Environment

```powershell
Get-ADScoutVersion                # version and runtime info
Test-ADScoutEnvironment           # preflight check -- domain connectivity, LDAP bind, MAQ
```

### Collection

```powershell
Collect -Preset Quick|Standard|Deep [-LabMode] [-SkipAclSweep] [-IncludeAclSweep]
Collect -Server dc01.corp.local
Collect -Credential $cred -Server dc01.corp.local -SearchBase 'DC=corp,DC=local'
```

### Users

```powershell
Get-Users                         # all users with decoded UacFlags, HasShadowCredential
Get-Users | Where-Object AdminCount -eq 1
Get-Users | Where-Object HasShadowCredential
ConvertTo-ADScoutUacFlag -UserAccountControl 66048   # decode UAC int to flag names
Find-ADScoutPrivilegedUser        # members of all privileged groups
Find-ADScoutWeakUacFlag           # PASSWD_NOTREQD, USE_DES_KEY_ONLY, etc.
```

### Groups

```powershell
Get-Groups
Get-Members -Identity 'Domain Admins' -Recursive    # recursive with nesting depth + path
Get-ADScoutGroupReport -PrivilegedOnly -Recursive   # all privileged groups expanded
Get-ADScoutGroupReport -GroupName 'DnsAdmins','Backup Operators' -Recursive
Get-ADScoutPrivilegePath          # users with any path to a privileged group
Find-ADScoutAdminGroup            # groups matching admin/operator/backup name patterns
Find-ADScoutAdminSDHolderOrphan   # all adminCount=1 objects
```

### Computers

```powershell
Get-Computers                     # includes Description, HasShadowCredential, UacFlags
Get-DCs                           # domain controllers only
Get-ADScoutLapsStatus             # LAPS coverage per computer
Find-ADScoutOldComputer -Days 90  # stale computer accounts
Find-LocalAdmin                   # live SMB scan -- where does current user have local admin
Find-LocalAdmin -Verbose          # shows per-host error codes
Find-LocalAdmin -ComputerName dc01,web04,files04
```

### Kerberos

```powershell
Find-ASREP                        # AS-REP roast candidates (preauth disabled)
Find-SPNs                         # Kerberoast candidates (SPN-bearing users)
Find-SPNs | Where-Object AdminCount -eq 1    # high-value cracks first
Find-Shadow                       # accounts with msDS-KeyCredentialLink set
```

### Delegation

```powershell
Find-Delegation                   # all delegation -- unconstrained + KCD + RBCD
Find-ADScoutUnconstrainedDelegation
Find-ADScoutConstrainedDelegation
```

### ACL

```powershell
Get-ADACL -Identity 'Domain Admins'          # ACL on any object, GUIDs resolved
Get-ADACL -Identity 'krbtgt'
Get-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=corp,DC=com'
Find-Interesting                             # interesting ACEs on domain root
Find-Interesting -Identity 'Domain Admins'   # interesting ACEs on specific object
Find-DCSync                                  # DCSync rights -- non-standard = Critical
Find-AclPaths                                # ACL sweep -- all privileged targets (Deep/IncludeAclSweep)
Find-ADScoutAdminSDHolderAce                 # non-standard ACEs on AdminSDHolder object
Find-ADScoutGPOWritePermission               # GPO write linked to privileged OUs
Find-ADScoutTargetedKerberoastPath           # GenericWrite on users = targeted Kerberoast
```

### Credential exposure

```powershell
Find-Passwords                    # production mode -- pass, pwd, cred, secret, etc.
Find-Passwords -LabMode           # adds OS{, HTB{, FLAG{ patterns
```

Checks on users: `description`, `info`, `comment`, `physicalDeliveryOfficeName`, `homeDirectory`, `scriptPath`, `profilePath`, `homePhone`, `streetAddress`.  
Checks on computers: `description`, `info`, `comment`, `physicalDeliveryOfficeName`, `location`.

### Domain

```powershell
Get-ADScoutDomainInfo
Get-Trusts                        # decoded TrustDirection, TrustType, SIDFiltering, IsForestTrust
Get-Policy                        # default domain + fine-grained PSOs
Get-ADScoutMachineAccountQuota    # ms-DS-MachineAccountQuota (RBCD/shadow cred prereq)
Get-ADScoutCrossForestEnum        # enumerate reachable trusted domains
```

### GPO / OU

```powershell
Get-GPOs
Get-OUs
Get-ADScoutLinkedGPO              # OUs with linked GPOs only
```

### Analysis

```powershell
Get-QuickWins                     # shortest path to DA, prioritized
Get-Findings | Get-Summary        # full findings with color-coded banner
Get-PathHints                     # chained multi-hop attack paths
Get-PathHints -From 'helpdesk'
Get-PathHints -To 'Domain Admins'
```

### GUI

```powershell
Show-Gui                          # findings dashboard
Show-Gui -View PrivilegedGroups
Show-Gui -View Delegation
Show-Gui -View Users
Show-Gui -View Computers
Show-Gui -View All
```

### Export / Import / Report

```powershell
Export-Run -Path .\snapshot.json              # full snapshot for offline analysis
Import-Run -Path .\snapshot.json              # reload -- indexes rebuilt automatically
New-ADScoutHtmlReport -RunData $data -OutputPath .\report.html   # standalone HTML report
.\ADScoutPS.ps1 -Preset Standard -Report     # direct execution with auto-report
```

---

## Alternate targets

```powershell
Collect -Server dc01.corp.local
$cred = Get-Credential
Collect -Server dc01.corp.local -Credential $cred
Collect -SearchBase 'OU=Workstations,DC=corp,DC=local'
Collect -Server dc01.corp.local -Credential $cred -SearchBase 'DC=corp,DC=local'
```

---

## Snapshots

Full offline analysis from a JSON snapshot. No domain connection needed after export.

```powershell
# Export
Export-Run -Path .\snapshot.json

# Import and analyze offline
Import-Module .\ADScoutPS.ps1 -LoadOnly
Import-Run -Path .\snapshot.json
Get-QuickWins
Get-PathHints
Get-Findings | Get-Summary
Show-Gui
```

---

## Direct execution with file output

Writes timestamped CSV/JSON per collection key plus `summary.md`, `snapshot.json`, and optionally `report.html`.

```powershell
.\ADScoutPS.ps1 -Preset Standard -LabMode
.\ADScoutPS.ps1 -Preset Deep -LabMode -Report
.\ADScoutPS.ps1 -Preset Standard -OutputPath C:\Assessments\Corp -LabMode
.\ADScoutPS.ps1 -OutputFormat CSV
.\ADScoutPS.ps1 -OutputFormat JSON
powershell -ExecutionPolicy Bypass -File .\ADScoutPS.ps1 -Preset Standard -LabMode
```

---

## How it works

ADScoutPS uses `System.DirectoryServices` directly — no ActiveDirectory module, no RSAT, no binaries beyond the script. Every LDAP query runs on port 389. Local admin scanning uses a P/Invoke call to `advapi32.dll!OpenSCManager` on port 445 (SMB).

`Collect` runs once and builds a `RunData` object with all collected data plus fast lookup indexes (`GroupMembershipIndex`, `UserGroupIndex`, `TierZeroObjects`, `ObjectByDN`, `ObjectBySam`). All analysis functions consume this object without re-querying LDAP. After `Import-Run`, analysis works identically offline.

ACE `ObjectType` GUIDs are resolved via a 60+ entry static map to human-readable right names (`User-Force-Change-Password`, `DS-Replication-Get-Changes-All`, etc.). Each ACE includes a resolved `IdentitySid` for locale-safe privileged principal filtering — works correctly on non-English AD deployments where group names are localized.

---

## Caveats

- **`lastLogonTimestamp` jitter** — stale computer results carry ~14 day fuzziness by AD design
- **LAPS** — checks attribute presence, not whether the password value is readable to you
- **ACL sweep** — slow on large production domains; negligible in lab environments
- **Shadow credentials** — WHFB-enrolled devices have legitimate entries; review before concluding abuse
- **DCSync expected holders** — Domain Admins, DCs, Enterprise Admins returned as `Info`; everything else `Critical`
- **`Find-LocalAdmin`** — touches live hosts over SMB (port 445); generates authentication events

---

## Version history

See [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*For authorized use only. Always obtain explicit written permission before running enumeration tooling against any environment.*
