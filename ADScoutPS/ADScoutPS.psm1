# ADScoutPS v0.3 - Read-only AD enumeration module for authorized labs/environments
Set-StrictMode -Version Latest

function New-ADScoutDirectoryEntry {
    [CmdletBinding()]
    param(
        [string]$Path,
        [System.Management.Automation.PSCredential]$Credential
    )
    if ($Credential) {
        $user = $Credential.UserName
        $pass = $Credential.GetNetworkCredential().Password
        return New-Object System.DirectoryServices.DirectoryEntry($Path, $user, $pass)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function New-ADScoutSearcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SearchBase,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [System.Management.Automation.PSCredential]$Credential,
        [ValidateSet('Base','OneLevel','Subtree')][string]$SearchScope = 'Subtree'
    )
    $entry = New-ADScoutDirectoryEntry -Path $SearchBase -Credential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$SearchScope
    foreach ($prop in $Properties) { [void]$searcher.PropertiesToLoad.Add($prop) }
    return $searcher
}

function Get-ADScoutProp {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        if ($Result.Properties[$Name].Count -eq 1) { return $Result.Properties[$Name][0] }
        return @($Result.Properties[$Name])
    }
    return $null
}

function Get-ADScoutRootDSE {
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    $path = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
    return New-ADScoutDirectoryEntry -Path $path -Credential $Credential
}

function Get-ADScoutDomainDN {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $root = Get-ADScoutRootDSE -Server $Server -Credential $Credential
    return [string]$root.Properties['defaultNamingContext'][0]
}

function ConvertTo-ADScoutLdapPath {
    param([Parameter(Mandatory)][string]$DistinguishedName, [string]$Server)
    if ($DistinguishedName -like 'LDAP://*') { return $DistinguishedName }
    if ($Server) { return "LDAP://$Server/$DistinguishedName" }
    return "LDAP://$DistinguishedName"
}

function Get-ADScoutDomainInfo {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $root = Get-ADScoutRootDSE -Server $Server -Credential $Credential
    [PSCustomObject]@{
        DefaultNamingContext       = [string]$root.Properties['defaultNamingContext'][0]
        ConfigurationNamingContext = [string]$root.Properties['configurationNamingContext'][0]
        SchemaNamingContext        = [string]$root.Properties['schemaNamingContext'][0]
        DnsHostName                = [string]$root.Properties['dnsHostName'][0]
        DomainFunctionality        = [string]$root.Properties['domainFunctionality'][0]
        ForestFunctionality        = [string]$root.Properties['forestFunctionality'][0]
        Server                     = $(if ($Server) { $Server } else { 'Auto' })
    }
}

function Get-ADScoutUser {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential, [int]$Limit = 0)
    $dn = Get-ADScoutDomainDN -Server $Server -Credential $Credential
    $base = ConvertTo-ADScoutLdapPath -DistinguishedName $dn -Server $Server
    $props = 'samaccountname','displayname','distinguishedname','useraccountcontrol','serviceprincipalname','pwdlastset','lastlogontimestamp','memberof'
    $s = New-ADScoutSearcher -SearchBase $base -Filter '(&(objectCategory=person)(objectClass=user))' -Properties $props -Credential $Credential
    $count = 0
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            SamAccountName    = Get-ADScoutProp $r 'samaccountname'
            DisplayName       = Get-ADScoutProp $r 'displayname'
            DistinguishedName = Get-ADScoutProp $r 'distinguishedname'
            UserAccountControl= Get-ADScoutProp $r 'useraccountcontrol'
            SPN               = (Get-ADScoutProp $r 'serviceprincipalname') -join ';'
            MemberOf          = (Get-ADScoutProp $r 'memberof') -join ';'
        }
        $count++; if ($Limit -gt 0 -and $count -ge $Limit) { break }
    }
}

function Get-ADScoutGroup {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential, [int]$Limit = 0)
    $dn = Get-ADScoutDomainDN -Server $Server -Credential $Credential
    $base = ConvertTo-ADScoutLdapPath -DistinguishedName $dn -Server $Server
    $props = 'samaccountname','name','distinguishedname','member','memberof','description'
    $s = New-ADScoutSearcher -SearchBase $base -Filter '(objectClass=group)' -Properties $props -Credential $Credential
    $count = 0
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProp $r 'name'
            SamAccountName    = Get-ADScoutProp $r 'samaccountname'
            DistinguishedName = Get-ADScoutProp $r 'distinguishedname'
            Description       = Get-ADScoutProp $r 'description'
            Members           = (Get-ADScoutProp $r 'member') -join ';'
            MemberOf          = (Get-ADScoutProp $r 'memberof') -join ';'
        }
        $count++; if ($Limit -gt 0 -and $count -ge $Limit) { break }
    }
}

function Get-ADScoutComputer {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential, [int]$Limit = 0)
    $dn = Get-ADScoutDomainDN -Server $Server -Credential $Credential
    $base = ConvertTo-ADScoutLdapPath -DistinguishedName $dn -Server $Server
    $props = 'name','dnshostname','distinguishedname','operatingsystem','operatingsystemversion','lastlogontimestamp','useraccountcontrol','serviceprincipalname'
    $s = New-ADScoutSearcher -SearchBase $base -Filter '(objectCategory=computer)' -Properties $props -Credential $Credential
    $count = 0
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProp $r 'name'
            DnsHostName       = Get-ADScoutProp $r 'dnshostname'
            OperatingSystem   = Get-ADScoutProp $r 'operatingsystem'
            OSVersion         = Get-ADScoutProp $r 'operatingsystemversion'
            DistinguishedName = Get-ADScoutProp $r 'distinguishedname'
            UserAccountControl= Get-ADScoutProp $r 'useraccountcontrol'
            SPN               = (Get-ADScoutProp $r 'serviceprincipalname') -join ';'
        }
        $count++; if ($Limit -gt 0 -and $count -ge $Limit) { break }
    }
}

function Find-ADScoutSPNAccount {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    Get-ADScoutUser -Server $Server -Credential $Credential | Where-Object { $_.SPN }
}

function Find-ADScoutAdminGroup {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    Get-ADScoutGroup -Server $Server -Credential $Credential | Where-Object {
        $_.Name -match 'admin|operator|backup|server|account|enterprise|schema|domain admins|remote|helpdesk'
    }
}

function Get-ADScoutOU {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $dn = Get-ADScoutDomainDN -Server $Server -Credential $Credential
    $base = ConvertTo-ADScoutLdapPath -DistinguishedName $dn -Server $Server
    $s = New-ADScoutSearcher -SearchBase $base -Filter '(objectClass=organizationalUnit)' -Properties @('name','distinguishedname','gplink') -Credential $Credential
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProp $r 'name'
            DistinguishedName = Get-ADScoutProp $r 'distinguishedname'
            GPLink            = (Get-ADScoutProp $r 'gplink') -join ';'
        }
    }
}

function Get-ADScoutGPO {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $dn = Get-ADScoutDomainDN -Server $Server -Credential $Credential
    $base = ConvertTo-ADScoutLdapPath -DistinguishedName "CN=Policies,CN=System,$dn" -Server $Server
    $s = New-ADScoutSearcher -SearchBase $base -Filter '(objectClass=groupPolicyContainer)' -Properties @('displayname','name','distinguishedname','gpcfilesyspath','whenchanged') -Credential $Credential
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            DisplayName       = Get-ADScoutProp $r 'displayname'
            Guid              = Get-ADScoutProp $r 'name'
            DistinguishedName = Get-ADScoutProp $r 'distinguishedname'
            FileSysPath       = Get-ADScoutProp $r 'gpcfilesyspath'
            WhenChanged       = Get-ADScoutProp $r 'whenchanged'
        }
    }
}

function Get-ADScoutLinkedGPO {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    Get-ADScoutOU -Server $Server -Credential $Credential | Where-Object { $_.GPLink } | ForEach-Object {
        [PSCustomObject]@{ OU = $_.DistinguishedName; GPLink = $_.GPLink }
    }
}

function Get-ADScoutObjectAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    $path = ConvertTo-ADScoutLdapPath -DistinguishedName $DistinguishedName -Server $Server
    $entry = New-ADScoutDirectoryEntry -Path $path -Credential $Credential
    foreach ($ace in $entry.ObjectSecurity.Access) {
        [PSCustomObject]@{
            TargetDN              = $DistinguishedName
            IdentityReference     = [string]$ace.IdentityReference
            ActiveDirectoryRights = [string]$ace.ActiveDirectoryRights
            AccessControlType     = [string]$ace.AccessControlType
            ObjectType            = [string]$ace.ObjectType
            InheritedObjectType   = [string]$ace.InheritedObjectType
            IsInherited           = [bool]$ace.IsInherited
            InheritanceType       = [string]$ace.InheritanceType
        }
    }
}

function Find-ADScoutInterestingAce {
    [CmdletBinding()]
    param(
        [string]$DistinguishedName,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$IncludeOUs
    )
    $targets = @()
    if ($DistinguishedName) { $targets += $DistinguishedName }
    if ($IncludeOUs) { $targets += (Get-ADScoutOU -Server $Server -Credential $Credential).DistinguishedName }
    if (-not $targets) { $targets += (Get-ADScoutDomainDN -Server $Server -Credential $Credential) }
    foreach ($target in $targets) {
        Get-ADScoutObjectAcl -DistinguishedName $target -Server $Server -Credential $Credential | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight|CreateChild|DeleteChild|WriteProperty'
        }
    }
}

function Get-ADScoutGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$Recursive
    )
    $dn = Get-ADScoutDomainDN -Server $Server -Credential $Credential
    $base = ConvertTo-ADScoutLdapPath -DistinguishedName $dn -Server $Server
    $escaped = $Identity.Replace('\\','\\5c').Replace('(','\\28').Replace(')','\\29')
    $filter = "(|(samAccountName=$escaped)(name=$escaped)(distinguishedName=$escaped))"
    $s = New-ADScoutSearcher -SearchBase $base -Filter $filter -Properties @('member','distinguishedname','name') -Credential $Credential
    $group = $s.FindOne()
    if (-not $group) { throw "Group not found: $Identity" }
    $seen = @{}
    function Expand-Member([string]$memberDn) {
        if ($seen.ContainsKey($memberDn)) { return }
        $seen[$memberDn] = $true
        [PSCustomObject]@{ MemberDN = $memberDn }
        if ($Recursive) {
            try {
                $path = ConvertTo-ADScoutLdapPath -DistinguishedName $memberDn -Server $Server
                $e = New-ADScoutDirectoryEntry -Path $path -Credential $Credential
                if ($e.Properties['objectClass'] -contains 'group') {
                    foreach ($m in $e.Properties['member']) { Expand-Member ([string]$m) }
                }
            } catch {}
        }
    }
    foreach ($m in $group.Properties['member']) { Expand-Member ([string]$m) }
}

function Find-ADScoutOldComputer {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential, [int]$Days = 90)
    # Lightweight heuristic: returns systems where lastLogonTimestamp field is absent in this simple version.
    Get-ADScoutComputer -Server $Server -Credential $Credential | Where-Object { -not $_.DnsHostName -or $_.OperatingSystem -match 'Windows 7|Windows Server 2008|Windows Server 2012' }
}

function Find-ADScoutDelegationComputer {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    Get-ADScoutComputer -Server $Server -Credential $Credential | Where-Object {
        ($_.UserAccountControl -band 0x80000) -or ($_.UserAccountControl -band 0x1000000)
    }
}

function Find-ADScoutPrivilegedUser {
    [CmdletBinding()]
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $adminGroups = Find-ADScoutAdminGroup -Server $Server -Credential $Credential
    foreach ($g in $adminGroups) {
        try {
            Get-ADScoutGroupMember -Identity $g.DistinguishedName -Server $Server -Credential $Credential -Recursive | ForEach-Object {
                [PSCustomObject]@{ Group = $g.Name; MemberDN = $_.MemberDN }
            }
        } catch {}
    }
}

function Export-ADScoutData {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$Path, [ValidateSet('Csv','Json')][string]$Format = 'Csv')
    if ($Format -eq 'Csv') { $Data | Export-Csv -NoTypeInformation -Path $Path }
    else { $Data | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $Path }
}

function Invoke-ADScout {
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$OutputPath = $(Join-Path (Get-Location) ("ADScout-Results-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
        [ValidateSet('Csv','Json')][string]$Format = 'Csv',
        [switch]$SkipAclSweep
    )
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    Write-Host "[+] ADScout output: $OutputPath"

    $domain = @(Get-ADScoutDomainInfo -Server $Server -Credential $Credential)
    $users = @(Get-ADScoutUser -Server $Server -Credential $Credential)
    $groups = @(Get-ADScoutGroup -Server $Server -Credential $Credential)
    $computers = @(Get-ADScoutComputer -Server $Server -Credential $Credential)
    $spns = @(Find-ADScoutSPNAccount -Server $Server -Credential $Credential)
    $adminGroups = @(Find-ADScoutAdminGroup -Server $Server -Credential $Credential)
    $gpos = @(Get-ADScoutGPO -Server $Server -Credential $Credential)
    $ous = @(Get-ADScoutOU -Server $Server -Credential $Credential)
    $linkedGpos = @(Get-ADScoutLinkedGPO -Server $Server -Credential $Credential)
    $privUsers = @(Find-ADScoutPrivilegedUser -Server $Server -Credential $Credential)
    $delegation = @(Find-ADScoutDelegationComputer -Server $Server -Credential $Credential)
    $oldComputers = @(Find-ADScoutOldComputer -Server $Server -Credential $Credential)
    $aces = @()
    if (-not $SkipAclSweep) { $aces = @(Find-ADScoutInterestingAce -Server $Server -Credential $Credential -IncludeOUs) }

    $sets = @{
        'domain' = $domain; 'users' = $users; 'groups' = $groups; 'computers' = $computers; 'spn_accounts' = $spns;
        'admin_groups' = $adminGroups; 'gpos' = $gpos; 'ous' = $ous; 'linked_gpos' = $linkedGpos;
        'privileged_memberships' = $privUsers; 'delegation_computers' = $delegation; 'old_or_legacy_computers' = $oldComputers; 'interesting_aces' = $aces
    }
    foreach ($k in $sets.Keys) {
        $ext = if ($Format -eq 'Csv') { 'csv' } else { 'json' }
        Export-ADScoutData -Data $sets[$k] -Path (Join-Path $OutputPath "$k.$ext") -Format $Format
    }
    $summary = @"
# ADScout Summary

Generated: $(Get-Date)
Server: $(if ($Server) { $Server } else { 'Auto' })

| Area | Count |
|---|---:|
| Users | $($users.Count) |
| Groups | $($groups.Count) |
| Computers | $($computers.Count) |
| SPN Accounts | $($spns.Count) |
| Admin-like Groups | $($adminGroups.Count) |
| GPOs | $($gpos.Count) |
| OUs | $($ous.Count) |
| Linked GPO Entries | $($linkedGpos.Count) |
| Privileged Membership Entries | $($privUsers.Count) |
| Delegation Computers | $($delegation.Count) |
| Legacy/Old Computer Hints | $($oldComputers.Count) |
| Interesting ACEs | $($aces.Count) |

## Suggested Next Review

1. Review admin_groups and privileged_memberships first.
2. Review spn_accounts for service-account exposure awareness.
3. Review interesting_aces for delegated rights such as GenericAll, GenericWrite, WriteDacl, WriteOwner, and WriteProperty.
4. Review gpos and linked_gpos for policy placement and scope.
"@
    $summary | Out-File -Encoding UTF8 -FilePath (Join-Path $OutputPath 'summary.md')
    Write-Host "[+] Complete. Open summary.md first."
    return [PSCustomObject]@{ OutputPath = $OutputPath; Users=$users.Count; Groups=$groups.Count; Computers=$computers.Count; InterestingACEs=$aces.Count; SPNs=$spns.Count }
}

Export-ModuleMember -Function Get-ADScoutDomainInfo,Get-ADScoutUser,Get-ADScoutGroup,Get-ADScoutComputer,Find-ADScoutSPNAccount,Find-ADScoutAdminGroup,Get-ADScoutOU,Get-ADScoutGPO,Get-ADScoutLinkedGPO,Get-ADScoutObjectAcl,Find-ADScoutInterestingAce,Get-ADScoutGroupMember,Find-ADScoutOldComputer,Find-ADScoutDelegationComputer,Find-ADScoutPrivilegedUser,Invoke-ADScout
