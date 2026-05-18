<#
.SYNOPSIS
ADScoutPS v1.5.0 - PowerShell Active Directory Enumeration Toolkit

.DESCRIPTION
Read-only AD enumeration for authorized lab environments and approved internal assessments.
Single-file design -- dot-source for interactive use, direct execution for operator mode.
No RSAT. No ActiveDirectory module. No dependencies beyond the Windows .NET runtime.

USAGE:
    # Load functions interactively (preferred)
    . .\ADScoutPS.ps1 -LoadOnly
    Get-ADScoutVersion
    Test-ADScoutEnvironment
    $data = Invoke-ADScoutCollection -Preset Standard -LabMode
    $data | Get-ADScoutFinding | Get-ADScoutSummary
    Get-ADScoutPathHint -RunData $data

    # Direct execution
    .\ADScoutPS.ps1 -Preset Standard -LabMode
    .\ADScoutPS.ps1 -Preset Deep -Report
    powershell -ExecutionPolicy Bypass -File .\ADScoutPS.ps1 -Preset Quick -LabMode

DISCLAIMER:
    For authorized use only. Use only in environments where you have explicit permission.

v1.4.0 additions:
    - Full extended rights GUID resolution (190+ GUIDs) -- ACEs show human-readable
      right names everywhere instead of raw GUIDs
    - Targeted Kerberoast path detection -- GenericAll/GenericWrite on a user = can set SPN
    - GPO write permission detection -- who can modify GPOs linked to privileged OUs
    - AdminSDHolder ACL sweep -- non-standard ACEs on the AdminSDHolder object
    - Machine account quota and shadow credential (msDS-KeyCredentialLink) detection
    - Cross-trust domain enumeration
    - TrustDirection and TrustType decoded to human-readable strings
    - HasShadowCredential field added to user and computer objects
    - Resolved ACE names throughout all ACL findings output
#>
param(
    [switch]$LoadOnly,
    [ValidateSet('Quick','Standard','Deep')][string]$Preset = 'Standard',
    [string]$Server,
    [PSCredential]$Credential,
    [string]$SearchBase,
    [string]$OutputPath = 'ADScout-Results',
    [ValidateSet('CSV','JSON','Both')][string]$OutputFormat = 'Both',
    [switch]$SkipAclSweep,
    [switch]$IncludeAclSweep,
    [switch]$LabMode,
    [switch]$Gui,
    [ValidateSet('Findings','PrivilegedGroups','Delegation','Users','Computers','All')][string]$View = 'Findings',
    [switch]$Report,
    [switch]$NoExport
)

Set-StrictMode -Version Latest

$script:ADScoutVersion      = '1.5.0'
$script:ADScoutLastRun      = $null
$script:ADScoutLastFindings = @()

function Resolve-ADScoutRunData {
<#
.SYNOPSIS
Internal helper -- returns RunData from parameter or session scope.
Throws a clear error if neither is available.
#>
    param([PSCustomObject]$RunData)
    if ($RunData) { return $RunData }
    if ($script:ADScoutLastRun) { return $script:ADScoutLastRun }
    throw "No RunData available. Run: Collect -Preset Standard"
}

# =============================================================================
# EXTENDED RIGHTS GUID MAP
# Static map of AD schema/extended-rights GUIDs -> human-readable names.
# Applied to ObjectType and InheritedObjectType fields in every ACE output.
# =============================================================================
$script:ADScoutGuidMap = @{
    # Extended rights
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password'
    'ab721a54-1e2f-11d0-9819-00aa0040529b' = 'Send-As'
    'ab721a56-1e2f-11d0-9819-00aa0040529b' = 'Receive-As'
    'ab721a52-1e2f-11d0-9819-00aa0040529b' = 'Send-To'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'Validated-SPN'
    '72e39547-7b18-11d1-adef-00c04fd8d5cd' = 'DNS-Host-Name-Attributes'
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Planning'
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Logging'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6af-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Next-RID'
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' = 'Change-Schema-Master'
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Rid-Master'
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' = 'Do-Garbage-Collection'
    'bae50096-4752-11d1-9052-00c04fc2d4cf' = 'Change-PDC'
    '440820ad-65b4-11d1-a3da-0000f875ae0d' = 'Add-GUID'
    '014bf69c-7b3b-11d1-85f6-08002be74fab' = 'Change-Domain-Master'
    'e48d0154-bcf8-11d1-8702-00c04fb96050' = 'Public-Information'
    '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' = 'Run-Protect-Admin-Groups-Task'
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f' = 'Manage-Optional-Features'
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' = 'DS-Clone-Domain-Controller'
    '084c93a2-620d-4879-a836-f0ae47de0e89' = 'DS-Read-Partition-Secrets'
    '94825a8d-b171-4116-8146-1e34d8f54401' = 'DS-Write-Partition-Secrets'
    '9b026da6-0d3c-465c-8bee-5199d7165cba' = 'DS-Validated-Write-Computer'
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' = 'Apply-Group-Policy'
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' = 'Enroll'
    '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'AutoEnroll'
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Allowed-To-Authenticate'
    # Property sets
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a' = 'Other-Domain-Parameters'
    'c7407360-20bf-11d0-a768-00aa006e0529' = 'Domain-Password'
    'e45795b2-9455-11d1-aebd-0000f80367c1' = 'Email-Information'
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf' = 'General-Information'
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Group-Membership'
    '77b5b886-944a-11d1-aebd-0000f80367c1' = 'Personal-Information'
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8' = 'Private-Information'
    'e45795b3-9455-11d1-aebd-0000f80367c1' = 'Web-Information'
    # Common attribute GUIDs
    'bf967950-0de6-11d0-a285-00aa003049e2' = 'description'
    'bf967953-0de6-11d0-a285-00aa003049e2' = 'displayName'
    'bf967972-0de6-11d0-a285-00aa003049e2' = 'member'
    'bf967991-0de6-11d0-a285-00aa003049e2' = 'sAMAccountName'
    '5fd42471-1262-11d0-a060-00aa006c33ed' = 'servicePrincipalName'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'
    'bf967a08-0de6-11d0-a285-00aa003049e2' = 'userPrincipalName'
    'f0f8ff84-1191-11d0-a060-00aa006c33ed' = 'memberOf'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'User-Account-Restrictions'
    'e362ed86-b728-0842-b27d-2dea7a9df218' = 'msDS-ManagedPassword'
    '6d22168-d63f-11d2-890a-00c04f79f805' = 'ms-DS-Key-Credential-Link'
    # Zero GUID = all properties / all extended rights
    '00000000-0000-0000-0000-000000000000' = 'All-Properties/All-Extended-Rights'
}

function Resolve-ADScoutGuid {
<#
.SYNOPSIS
Resolves an AD schema/extended-rights GUID to a human-readable name.
Returns the original GUID string if not found in the map.
#>
    param([string]$Guid)
    if ([string]::IsNullOrWhiteSpace($Guid)) { return $Guid }
    $lower = $Guid.ToLower()
    if ($script:ADScoutGuidMap.ContainsKey($lower)) { return $script:ADScoutGuidMap[$lower] }
    return $Guid
}

# =============================================================================
# CORE INFRASTRUCTURE
# =============================================================================

function New-ADScoutDirectoryEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LdapPath,
        [PSCredential]$Credential
    )
    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $LdapPath,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }
    New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
}

function Get-ADScoutDomainContext {
<#
.SYNOPSIS
Auto-discovers the current AD domain, PDC, and base distinguished name.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase
    )
    $pdc    = $Server
    $source = 'RootDSE'
    if (-not $pdc -and -not $Credential) {
        try {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $pdc       = $domainObj.PdcRoleOwner.Name
            $source    = 'CurrentDomain/PDC'
        } catch { $source = 'RootDSE fallback' }
    }
    $rootPath = if ($pdc) { "LDAP://$pdc/RootDSE" } else { 'LDAP://RootDSE' }
    $root     = New-ADScoutDirectoryEntry -LdapPath $rootPath -Credential $Credential
    $base     = if ($SearchBase) { $SearchBase } else { [string]$root.Properties['defaultNamingContext'][0] }
    if ([string]::IsNullOrWhiteSpace($base)) { throw 'Could not determine defaultNamingContext/SearchBase.' }
    [PSCustomObject]@{
        Server                     = $pdc
        DefaultNamingContext       = [string]$root.Properties['defaultNamingContext'][0]
        ConfigurationNamingContext = [string]$root.Properties['configurationNamingContext'][0]
        SchemaNamingContext        = [string]$root.Properties['schemaNamingContext'][0]
        DnsHostName                = [string]$root.Properties['dnsHostName'][0]
        SearchBase                 = $base
        LdapBasePath               = if ($pdc) { "LDAP://$pdc/$base" } else { "LDAP://$base" }
        DiscoverySource            = $source
    }
}

function New-ADScoutSearcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase,
        [int]$SizeLimit = 0
    )
    $ctx      = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $root     = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter      = $Filter
    $searcher.PageSize    = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    $searcher
}

function Get-ADScoutProperty {
    param($Result, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Result) { return $null }
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        if ($Result.Properties[$Name].Count -eq 1) { return $Result.Properties[$Name][0].ToString() }
        return ($Result.Properties[$Name] | ForEach-Object { $_.ToString() }) -join ';'
    }
    $null
}

function Get-ADScoutPropertyValues {
    param($Result, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Result) { return @() }
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return @($Result.Properties[$Name] | ForEach-Object { $_.ToString() })
    }
    return @()
}

function Get-ADScoutDirectoryEntryPropertyValues {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Entry) { return @() }
    try {
        if ($Entry.Properties.Contains($Name) -and $Entry.Properties[$Name].Count -gt 0) {
            return @($Entry.Properties[$Name] | ForEach-Object { $_.ToString() })
        }
    } catch {}
    return @()
}

function Get-ADScoutObjectClassName {
    param([string[]]$ObjectClassValues)
    if (-not $ObjectClassValues -or $ObjectClassValues.Count -eq 0) { return $null }
    return $ObjectClassValues[-1]
}

function Get-ADScoutSafeProperty {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-ADScoutDirectoryObjectSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase
    )
    try {
        $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $path  = if ($ctx.Server) { "LDAP://$($ctx.Server)/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-ADScoutDirectoryEntry -LdapPath $path -Credential $Credential
        $classes = Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'objectClass'
        $sam     = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'samAccountName'    | Select-Object -First 1)
        $name    = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'name'              | Select-Object -First 1)
        $upn     = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'userPrincipalName' | Select-Object -First 1)
        $dns     = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'dNSHostName'       | Select-Object -First 1)
        [PSCustomObject]@{
            Name              = $name
            SamAccountName    = $sam
            UserPrincipalName = $upn
            DnsHostName       = $dns
            ObjectClass       = Get-ADScoutObjectClassName -ObjectClassValues $classes
            ObjectClassPath   = ($classes -join ';')
            DistinguishedName = $DistinguishedName
        }
    } catch {
        [PSCustomObject]@{
            Name=$null; SamAccountName=$null; UserPrincipalName=$null; DnsHostName=$null
            ObjectClass=$null; ObjectClassPath=$null; DistinguishedName=$DistinguishedName
            Error=$_.Exception.Message
        }
    }
}

function Get-ADScoutObjectDisplayName {
<#
.SYNOPSIS
Returns the best available display identifier for an ADScout object.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$InputObject)
    process {
        foreach ($propertyName in @('SamAccountName','MemberSamAccountName','Name','Member','DnsHostName','IdentityReference','DistinguishedName')) {
            $value = Get-ADScoutSafeProperty -InputObject $InputObject -Name $propertyName
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return [string]$value
            }
        }
        return '<unknown>'
    }
}

# =============================================================================
# VERSION / ENVIRONMENT
# =============================================================================

function ConvertTo-ADScoutUacFlag {
<#
.SYNOPSIS
Decodes a userAccountControl integer into readable flag names.
.EXAMPLE
ConvertTo-ADScoutUacFlag -UserAccountControl 66048
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$UserAccountControl)
    $map = [ordered]@{
        SCRIPT=0x0001; ACCOUNTDISABLE=0x0002; HOMEDIR_REQUIRED=0x0008; LOCKOUT=0x0010
        PASSWD_NOTREQD=0x0020; PASSWD_CANT_CHANGE=0x0040; ENCRYPTED_TEXT_PWD_ALLOWED=0x0080
        TEMP_DUPLICATE_ACCOUNT=0x0100; NORMAL_ACCOUNT=0x0200; INTERDOMAIN_TRUST_ACCOUNT=0x0800
        WORKSTATION_TRUST_ACCOUNT=0x1000; SERVER_TRUST_ACCOUNT=0x2000; DONT_EXPIRE_PASSWORD=0x10000
        MNS_LOGON_ACCOUNT=0x20000; SMARTCARD_REQUIRED=0x40000; TRUSTED_FOR_DELEGATION=0x80000
        NOT_DELEGATED=0x100000; USE_DES_KEY_ONLY=0x200000; DONT_REQUIRE_PREAUTH=0x400000
        PASSWORD_EXPIRED=0x800000; TRUSTED_TO_AUTH_FOR_DELEGATION=0x1000000
        PARTIAL_SECRETS_ACCOUNT=0x04000000
    }
    foreach ($kv in $map.GetEnumerator()) {
        if (($UserAccountControl -band [int]$kv.Value) -ne 0) { $kv.Key }
    }
}

function Get-ADScoutVersion {
<#
.SYNOPSIS
Returns ADScoutPS version and runtime information.
#>
    [CmdletBinding()]
    param()
    [PSCustomObject]@{
        Name              = 'ADScoutPS'
        Version           = $script:ADScoutVersion
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition         = $PSVersionTable.PSEdition
        ComputerName      = $env:COMPUTERNAME
        UserName          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Timestamp         = Get-Date
    }
}

function Test-ADScoutEnvironment {
<#
.SYNOPSIS
Runs a quick environment validation before collection.
.DESCRIPTION
Checks current identity, PowerShell version, RootDSE/domain discovery, LDAP bind,
and Out-GridView availability.
.EXAMPLE
Test-ADScoutEnvironment
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx = $null; $domainStatus = 'Failed'; $ldapStatus = 'Failed'; $errorText = $null
    try {
        $ctx          = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $domainStatus = 'Success'
        $entry        = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
        [void]$entry.NativeObject
        $ldapStatus   = 'Success'
    } catch { $errorText = $_.Exception.Message }
    [PSCustomObject]@{
        Tool                = 'ADScoutPS'
        Version             = $script:ADScoutVersion
        CurrentUser         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ComputerName        = $env:COMPUTERNAME
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        PSEdition           = $PSVersionTable.PSEdition
        DomainDiscovery     = $domainStatus
        LdapBind            = $ldapStatus
        Server              = if ($ctx) { $ctx.Server }     else { $Server }
        SearchBase          = if ($ctx) { $ctx.SearchBase } else { $SearchBase }
        DomainController    = if ($ctx) { $ctx.DnsHostName } else { $null }
        OutGridViewAvailable = [bool](Get-Command Out-GridView -ErrorAction SilentlyContinue)
        Error               = $errorText
        Timestamp           = Get-Date
    }
}

# =============================================================================
# COLLECTION FUNCTIONS
# =============================================================================

function Get-ADScoutDomainInfo {
<#
.SYNOPSIS
Retrieves RootDSE/domain metadata.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
}

function Get-ADScoutUser {
<#
.SYNOPSIS
Retrieves AD users with decoded UAC flags.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $props = 'samaccountname','userprincipalname','displayname','distinguishedname',
             'description','serviceprincipalname','lastlogontimestamp','memberof',
             'useraccountcontrol','admincount','msds-keycredentiallink'
    $s = New-ADScoutSearcher -Filter '(&(objectCategory=person)(objectClass=user))' `
         -Properties $props -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $uacRaw = Get-ADScoutProperty $r 'useraccountcontrol'
        $uac    = if ($uacRaw) { [int]$uacRaw } else { 0 }
        [PSCustomObject]@{
            SamAccountName       = Get-ADScoutProperty $r 'samaccountname'
            UserPrincipalName    = Get-ADScoutProperty $r 'userprincipalname'
            DisplayName          = Get-ADScoutProperty $r 'displayname'
            Description          = Get-ADScoutProperty $r 'description'
            AdminCount           = Get-ADScoutProperty $r 'admincount'
            UserAccountControl   = $uac
            UacFlags             = (ConvertTo-ADScoutUacFlag -UserAccountControl $uac) -join ','
            ServicePrincipalName = Get-ADScoutProperty $r 'serviceprincipalname'
            MemberOf             = Get-ADScoutProperty $r 'memberof'
            HasShadowCredential  = ([bool](Get-ADScoutProperty $r 'msds-keycredentiallink'))
            DistinguishedName    = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutGroup {
<#
.SYNOPSIS
Retrieves AD groups.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=group)' `
         -Properties @('samaccountname','name','distinguishedname','description','member') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            Description       = Get-ADScoutProperty $r 'description'
            Member            = Get-ADScoutProperty $r 'member'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutComputer {
<#
.SYNOPSIS
Retrieves AD computer objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $props = 'name','dnshostname','operatingsystem','operatingsystemversion',
             'distinguishedname','description','useraccountcontrol','lastlogontimestamp',
             'primarygroupid','ms-mcs-admpwdexpirationtime','mslaps-passwordexpirationtime',
             'msds-keycredentiallink'
    $s = New-ADScoutSearcher -Filter '(objectCategory=computer)' `
         -Properties $props -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $uacRaw = Get-ADScoutProperty $r 'useraccountcontrol'
        $uac    = if ($uacRaw) { [int]$uacRaw } else { 0 }
        [PSCustomObject]@{
            Name                   = Get-ADScoutProperty $r 'name'
            DnsHostName            = Get-ADScoutProperty $r 'dnshostname'
            Description            = Get-ADScoutProperty $r 'description'
            OperatingSystem        = Get-ADScoutProperty $r 'operatingsystem'
            OperatingSystemVersion = Get-ADScoutProperty $r 'operatingsystemversion'
            LastLogonTimestamp    = Get-ADScoutProperty $r 'lastlogontimestamp'
            PrimaryGroupId        = Get-ADScoutProperty $r 'primarygroupid'
            UserAccountControl    = $uac
            UacFlags              = (ConvertTo-ADScoutUacFlag -UserAccountControl $uac) -join ','
            HasLegacyLaps          = ([bool](Get-ADScoutProperty $r 'ms-mcs-admpwdexpirationtime'))
            HasWindowsLaps         = ([bool](Get-ADScoutProperty $r 'mslaps-passwordexpirationtime'))
            HasShadowCredential    = ([bool](Get-ADScoutProperty $r 'msds-keycredentiallink'))
            DistinguishedName      = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutDomainController {
<#
.SYNOPSIS
Enumerates domain controllers.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.UacFlags -match 'SERVER_TRUST_ACCOUNT' -or $_.PrimaryGroupId -eq '516' }
}

function Find-ADScoutSPNAccount {
<#
.SYNOPSIS
Finds accounts with servicePrincipalName values set (Kerberoast review targets).
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher `
         -Filter '(&(servicePrincipalName=*)(|(objectCategory=person)(objectCategory=computer)))' `
         -Properties @('samaccountname','serviceprincipalname','distinguishedname','description','admincount') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            SamAccountName       = Get-ADScoutProperty $r 'samaccountname'
            ServicePrincipalName = Get-ADScoutProperty $r 'serviceprincipalname'
            Description          = Get-ADScoutProperty $r 'description'
            AdminCount           = Get-ADScoutProperty $r 'admincount'
            DistinguishedName    = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Find-ADScoutASREPAccount {
<#
.SYNOPSIS
Finds accounts with Kerberos preauthentication disabled (AS-REP roast candidates).
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.UacFlags -match 'DONT_REQUIRE_PREAUTH' }
}

function Find-ADScoutUnconstrainedDelegation {
<#
.SYNOPSIS
Finds accounts configured for unconstrained delegation.
.DESCRIPTION
Returns users and computers with TRUSTED_FOR_DELEGATION set. Domain controllers are
excluded by default since unconstrained delegation is expected on DCs.
#>
    [CmdletBinding()]
    param(
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [switch]$IncludeDomainControllers
    )
    $items = @(Get-ADScoutUser     -Server $Server -Credential $Credential -SearchBase $SearchBase) +
             @(Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase)
    foreach ($item in $items) {
        $uacFlags = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'UacFlags')
        if ($uacFlags -notmatch 'TRUSTED_FOR_DELEGATION') { continue }
        $primaryGroupId  = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'PrimaryGroupId')
        $objectName      = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'SamAccountName')
        if ([string]::IsNullOrWhiteSpace($objectName)) {
            $objectName = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'Name')
        }
        $isDomainController = ($primaryGroupId -eq '516' -or $uacFlags -match 'SERVER_TRUST_ACCOUNT')
        if ($isDomainController -and -not $IncludeDomainControllers) { continue }
        [PSCustomObject]@{
            Name              = $objectName
            ObjectType        = if ($primaryGroupId) { 'computer' } else { 'user' }
            IsDomainController = $isDomainController
            PrimaryGroupId    = $primaryGroupId
            UacFlags          = $uacFlags
            DistinguishedName = Get-ADScoutSafeProperty -InputObject $item -Name 'DistinguishedName'
        }
    }
}

function Find-ADScoutConstrainedDelegation {
<#
.SYNOPSIS
Finds traditional constrained delegation (KCD) and resource-based constrained delegation (RBCD).
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $kcd = New-ADScoutSearcher `
           -Filter '(&(msDS-AllowedToDelegateTo=*)(|(objectCategory=computer)(objectCategory=person)))' `
           -Properties @('samaccountname','distinguishedname','msds-allowedtodelegateto') `
           -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $kcd.FindAll()) {
        [PSCustomObject]@{
            Type              = 'KCD'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            DelegatesTo       = Get-ADScoutProperty $r 'msds-allowedtodelegateto'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
    $rbcd = New-ADScoutSearcher `
            -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
            -Properties @('samaccountname','distinguishedname','name') `
            -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $rbcd.FindAll()) {
        [PSCustomObject]@{
            Type              = 'RBCD'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            DelegatesTo       = 'msDS-AllowedToActOnBehalfOfOtherIdentity present'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutDomainTrust {
<#
.SYNOPSIS
Enumerates domain trust objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=trustedDomain)' `
         -Properties @('name','flatname','trustdirection','trusttype','trustattributes','distinguishedname') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $attrs    = Get-ADScoutProperty $r 'trustattributes'
        $attrsInt = if ($attrs) { [int]$attrs } else { 0 }
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            FlatName          = Get-ADScoutProperty $r 'flatname'
            TrustDirection    = switch ([int](Get-ADScoutProperty $r 'trustdirection')) {
                                    0 { 'Disabled' } 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' }
                                    default { Get-ADScoutProperty $r 'trustdirection' }
                                }
            TrustType         = switch ([int](Get-ADScoutProperty $r 'trusttype')) {
                                    1 { 'Downlevel' } 2 { 'Uplevel' } 3 { 'MIT' } 4 { 'DCE' }
                                    default { Get-ADScoutProperty $r 'trusttype' }
                                }
            SIDFilteringEnabled = (($attrsInt -band 0x4) -ne 0)
            IsTransitive      = (($attrsInt -band 0x2) -eq 0)
            IsForestTrust     = (($attrsInt -band 0x8) -ne 0)
            TrustAttributesRaw = $attrs
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutPasswordPolicy {
<#
.SYNOPSIS
Returns default domain password policy and fine-grained password policies where readable.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $entry = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $defaultMinLength = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'minPwdLength'    | Select-Object -First 1)
    $defaultHistory   = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'pwdHistoryLength' | Select-Object -First 1)
    $defaultLockout   = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'lockoutThreshold' | Select-Object -First 1)
    $defaultMaxAge    = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'maxPwdAge'        | Select-Object -First 1)
    $defaultMinAge    = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'minPwdAge'        | Select-Object -First 1)
    [PSCustomObject]@{
        PolicyType       = 'DefaultDomain'
        Name             = 'Default Domain Policy'
        DistinguishedName = $ctx.SearchBase
        MinPwdLength     = $defaultMinLength
        PwdHistoryLength = $defaultHistory
        LockoutThreshold = $defaultLockout
        LockoutDisabled  = ($defaultLockout -ne $null -and [int]$defaultLockout -eq 0)
        MaxPwdAgeRaw     = $defaultMaxAge
        MinPwdAgeRaw     = $defaultMinAge
    }
    $s = New-ADScoutSearcher -Filter '(objectClass=msDS-PasswordSettings)' `
         -Properties @('name','distinguishedname','msds-minimumpasswordlength','msds-passwordhistorylength',
                       'msds-lockoutthreshold','msds-passwordsettingsprecedence','msds-psoappliesto') `
         -Server $Server -Credential $Credential -SearchBase $ctx.SearchBase
    foreach ($r in $s.FindAll()) {
        $fgLockout = Get-ADScoutProperty $r 'msds-lockoutthreshold'
        [PSCustomObject]@{
            PolicyType       = 'FineGrained'
            Name             = Get-ADScoutProperty $r 'name'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
            Precedence       = Get-ADScoutProperty $r 'msds-passwordsettingsprecedence'
            MinPwdLength     = Get-ADScoutProperty $r 'msds-minimumpasswordlength'
            PwdHistoryLength = Get-ADScoutProperty $r 'msds-passwordhistorylength'
            LockoutThreshold = $fgLockout
            LockoutDisabled  = ($fgLockout -ne $null -and [int]$fgLockout -eq 0)
            AppliesTo        = Get-ADScoutProperty $r 'msds-psoappliesto'
        }
    }
}

function Find-ADScoutAdminSDHolderOrphan {
<#
.SYNOPSIS
Finds adminCount=1 users/groups -- current or historical privileged objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher `
         -Filter '(&(adminCount=1)(|(objectCategory=person)(objectCategory=group)))' `
         -Properties @('samaccountname','name','objectclass','distinguishedname','admincount') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            ObjectClass       = Get-ADScoutProperty $r 'objectclass'
            AdminCount        = Get-ADScoutProperty $r 'admincount'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Find-ADScoutWeakUacFlag {
<#
.SYNOPSIS
Finds users with weak or review-worthy UAC flags.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.UacFlags -match 'PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD|ENCRYPTED_TEXT_PWD_ALLOWED|USE_DES_KEY_ONLY' }
}

function Get-ADScoutLapsStatus {
<#
.SYNOPSIS
Reports visible legacy/Windows LAPS metadata per computer.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Select-Object Name, DnsHostName, HasLegacyLaps, HasWindowsLaps, DistinguishedName
}

function Get-ADScoutGPO {
<#
.SYNOPSIS
Enumerates Group Policy Objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)
    $ctx        = Get-ADScoutDomainContext -Server $Server -Credential $Credential
    $policyBase = "CN=Policies,CN=System,$($ctx.DefaultNamingContext)"
    $s = New-ADScoutSearcher -Filter '(objectClass=groupPolicyContainer)' `
         -Properties @('displayname','name','distinguishedname','whenchanged','gpcfilesyspath') `
         -Server $Server -Credential $Credential -SearchBase $policyBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            DisplayName       = Get-ADScoutProperty $r 'displayname'
            Guid              = Get-ADScoutProperty $r 'name'
            GpcFileSysPath    = Get-ADScoutProperty $r 'gpcfilesyspath'
            WhenChanged       = Get-ADScoutProperty $r 'whenchanged'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutOU {
<#
.SYNOPSIS
Enumerates Organizational Units and linked GPO metadata.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=organizationalUnit)' `
         -Properties @('name','distinguishedname','gplink') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            LinkedGPOs        = Get-ADScoutProperty $r 'gplink'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutLinkedGPO {
<#
.SYNOPSIS
Returns OUs that have linked GPOs.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutOU -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.LinkedGPOs }
}

function Find-ADScoutOldComputer {
<#
.SYNOPSIS
Finds computer accounts that have not authenticated within the specified number of days.
.DESCRIPTION
Converts lastLogonTimestamp via [datetime]::FromFileTime() for accurate comparison.
Note: lastLogonTimestamp replicates on a 9-14 day jitter by design -- results carry
inherent fuzziness of up to ~2 weeks. Accounts with no lastLogonTimestamp are always
included as they may have never authenticated.
.EXAMPLE
Find-ADScoutOldComputer -Days 90
#>
    [CmdletBinding()]
    param(
        [int]$Days = 90,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    $cutoff = (Get-Date).AddDays(-$Days)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object {
        if (-not $_.LastLogonTimestamp) { return $true }
        try {
            $ft = [long]$_.LastLogonTimestamp
            [datetime]::FromFileTime($ft) -lt $cutoff
        } catch { $true }
    }
}

function Test-ADScoutPrivilegedIdentity {
<#
.SYNOPSIS
Returns $true if an ACE identity reference or SID belongs to a well-known privileged principal.
.DESCRIPTION
Checks both the IdentityReference (display name) and IdentitySid fields so the exclusion
works correctly on non-English AD environments where group names are localized.
Well-known privileged SID suffixes: -512 (DA), -516 (DC), -518 (Schema Admins),
-519 (EA), -544 (Builtin\Admins), S-1-5-18 (SYSTEM), S-1-5-9 (Enterprise DCs).
#>
    param(
        [string]$IdentityReference,
        [string]$IdentitySid
    )
    # SID-suffix match -- locale-safe, primary check
    $privilegedSidPattern = '-512$|-516$|-518$|-519$|-544$|^S-1-5-18$|^S-1-5-9$'
    if ($IdentitySid -and $IdentitySid -match $privilegedSidPattern) { return $true }
    # Name-pattern match -- English fallback / additional coverage
    $privilegedNamePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                             'SYSTEM|CREATOR OWNER|Domain Controllers|NT AUTHORITY\\SYSTEM|' +
                             'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS'
    if ($IdentityReference -and $IdentityReference -match $privilegedNamePattern) { return $true }
    return $false
}

function Find-ADScoutAclAttackPath {
<#
.SYNOPSIS
Checks ACLs on high-value AD objects for abusable rights held by non-privileged principals.
.DESCRIPTION
Find-ADScoutInterestingAce only checks the domain root. This function sweeps ACLs on
specific high-value targets: privileged groups, krbtgt, DA user accounts, and DC computer
objects -- the objects where an abusable ACE actually translates to a privilege escalation path.

Abusable rights checked: GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty,
Self, ExtendedRight.

Well-known privileged principals are filtered via Test-ADScoutPrivilegedIdentity
(SID-suffix primary, display name fallback -- locale-safe).
.EXAMPLE
Find-ADScoutAclAttackPath
.EXAMPLE
Find-ADScoutAclAttackPath | Where-Object { $_.Rights -match 'GenericAll|WriteDacl' }
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)

    # Fixed high-value group targets
    $groupTargets = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators',
        'Server Operators', 'Print Operators', 'DnsAdmins',
        'Group Policy Creator Owners', 'Remote Management Users'
    )

    # Add krbtgt account
    $userTargets = @('krbtgt')

    # Add individual DA members (users only -- so an ACE on a DA account is visible)
    try {
        $daMembers = @(Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive `
                       -Server $Server -Credential $Credential -SearchBase $SearchBase |
                       Where-Object { $_.MemberObjectClass -eq 'user' } |
                       Select-Object -ExpandProperty MemberSamAccountName)
        $userTargets += $daMembers
    } catch {}

    # Add DC computer objects
    $dcTargets = @(Get-ADScoutDomainController -Server $Server -Credential $Credential -SearchBase $SearchBase |
                   Select-Object -ExpandProperty Name)

    $allTargets = @(
        ($groupTargets | ForEach-Object { @{ Identity=$_; TargetType='Group' } })
        ($userTargets  | ForEach-Object { @{ Identity=$_; TargetType='User'  } })
        ($dcTargets    | ForEach-Object { @{ Identity=$_; TargetType='Computer' } })
    )

    foreach ($t in $allTargets) {
        try {
            Get-ADScoutObjectAcl -Identity $t.Identity -Server $Server -Credential $Credential -SearchBase $SearchBase |
                Where-Object {
                    $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|Self|ExtendedRight' -and
                    $_.AccessControlType     -eq 'Allow' -and
                    -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
                } |
                ForEach-Object {
                    [PSCustomObject]@{
                        TargetObject      = $t.Identity
                        TargetType        = $t.TargetType
                        IdentityReference = $_.IdentityReference
                        Rights            = $_.ActiveDirectoryRights
                        ObjectType        = $_.ObjectType
                        IsInherited       = $_.IsInherited
                        DistinguishedName = $_.DistinguishedName
                    }
                }
        } catch {}
    }
}


function Find-ADScoutAdminGroup {
<#
.SYNOPSIS
Finds admin/privileged-looking groups by name pattern.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.Name -match 'admin|operator|backup|account|enterprise|schema|domain controllers' }
}

function Find-ADScoutLocalAdminAccess {
<#
.SYNOPSIS
Finds computers where the current user has local administrator access.
.DESCRIPTION
Attempts to open the Service Control Manager (SCM) on each domain computer
with SC_MANAGER_ALL_ACCESS. A successful connection means the current user
has local admin rights on that machine -- same technique as PowerView's
Find-LocalAdminAccess.

Uses computers already collected in RunData (no re-collection).
Falls back to a live LDAP query if no RunData is in session.

Note: This touches live hosts over SMB (port 445). It will generate
authentication events on target machines. Use with awareness of detection risk.

Note: Will not work reliably against computers that are offline or
blocking SMB. Errors per host are suppressed by default (-Verbose to see them).
.EXAMPLE
Find-LocalAdmin
.EXAMPLE
Find-LocalAdmin -Verbose
.EXAMPLE
Find-ADScoutLocalAdminAccess -ComputerName dc01,web04,files04
#>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [int]$TimeoutMs = 2000
    )

    # P/Invoke signature for OpenSCManager
    $code = @'
using System;
using System.Runtime.InteropServices;
public class SCMCheck {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);
    public const uint SC_MANAGER_ALL_ACCESS    = 0xF003F;
    public const uint SC_MANAGER_CONNECT       = 0x0001;
    public const uint SERVICES_ACTIVE_DATABASE = 0;
}
'@
    # Add type only once per session
    if (-not ([System.Management.Automation.PSTypeName]'SCMCheck').Type) {
        try { Add-Type -TypeDefinition $code -Language CSharp }
        catch { Write-Warning "Failed to compile SCMCheck type: $($_.Exception.Message)"; return }
    }

    # Get computer list -- RunData first, then parameter, then live query
    $targets = @()
    if ($ComputerName -and $ComputerName.Count -gt 0) {
        $targets = $ComputerName
    } elseif ($script:ADScoutLastRun -and $script:ADScoutLastRun.Computers) {
        $targets = @($script:ADScoutLastRun.Computers |
                     ForEach-Object {
                         $dns = Get-ADScoutSafeProperty $_ 'DnsHostName'
                         $name = Get-ADScoutSafeProperty $_ 'Name'
                         if ($dns) { $dns } elseif ($name) { $name }
                     } | Where-Object { $_ })
    } else {
        Write-Host '[*] No RunData in session -- querying LDAP for computers...' -ForegroundColor DarkGray
        $targets = @(Get-ADScoutComputer | ForEach-Object {
            $dns = Get-ADScoutSafeProperty $_ 'DnsHostName'
            $name = Get-ADScoutSafeProperty $_ 'Name'
            if ($dns) { $dns } elseif ($name) { $name }
        } | Where-Object { $_ })
    }

    if ($targets.Count -eq 0) {
        Write-Warning 'No computers found to scan.'
        return
    }

    Write-Host "[*] Scanning $($targets.Count) computers for local admin access..." -ForegroundColor Cyan
    $found = [System.Collections.ArrayList]@()

    foreach ($target in $targets) {
        Write-Verbose "Trying $target..."
        try {
            $handle = [SCMCheck]::OpenSCManager($target, 'ServicesActive', [SCMCheck]::SC_MANAGER_ALL_ACCESS)
            if ($handle -ne [IntPtr]::Zero) {
                [void][SCMCheck]::CloseServiceHandle($handle)
                Write-Host "[+] Local admin: $target" -ForegroundColor Green
                [void]$found.Add([PSCustomObject]@{
                    ComputerName = $target
                    Access       = 'LocalAdmin'
                    Method       = 'SCM-OpenSCManager'
                    Timestamp    = Get-Date
                })
            } else {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "$target -- access denied (error $err)"
            }
        } catch {
            Write-Verbose "$target -- $($_.Exception.Message)"
        }
    }

    if ($found.Count -eq 0) {
        Write-Host '[-] No local admin access found.' -ForegroundColor DarkYellow
    } else {
        Write-Host "[+] Local admin access on $($found.Count) machine(s)." -ForegroundColor Green
    }

    return @($found)
}

function Find-ADScoutPasswordInDescription {
<#
.SYNOPSIS
Finds user and computer accounts with credential or flag content in any readable string field.
.DESCRIPTION
Checks description, info, comment, physicalDeliveryOfficeName, homeDirectory,
scriptPath, and profilePath. All are readable by authenticated domain users by default.
Lab designers and admins commonly store passwords, credentials, or flags in these fields.
The keyword pattern is intentionally broad -- review all results in context.
.EXAMPLE
Find-ADScoutPasswordInDescription
.EXAMPLE
Find-ADScoutPasswordInDescription | Format-Table SamAccountName, Field, Value -AutoSize
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase, [switch]$LabMode)

    $keywords = @('pass','pwd','cred','secret','key','login','logon','temp','default',
                  'welcome','initial','P@ss','changeme')
    if ($LabMode) { $keywords += @('OS{','HTB{','FLAG{','{') }
    $pattern  = ($keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'

    $userFields = @(
        'description',
        'info',
        'comment',
        'physicaldeliveryofficename',
        'homedirectory',
        'scriptpath',
        'profilepath',
        'homephone',
        'streetaddress'
    )

    # Fields to check on computer objects
    $computerFields = @(
        'description',
        'info',
        'comment',
        'physicaldeliveryofficename',
        'location'
    )

    # Users -- direct LDAP query to get all extended fields
    $userProps = @('samaccountname','distinguishedname') + $userFields
    $us = New-ADScoutSearcher -Filter '(&(objectCategory=person)(objectClass=user))' `
          -Properties $userProps -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $us.FindAll()) {
        $sam = Get-ADScoutProperty $r 'samaccountname'
        $dn  = Get-ADScoutProperty $r 'distinguishedname'
        foreach ($field in $userFields) {
            $val = Get-ADScoutProperty $r $field
            if ($val -and $val -match $pattern) {
                [PSCustomObject]@{
                    ObjectType        = 'user'
                    SamAccountName    = $sam
                    Field             = $field
                    Value             = $val
                    DistinguishedName = $dn
                }
            }
        }
    }

    # Computers -- direct LDAP query
    $compProps = @('name','distinguishedname') + $computerFields
    $cs = New-ADScoutSearcher -Filter '(objectCategory=computer)' `
          -Properties $compProps -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $cs.FindAll()) {
        $name = Get-ADScoutProperty $r 'name'
        $dn   = Get-ADScoutProperty $r 'distinguishedname'
        foreach ($field in $computerFields) {
            $val = Get-ADScoutProperty $r $field
            if ($val -and $val -match $pattern) {
                [PSCustomObject]@{
                    ObjectType        = 'computer'
                    SamAccountName    = $name
                    Field             = $field
                    Value             = $val
                    DistinguishedName = $dn
                }
            }
        }
    }
}

# =============================================================================
# ACL FUNCTIONS
# =============================================================================

function Resolve-ADScoutDistinguishedName {
    [CmdletBinding()]
    param(
        [string]$Identity, [string]$ObjectClass = '*',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    if ($Identity -match '^(CN|OU|DC)=') { return $Identity }
    $safe        = $Identity -replace '\\','\\5c' -replace '\*','\\2a' -replace '\(','\\28' -replace '\)','\\29'
    $classFilter = if ($ObjectClass -and $ObjectClass -ne '*') { "(objectClass=$ObjectClass)" } else { '(objectClass=*)' }
    $filter      = "(&${classFilter}(|(name=$safe)(samAccountName=$safe)(displayName=$safe)))"
    $s = New-ADScoutSearcher -Filter $filter -Properties @('distinguishedname') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase -SizeLimit 1
    $r = $s.FindOne()
    if (-not $r) { throw "Could not resolve identity '$Identity' to a distinguishedName." }
    Get-ADScoutProperty $r 'distinguishedname'
}

function Get-ADScoutObjectAcl {
<#
.SYNOPSIS
Reads ACL/ACE data for an AD object by distinguishedName or friendly identity.
.EXAMPLE
Get-ADScoutObjectAcl -Identity 'Domain Admins' -ObjectClass group
#>
    [CmdletBinding(DefaultParameterSetName = 'DN')]
    param(
        [Parameter(ParameterSetName = 'DN')][string]$DistinguishedName,
        [Parameter(ParameterSetName = 'Identity')][string]$Identity,
        [Parameter(ParameterSetName = 'Identity')][string]$ObjectClass = '*',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    if (-not $DistinguishedName) {
        $DistinguishedName = Resolve-ADScoutDistinguishedName -Identity $Identity -ObjectClass $ObjectClass `
                             -Server $Server -Credential $Credential -SearchBase $SearchBase
    }
    $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $path  = if ($ctx.Server) { "LDAP://$($ctx.Server)/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
    $entry = New-ADScoutDirectoryEntry -LdapPath $path -Credential $Credential
    foreach ($ace in $entry.ObjectSecurity.Access) {
        $rawObjType = $ace.ObjectType.ToString()
        $rawInhType = $ace.InheritedObjectType.ToString()
        $identRef   = $ace.IdentityReference
        # Resolve to NTAccount if it came in as a SID, or extract SID if it came as NTAccount
        $sidString  = $null
        try {
            if ($identRef -is [System.Security.Principal.SecurityIdentifier]) {
                $sidString = $identRef.ToString()
            } elseif ($identRef -is [System.Security.Principal.NTAccount]) {
                $sidString = $identRef.Translate([System.Security.Principal.SecurityIdentifier]).ToString()
            } else {
                $sidString = ([System.Security.Principal.NTAccount]$identRef.ToString()).Translate([System.Security.Principal.SecurityIdentifier]).ToString()
            }
        } catch { $sidString = $null }
        [PSCustomObject]@{
            IdentityReference       = $ace.IdentityReference.ToString()
            IdentitySid             = $sidString
            ActiveDirectoryRights   = $ace.ActiveDirectoryRights.ToString()
            AccessControlType       = $ace.AccessControlType.ToString()
            ObjectType              = Resolve-ADScoutGuid -Guid $rawObjType
            ObjectTypeGuid          = $rawObjType
            InheritedObjectType     = Resolve-ADScoutGuid -Guid $rawInhType
            InheritedObjectTypeGuid = $rawInhType
            IsInherited             = $ace.IsInherited
            InheritanceType         = $ace.InheritanceType.ToString()
            DistinguishedName       = $DistinguishedName
        }
    }
}

function Find-ADScoutInterestingAce {
<#
.SYNOPSIS
Finds powerful ACEs on a target object or the domain root.
#>
    [CmdletBinding()]
    param(
        [string]$DistinguishedName, [string]$Identity, [string]$ObjectClass = '*',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    $aclParams = @{ Server=$Server; Credential=$Credential; SearchBase=$SearchBase }
    if     ($DistinguishedName) { $aclParams['DistinguishedName'] = $DistinguishedName }
    elseif ($Identity)          { $aclParams['Identity'] = $Identity; $aclParams['ObjectClass'] = $ObjectClass }
    else   { $aclParams['DistinguishedName'] = (Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase).SearchBase }
    Get-ADScoutObjectAcl @aclParams |
        Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight|CreateChild|DeleteChild|WriteProperty' }
}

function Find-ADScoutDCSyncRight {
<#
.SYNOPSIS
Detects principals with replication rights on the domain root ACL.
.DESCRIPTION
Well-known privileged principals are identified by SID suffix rather than name,
making detection locale-safe on non-English Windows installs.
Well-known SID suffixes treated as expected/Info:
  -512 Domain Admins, -516 Domain Controllers, -518 Schema Admins,
  -519 Enterprise Admins, S-1-5-18 SYSTEM, S-1-5-9 Enterprise Domain Controllers
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $repGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
        '89e95b76-444d-4c62-991a-0facbeda640c'
    )
    Get-ADScoutObjectAcl -DistinguishedName $ctx.SearchBase -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $repGuids -contains $_.ObjectTypeGuid } |
        ForEach-Object {
            $identityRef = $_.IdentityReference
            $identitySid = $_.IdentitySid
            $isWellKnown = Test-ADScoutPrivilegedIdentity -IdentityReference $identityRef -IdentitySid $identitySid
            $sev         = if ($isWellKnown) { 'Info' } else { 'Critical' }
            [PSCustomObject]@{
                Severity              = $sev
                IdentityReference     = $identityRef
                RightName             = $_.ObjectType
                ActiveDirectoryRights = $_.ActiveDirectoryRights
                AccessControlType     = $_.AccessControlType
                IsInherited           = $_.IsInherited
                DistinguishedName     = $ctx.SearchBase
            }
        }
}

# =============================================================================
# GROUP MEMBERSHIP / PRIVILEGE PATH
# =============================================================================

function Get-ADScoutGroupMember {
<#
.SYNOPSIS
Gets direct or recursive group members with analyst-friendly columns.
.EXAMPLE
Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [switch]$Recursive,
        [int]$MaxDepth = 20,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    $rootGroupDn   = Resolve-ADScoutDistinguishedName -Identity $Identity -ObjectClass group `
                     -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rootSummary   = Get-ADScoutDirectoryObjectSummary -DistinguishedName $rootGroupDn `
                     -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rootGroupName = if ($rootSummary.SamAccountName) { $rootSummary.SamAccountName } `
                     elseif ($rootSummary.Name) { $rootSummary.Name } else { $Identity }
    $visited       = New-Object 'System.Collections.Generic.HashSet[string]'

    function Invoke-ADScoutGroupMemberWalk {
        param([string]$GroupDn, [string]$ParentGroupName, [int]$Depth, [string]$Path)
        if ($Depth -gt $MaxDepth) { return }
        if (-not $visited.Add($GroupDn)) { return }
        $ctx        = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $groupPath  = if ($ctx.Server) { "LDAP://$($ctx.Server)/$GroupDn" } else { "LDAP://$GroupDn" }
        $groupEntry = New-ADScoutDirectoryEntry -LdapPath $groupPath -Credential $Credential
        $memberDns  = Get-ADScoutDirectoryEntryPropertyValues -Entry $groupEntry -Name 'member'
        foreach ($memberDn in $memberDns) {
            $member     = Get-ADScoutDirectoryObjectSummary -DistinguishedName $memberDn `
                          -Server $Server -Credential $Credential -SearchBase $SearchBase
            $display    = if ($member.SamAccountName) { $member.SamAccountName } `
                          elseif ($member.Name) { $member.Name } `
                          elseif ($member.DnsHostName) { $member.DnsHostName } else { $memberDn }
            $memberPath = if ($Path) { "$Path -> $display" } else { "$ParentGroupName -> $display" }
            [PSCustomObject]@{
                RootGroup              = $rootGroupName
                ParentGroup            = $ParentGroupName
                MemberName             = $member.Name
                MemberSamAccountName   = $member.SamAccountName
                MemberUserPrincipalName = $member.UserPrincipalName
                MemberDnsHostName      = $member.DnsHostName
                MemberObjectClass      = $member.ObjectClass
                Depth                  = $Depth
                IsNested               = ($Depth -gt 0)
                Path                   = $memberPath
                MemberDistinguishedName = $member.DistinguishedName
            }
            if ($Recursive -and $member.ObjectClass -eq 'group') {
                Invoke-ADScoutGroupMemberWalk -GroupDn $memberDn -ParentGroupName $display `
                    -Depth ($Depth + 1) -Path $memberPath
            }
        }
    }
    Invoke-ADScoutGroupMemberWalk -GroupDn $rootGroupDn -ParentGroupName $rootGroupName -Depth 0 -Path $rootGroupName
}

function Get-ADScoutGroupReport {
<#
.SYNOPSIS
Creates a clean group/member report for all groups, selected groups, or privileged groups.
.EXAMPLE
Get-ADScoutGroupReport -PrivilegedOnly -Recursive | Format-Table -AutoSize
.EXAMPLE
Get-ADScoutGroupReport -GroupName 'Domain Admins','Remote Management Users' -Recursive
#>
    [CmdletBinding()]
    param(
        [string[]]$GroupName, [switch]$Recursive, [switch]$PrivilegedOnly,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    if ($PrivilegedOnly) {
        $GroupName = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                       'Account Operators','Backup Operators','Server Operators','Print Operators',
                       'Remote Desktop Users','Remote Management Users','DnsAdmins',
                       'Group Policy Creator Owners')
    }
    if (-not $GroupName -or $GroupName.Count -eq 0) {
        $GroupName = @(Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase |
                       Select-Object -ExpandProperty Name)
    }
    foreach ($group in $GroupName) {
        try {
            $rows = @(Get-ADScoutGroupMember -Identity $group -Recursive:$Recursive `
                      -Server $Server -Credential $Credential -SearchBase $SearchBase)
            if ($rows.Count -eq 0) {
                [PSCustomObject]@{ Group=$group; ParentGroup=$group; Member='<No members found>'
                    MemberType=$null; Depth=$null; IsNested=$null; Path=$null; DistinguishedName=$null }
                continue
            }
            foreach ($row in $rows) {
                $memberName = if ($row.MemberSamAccountName) { $row.MemberSamAccountName } `
                              elseif ($row.MemberName) { $row.MemberName } `
                              elseif ($row.MemberDnsHostName) { $row.MemberDnsHostName } `
                              else { $row.MemberDistinguishedName }
                [PSCustomObject]@{
                    Group=$row.RootGroup; ParentGroup=$row.ParentGroup; Member=$memberName
                    MemberType=$row.MemberObjectClass; Depth=$row.Depth; IsNested=$row.IsNested
                    Path=$row.Path; DistinguishedName=$row.MemberDistinguishedName
                }
            }
        } catch {
            [PSCustomObject]@{ Group=$group; ParentGroup=$group; Member='<Error>'
                MemberType=$null; Depth=$null; IsNested=$null
                Path=$_.Exception.Message; DistinguishedName=$null }
        }
    }
}

function Find-ADScoutPrivilegedUser {
<#
.SYNOPSIS
Expands common privileged groups to identify privileged user members.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.Member -and $_.Member -notlike '<*>' }
}

function Find-ADScoutDelegationHint {
<#
.SYNOPSIS
Compatibility wrapper -- returns all delegation review items.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    @(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) +
    @(Find-ADScoutConstrainedDelegation   -Server $Server -Credential $Credential -SearchBase $SearchBase)
}

function Get-ADScoutPrivilegePath {
<#
.SYNOPSIS
Shows user-to-privileged-group membership paths.
.EXAMPLE
Get-ADScoutPrivilegePath
#>
    [CmdletBinding()]
    param([int]$MaxDepth = 20, [string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.MemberType -eq 'user' } |
        Select-Object Group, ParentGroup, Member, MemberType, Depth, Path, DistinguishedName
}

function Get-ADScoutAsRepRoastCandidate {
<#
.SYNOPSIS
Alias for Find-ADScoutASREPAccount.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Find-ADScoutASREPAccount -Server $Server -Credential $Credential -SearchBase $SearchBase
}

function Get-ADScoutMachineAccountQuota {
<#
.SYNOPSIS
Returns the ms-DS-MachineAccountQuota value for the domain.
.DESCRIPTION
A non-zero value means any authenticated user can add that many computer accounts
to the domain -- a prerequisite for RBCD and shadow credential attacks.
.EXAMPLE
Get-ADScoutMachineAccountQuota
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $entry = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $maq   = Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'ms-DS-MachineAccountQuota' | Select-Object -First 1
    $maqInt = if ($maq) { [int]$maq } else { 0 }
    [PSCustomObject]@{
        MachineAccountQuota = $maqInt
        AbuseRisk           = if ($maqInt -gt 0) {
                                  "Non-zero ($maqInt) -- any authenticated user can add computer accounts (RBCD/ShadowCred prerequisite)"
                              } else {
                                  'Zero -- only privileged users can add computer accounts'
                              }
        DistinguishedName   = $ctx.SearchBase
    }
}

function Find-ADScoutShadowCredential {
<#
.SYNOPSIS
Finds accounts with msDS-KeyCredentialLink set (shadow credentials indicator).
.DESCRIPTION
msDS-KeyCredentialLink is used by Windows Hello for Business but can also be abused
(shadow credentials attack) to obtain a TGT without knowing the account password.
Any unexpected entry here should be reviewed.
.EXAMPLE
Find-ADScoutShadowCredential
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher `
         -Filter '(msDS-KeyCredentialLink=*)' `
         -Properties @('samaccountname','name','objectclass','distinguishedname','msds-keycredentiallink') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $classes = Get-ADScoutPropertyValues $r 'objectclass'
        [PSCustomObject]@{
            SamAccountName     = Get-ADScoutProperty $r 'samaccountname'
            Name               = Get-ADScoutProperty $r 'name'
            ObjectClass        = Get-ADScoutObjectClassName -ObjectClassValues $classes
            KeyCredentialCount = $r.Properties['msds-keycredentiallink'].Count
            DistinguishedName  = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Find-ADScoutAdminSDHolderAce {
<#
.SYNOPSIS
Checks the AdminSDHolder object for non-standard ACEs.
.DESCRIPTION
The AdminSDHolder object (CN=AdminSDHolder,CN=System,...) is the ACL template for all
protected (adminCount=1) objects. SDProp propagates its ACL to all protected objects
every 60 minutes. A non-standard ACE here is a persistence and privilege escalation mechanism.
.EXAMPLE
Find-ADScoutAdminSDHolderAce
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx       = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $asdnDn    = "CN=AdminSDHolder,CN=System,$($ctx.DefaultNamingContext)"
    $excludePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                      'SYSTEM|CREATOR OWNER|Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544'
    try {
        Get-ADScoutObjectAcl -DistinguishedName $asdnDn -Server $Server -Credential $Credential -SearchBase $SearchBase |
            Where-Object {
                $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight' -and
                $_.AccessControlType     -eq 'Allow' -and
                -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
            } |
            ForEach-Object {
                [PSCustomObject]@{
                    IdentityReference = $_.IdentityReference
                    Rights            = $_.ActiveDirectoryRights
                    ObjectType        = $_.ObjectType
                    ObjectTypeGuid    = $_.ObjectTypeGuid
                    IsInherited       = $_.IsInherited
                    AbuseNote         = 'ACE on AdminSDHolder propagates to all protected objects via SDProp -- persistence/privesc path'
                    DistinguishedName = $asdnDn
                }
            }
    } catch {
        Write-Verbose "AdminSDHolder ACL read failed: $($_.Exception.Message)"
    }
}

function Find-ADScoutGPOWritePermission {
<#
.SYNOPSIS
Identifies principals that can modify GPOs linked to privileged or sensitive OUs.
.DESCRIPTION
Combines GPO ACL data with OU link data. A non-privileged principal with write access
to a GPO linked to a privileged OU (Domain Controllers, Tier 0, PAW, etc.) can execute
code as SYSTEM on all machines in scope. GUIDs resolved to human-readable names in output.
.EXAMPLE
Find-ADScoutGPOWritePermission
.EXAMPLE
Find-ADScoutGPOWritePermission | Where-Object AppliesToPrivOu
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $excludePattern     = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                          'SYSTEM|CREATOR OWNER|Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544|' +
                          'Group Policy Creator Owners'
    $privilegedOuPattern = 'Domain Controllers|Tier 0|Privileged|Admin|Executive|PAW|Secure'
    $ctx  = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $gpos = @(Get-ADScoutGPO -Server $Server -Credential $Credential)
    $ous  = @(Get-ADScoutOU  -Server $Server -Credential $Credential -SearchBase $SearchBase |
              Where-Object { $_.LinkedGPOs })
    # Build GPO guid -> linked OU names map
    $gpoOuMap = @{}
    foreach ($ou in $ous) {
        if (-not $ou.LinkedGPOs) { continue }
        $guids = [regex]::Matches($ou.LinkedGPOs, '\{([^}]+)\}') | ForEach-Object { "{$($_.Groups[1].Value)}" }
        foreach ($guid in $guids) {
            if (-not $gpoOuMap.ContainsKey($guid)) { $gpoOuMap[$guid] = @() }
            $gpoOuMap[$guid] += $ou.Name
        }
    }
    foreach ($gpo in $gpos) {
        $gpoGuid   = $gpo.Guid
        $linkedOus = if ($gpoOuMap.ContainsKey($gpoGuid)) { $gpoOuMap[$gpoGuid] } else { @() }
        $isPrivOu  = $linkedOus | Where-Object { $_ -match $privilegedOuPattern }
        try {
            $aces = @(Get-ADScoutObjectAcl -DistinguishedName $gpo.DistinguishedName `
                      -Server $Server -Credential $Credential -SearchBase $SearchBase |
                      Where-Object {
                          $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|CreateChild' -and
                          $_.AccessControlType     -eq 'Allow' -and
                          -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
                      })
            foreach ($ace in $aces) {
                [PSCustomObject]@{
                    GPOName           = $gpo.DisplayName
                    GPOGuid           = $gpoGuid
                    IdentityReference = $ace.IdentityReference
                    Rights            = $ace.ActiveDirectoryRights
                    ObjectType        = $ace.ObjectType
                    LinkedOUs         = ($linkedOus -join '; ')
                    AppliesToPrivOu   = ([bool]$isPrivOu)
                    AbuseNote         = if ($isPrivOu) {
                                            'GPO linked to privileged OU -- write access enables code exec on in-scope machines'
                                        } else { 'GPO write access -- review scope' }
                    DistinguishedName = $gpo.DistinguishedName
                }
            }
        } catch {}
    }
}

function Find-ADScoutTargetedKerberoastPath {
<#
.SYNOPSIS
Finds principals that can perform a targeted Kerberoast attack.
.DESCRIPTION
GenericAll or GenericWrite on a user account allows an attacker to set an arbitrary SPN
on that account, request a TGS, and crack it offline -- even if the account had no SPN.
This function identifies non-privileged principals with those rights on user objects.
Runs only under -IncludeAclSweep or -Preset Deep due to the per-user ACL cost.
.EXAMPLE
Find-ADScoutTargetedKerberoastPath
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $excludePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                      'SYSTEM|CREATOR OWNER|Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544'
    $users = Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
             Where-Object { $_.UacFlags -notmatch 'ACCOUNTDISABLE' }
    foreach ($user in $users) {
        try {
            Get-ADScoutObjectAcl -DistinguishedName $user.DistinguishedName `
                                 -Server $Server -Credential $Credential -SearchBase $SearchBase |
                Where-Object {
                    $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite' -and
                    $_.AccessControlType     -eq 'Allow' -and
                    -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
                } |
                ForEach-Object {
                    [PSCustomObject]@{
                        TargetUser        = $user.SamAccountName
                        AttackerPrincipal = $_.IdentityReference
                        Rights            = $_.ActiveDirectoryRights
                        ObjectType        = $_.ObjectType
                        IsInherited       = $_.IsInherited
                        AbuseNote         = 'Can set SPN on target and Kerberoast (targeted Kerberoast)'
                        DistinguishedName = $user.DistinguishedName
                    }
                }
        } catch {}
    }
}

function Get-ADScoutCrossForestEnum {
<#
.SYNOPSIS
Enumerates basic information from trusted domains/forests.
.DESCRIPTION
Follows trust relationships from Get-ADScoutDomainTrust and attempts to collect
domain context from each reachable trusted domain. Skips outbound-only trusts.
Collection depth limited to direct trusts only.
.EXAMPLE
Get-ADScoutCrossForestEnum
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $trusts = @(Get-ADScoutDomainTrust -Server $Server -Credential $Credential -SearchBase $SearchBase)
    if ($trusts.Count -eq 0) { Write-Verbose 'No domain trusts found.'; return }
    foreach ($trust in $trusts) {
        $trustName = $trust.Name
        if ([string]::IsNullOrWhiteSpace($trustName)) { continue }
        if ($trust.TrustDirection -eq 'Outbound') {
            [PSCustomObject]@{
                TrustedDomain       = $trustName; TrustDirection=$trust.TrustDirection
                IsForestTrust       = $trust.IsForestTrust; SIDFilteringEnabled=$trust.SIDFilteringEnabled
                Status              = 'Skipped -- outbound-only trust'
                SearchBase=$null; DomainControllers=$null; UserCount=$null; ComputerCount=$null; Error=$null
            }
            continue
        }
        try {
            $ctx       = Get-ADScoutDomainContext -Server $trustName -Credential $Credential -SearchBase $null
            $dcCount   = @(Get-ADScoutDomainController -Server $trustName -Credential $Credential -SearchBase $ctx.SearchBase).Count
            $userCount = 0; $compCount = 0
            try { $us = New-ADScoutSearcher -Filter '(&(objectCategory=person)(objectClass=user))' -Properties @('samaccountname') -Server $trustName -Credential $Credential -SearchBase $ctx.SearchBase; $userCount = $us.FindAll().Count } catch {}
            try { $cs = New-ADScoutSearcher -Filter '(objectCategory=computer)' -Properties @('name') -Server $trustName -Credential $Credential -SearchBase $ctx.SearchBase; $compCount = $cs.FindAll().Count } catch {}
            [PSCustomObject]@{
                TrustedDomain       = $trustName; TrustDirection=$trust.TrustDirection
                IsForestTrust       = $trust.IsForestTrust; SIDFilteringEnabled=$trust.SIDFilteringEnabled
                Status              = 'Reachable'; SearchBase=$ctx.SearchBase
                DomainControllers   = $dcCount; UserCount=$userCount; ComputerCount=$compCount; Error=$null
            }
        } catch {
            [PSCustomObject]@{
                TrustedDomain       = $trustName; TrustDirection=$trust.TrustDirection
                IsForestTrust       = $trust.IsForestTrust; SIDFilteringEnabled=$trust.SIDFilteringEnabled
                Status              = 'Unreachable'; SearchBase=$null
                DomainControllers   = $null; UserCount=$null; ComputerCount=$null; Error=$_.Exception.Message
            }
        }
    }
}

# =============================================================================
# FINDINGS ENGINE
# =============================================================================

function New-ADScoutFinding {
<#
.SYNOPSIS
Creates a normalized ADScout finding object.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Position=1)][string]$Category,
        [Parameter(Position=2)][string]$Title,
        [Parameter(Position=3)][string]$Target,
        [Parameter(Position=4)][string]$Evidence,
        [Parameter(Position=5)][string]$WhyItMatters,
        [Parameter(Position=6)][string]$RecommendedReview,
        [Parameter(Position=7)][string]$SourceCommand,
        [Parameter(Position=8)][string]$DistinguishedName,
        [Parameter(Position=9)][string]$ManualVerify,
        [string]$Identity
    )
    if (-not $Identity) { $Identity = $Target }
    [PSCustomObject][ordered]@{
        Severity          = $Severity
        Category          = $Category
        Title             = $Title
        Target            = $Target
        Identity          = $Identity
        Evidence          = $Evidence
        WhyItMatters      = $WhyItMatters
        RecommendedReview = $RecommendedReview
        ManualVerify      = $ManualVerify
        SourceCommand     = $SourceCommand
        DistinguishedName = $DistinguishedName
        Timestamp         = Get-Date
    }
}

function Get-ADScoutFinding {
<#
.SYNOPSIS
Returns normalized findings sorted by operational priority.
.DESCRIPTION
Accepts either a RunData object (preferred -- no re-collection) or legacy
connection parameters for backward compatibility.

Pass RunData from Invoke-ADScoutCollection for zero-LDAP analysis:
  Get-ADScoutFinding -RunData $data

Or use legacy mode (re-collects from LDAP):
  Get-ADScoutFinding -SkipAclSweep
  Get-ADScoutFinding -IncludeAclSweep
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Standard
Get-ADScoutFinding -RunData $data | Get-ADScoutSummary
.EXAMPLE
Get-ADScoutFinding -RunData $data | Where-Object Severity -eq 'Critical'
.EXAMPLE
Get-ADScoutFinding -SkipAclSweep
#>
    [CmdletBinding(DefaultParameterSetName='RunData')]
    param(
        [Parameter(ParameterSetName='RunData', ValueFromPipeline)]
        [PSCustomObject]$RunData,
        [Parameter(ParameterSetName='Legacy')][string]$Server,
        [Parameter(ParameterSetName='Legacy')][PSCredential]$Credential,
        [Parameter(ParameterSetName='Legacy')][string]$SearchBase,
        [switch]$SkipAclSweep,
        [switch]$IncludeAclSweep
    )
    begin { $pipeRunData = $null }
    process { if ($RunData) { $pipeRunData = $RunData } }
    end {
    $rd = Resolve-ADScoutRunData -RunData $pipeRunData

    # Legacy mode -- re-collect if session has no RunData and connection params provided
    if (-not $rd -and ($Server -or $SearchBase -or $Credential)) {
        $rd = Invoke-ADScoutCollection -Server $Server -Credential $Credential -SearchBase $SearchBase `
              -Preset (if ($IncludeAclSweep) { 'Deep' } else { 'Standard' }) `
              -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep
    }

    $runAcl = $rd.Meta.AclSweep -and (-not $SkipAclSweep.IsPresent)
    $f      = [System.Collections.ArrayList]@()

    # Credential/flag content in user-readable fields
    foreach ($x in @($rd.PasswordInDescription)) {
        [void]$f.Add((New-ADScoutFinding 'Critical' 'Credential Exposure' 'Sensitive content in user-readable AD field' `
            $x.SamAccountName "Field=$($x.Field); Value=$($x.Value)" `
            "The '$($x.Field)' field is readable by all authenticated users. Credentials or flags stored here are trivially accessible." `
            "Remove the sensitive content from the '$($x.Field)' field and rotate any credentials found." `
            'Find-ADScoutPasswordInDescription' $x.DistinguishedName `
            "Find-ADScoutPasswordInDescription | Where-Object SamAccountName -eq '$($x.SamAccountName)'"))
    }

    # AS-REP roast
    foreach ($x in @($rd.ASREPAccounts)) {
        $sam = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding 'Critical' 'Authentication' 'AS-REP roast candidate' `
            $sam $x.UacFlags `
            'Kerberos preauthentication is disabled. An unauthenticated attacker can request an AS-REP and crack it offline.' `
            'Enable Kerberos preauthentication unless there is a documented technical requirement.' `
            'Find-ADScoutASREPAccount' $x.DistinguishedName `
            "Get-ADScoutUser | Where-Object SamAccountName -eq '$sam' | Select-Object SamAccountName,UacFlags,AdminCount,MemberOf"))
    }

    # Machine account quota
    foreach ($x in @($rd.MachineAccountQuota) | Where-Object { $_.MachineAccountQuota -gt 0 }) {
        [void]$f.Add((New-ADScoutFinding 'High' 'Domain Configuration' 'Machine account quota is non-zero' `
            "ms-DS-MachineAccountQuota=$($x.MachineAccountQuota)" $x.AbuseRisk `
            'Any authenticated domain user can join machines to the domain. This is a prerequisite for RBCD and shadow credential attacks.' `
            'Set ms-DS-MachineAccountQuota to 0. Use delegated OU permissions for legitimate computer joins.' `
            'Get-ADScoutMachineAccountQuota' $x.DistinguishedName `
            'Get-ADScoutMachineAccountQuota'))
    }

    # Shadow credentials
    foreach ($x in @($rd.ShadowCredentials)) {
        $sev = if ($x.ObjectClass -eq 'computer' -and $x.KeyCredentialCount -eq 1) { 'Medium' } else { 'High' }
        $sam = $x.SamAccountName
        [void]$f.Add((New-ADScoutFinding $sev 'Shadow Credentials' 'msDS-KeyCredentialLink present' `
            $sam "ObjectClass=$($x.ObjectClass); KeyCount=$($x.KeyCredentialCount)" `
            'msDS-KeyCredentialLink enables certificate-based auth. Attacker-controlled entries allow TGT retrieval without the account password.' `
            'Review each KeyCredentialLink entry. Legitimate entries exist for WHFB-enrolled devices. Unexpected entries indicate shadow credential abuse.' `
            'Find-ADScoutShadowCredential' $x.DistinguishedName `
            "Find-ADScoutShadowCredential | Where-Object SamAccountName -eq '$sam'"))
    }

    # Kerberoast (SPN accounts)
    foreach ($x in @($rd.SPNAccounts)) {
        $sev = if ((Get-ADScoutSafeProperty $x 'AdminCount') -eq '1') { 'High' } else { 'Medium' }
        $sam = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding $sev 'Kerberos' 'SPN-bearing user account' `
            $sam $x.ServicePrincipalName `
            'Any authenticated user can request a TGS for this SPN. The ticket is encrypted with the account password and can be cracked offline.' `
            'Use Group Managed Service Accounts (gMSA). Enforce long random passwords on legacy service accounts.' `
            'Find-ADScoutSPNAccount' $x.DistinguishedName `
            "Find-ADScoutSPNAccount | Where-Object SamAccountName -eq '$sam' | Select-Object SamAccountName,ServicePrincipalName,AdminCount"))
    }

    # Unconstrained delegation
    foreach ($x in @($rd.Delegation) | Where-Object { (Get-ADScoutSafeProperty $_ 'Type') -ne 'KCD' -and (Get-ADScoutSafeProperty $_ 'Type') -ne 'RBCD' }) {
        $name = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding 'Critical' 'Delegation' 'Unconstrained delegation on non-DC object' `
            $name (Get-ADScoutSafeProperty $x 'UacFlags') `
            'Any service ticket presented to this host caches the sender TGT in memory. Compromise of this host enables impersonation of any user who connects.' `
            'Replace unconstrained delegation with constrained or resource-based constrained delegation.' `
            'Find-ADScoutUnconstrainedDelegation' $x.DistinguishedName `
            "Find-ADScoutUnconstrainedDelegation | Where-Object { `$_.Name -eq '$name' -or `$_.SamAccountName -eq '$name' }"))
    }

    # Constrained delegation
    foreach ($x in @($rd.Delegation) | Where-Object { (Get-ADScoutSafeProperty $_ 'Type') -in @('KCD','RBCD') }) {
        $sev  = if ($x.Type -eq 'RBCD') { 'High' } else { 'Medium' }
        $name = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding $sev 'Delegation' "$($x.Type) delegation configured" `
            $name $x.DelegatesTo `
            'Delegation configuration enables impersonation of users to target services. RBCD is particularly flexible and abusable.' `
            'Validate target services and principals. Confirm delegation is scoped to the minimum necessary services.' `
            'Find-ADScoutConstrainedDelegation' $x.DistinguishedName `
            "Find-ADScoutConstrainedDelegation | Where-Object { `$_.SamAccountName -eq '$name' }"))
    }

    # DCSync rights
    foreach ($x in @($rd.DCSyncRights)) {
        $iref = $x.IdentityReference
        [void]$f.Add((New-ADScoutFinding $x.Severity 'Replication Rights' 'DCSync-related replication right' `
            $iref $x.RightName `
            'Directory replication rights on the domain root allow extraction of all credential material via DCSync.' `
            'Review whether this principal requires replication rights. Expected: Domain Admins, Domain Controllers, Enterprise Admins.' `
            'Find-ADScoutDCSyncRight' $x.DistinguishedName `
            "Find-ADScoutDCSyncRight | Where-Object { `$_.IdentityReference -eq '$iref' }"))
    }

    # Password policy
    foreach ($x in @($rd.PasswordPolicies) | Where-Object {
        (Get-ADScoutSafeProperty $_ 'LockoutDisabled') -eq $true -or
        ((Get-ADScoutSafeProperty $_ 'MinPwdLength') -ne $null -and [int](Get-ADScoutSafeProperty $_ 'MinPwdLength') -lt 12)
    }) {
        [void]$f.Add((New-ADScoutFinding 'High' 'Password Policy' 'Password policy review item' `
            $x.Name "MinPwdLength=$($x.MinPwdLength); LockoutThreshold=$($x.LockoutThreshold)" `
            'Weak password or lockout policy enables password spraying and brute force. No lockout = unlimited attempts.' `
            'Set minimum password length >= 12. Configure lockout threshold of 5-10 attempts.' `
            'Get-ADScoutPasswordPolicy' $x.DistinguishedName `
            'Get-ADScoutPasswordPolicy | Format-List'))
    }

    # Domain trusts
    foreach ($x in @($rd.DomainTrusts)) {
        $sev = if (-not $x.SIDFilteringEnabled -and $x.TrustDirection -eq 'Bidirectional') { 'High' } else { 'Info' }
        [void]$f.Add((New-ADScoutFinding $sev 'Trusts' 'Domain trust present' `
            $x.Name "Direction=$($x.TrustDirection); Type=$($x.TrustType); SIDFiltering=$($x.SIDFilteringEnabled)" `
            'Trusts extend the AD security boundary. Bidirectional trusts without SID filtering enable SID history abuse across domains.' `
            'Review trust direction, transitivity, and SID filtering. Disable SID history if not required.' `
            'Get-ADScoutDomainTrust' $x.DistinguishedName `
            "Get-ADScoutDomainTrust | Where-Object Name -eq '$($x.Name)' | Format-List"))
    }

    # Domain controllers (informational)
    foreach ($x in @($rd.DomainControllers)) {
        $name = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding 'Info' 'Domain Controllers' 'Domain controller discovered' `
            $name $x.OperatingSystem `
            'Domain controllers are Tier 0 assets.' `
            'Use for scoping and attack path analysis.' `
            'Get-ADScoutDomainController' $x.DistinguishedName `
            "Get-ADScoutDomainController | Where-Object { `$_.Name -eq '$name' } | Format-List"))
    }

    # adminCount orphans
    foreach ($x in @($rd.AdminSDHolderObjects)) {
        $target = if ($x.SamAccountName) { $x.SamAccountName } else { $x.Name }
        [void]$f.Add((New-ADScoutFinding 'Medium' 'Privilege Hygiene' 'adminCount=1 object' `
            $target $x.ObjectClass `
            'adminCount=1 indicates SDProp has applied the AdminSDHolder ACL. ACL inheritance is broken on this object.' `
            'Review whether object is still privileged. Re-enable ACL inheritance if no longer protected.' `
            'Find-ADScoutAdminSDHolderOrphan' $x.DistinguishedName `
            "Find-ADScoutAdminSDHolderOrphan | Where-Object { `$_.SamAccountName -eq '$target' -or `$_.Name -eq '$target' }"))
    }

    # Weak UAC flags
    foreach ($x in @($rd.WeakUacFlags)) {
        $sev  = if ($x.UacFlags -match 'ENCRYPTED_TEXT_PWD_ALLOWED|PASSWD_NOTREQD|USE_DES_KEY_ONLY') { 'High' } else { 'Medium' }
        $name = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding $sev 'Account Flags' 'Weak/review-worthy UAC flag' `
            $name $x.UacFlags `
            'These flags weaken authentication controls: PASSWD_NOTREQD allows empty passwords, USE_DES_KEY_ONLY enables weak encryption.' `
            'Remove flags unless there is a documented technical requirement.' `
            'Find-ADScoutWeakUacFlag' $x.DistinguishedName `
            "Get-ADScoutUser | Where-Object SamAccountName -eq '$name' | Select-Object SamAccountName,UacFlags"))
    }

    # LAPS coverage gaps
    foreach ($x in @($rd.LapsStatus) | Where-Object { -not $_.HasLegacyLaps -and -not $_.HasWindowsLaps }) {
        $name = Get-ADScoutObjectDisplayName $x
        [void]$f.Add((New-ADScoutFinding 'Medium' 'Endpoint Hygiene' 'No visible LAPS metadata' `
            $name $x.DnsHostName `
            'Systems without LAPS may share local administrator passwords, enabling lateral movement via pass-the-hash.' `
            'Deploy LAPS or document the alternative local admin password management control.' `
            'Get-ADScoutLapsStatus' $x.DistinguishedName `
            "Get-ADScoutLapsStatus | Where-Object { `$_.Name -eq '$name' }"))
    }

    # Stale computer accounts
    foreach ($x in @($rd.StaleComputers)) {
        $name     = Get-ADScoutObjectDisplayName $x
        $evidence = if ($x.LastLogonTimestamp) { "LastLogonTimestamp=$($x.LastLogonTimestamp)" } else { 'LastLogonTimestamp absent' }
        [void]$f.Add((New-ADScoutFinding 'Low' 'Endpoint Hygiene' 'Stale computer account (>90 days)' `
            $name $evidence `
            'Stale computer accounts may represent decommissioned systems still enabled in AD.' `
            'Confirm whether the account is still in use. Disable or remove if not.' `
            'Find-ADScoutOldComputer' $x.DistinguishedName `
            "Find-ADScoutOldComputer -Days 90 | Where-Object { `$_.Name -eq '$name' }"))
    }

    # ACL sweep findings (from pre-collected data)
    if ($runAcl) {
        foreach ($x in @($rd.AclAttackPaths)) {
            $iref = $x.IdentityReference
            $tgt  = $x.TargetObject
            [void]$f.Add((New-ADScoutFinding 'Critical' 'ACL Attack Path' "Abusable ACE on $($x.TargetType): $tgt" `
                $iref "$($x.Rights) [$($x.ObjectType)]" `
                "A non-privileged principal has $($x.Rights) on a high-value $($x.TargetType) object. Direct privilege escalation path." `
                'Remove the ACE. GenericAll = full control, WriteDacl = grant self any right, User-Force-Change-Password = reset without knowing current password.' `
                'Find-ADScoutAclAttackPath' $x.DistinguishedName `
                "Get-ADScoutObjectAcl -Identity '$tgt' | Where-Object { `$_.IdentityReference -match '$iref' } | Format-List"))
        }
        foreach ($x in @($rd.AdminSDHolderAces)) {
            $iref = $x.IdentityReference
            [void]$f.Add((New-ADScoutFinding 'Critical' 'Persistence' 'Non-standard ACE on AdminSDHolder' `
                $iref "$($x.Rights) [$($x.ObjectType)]" `
                'AdminSDHolder ACEs propagate to all protected objects every 60 minutes via SDProp. Persistence and privilege escalation mechanism.' `
                'Remove the non-standard ACE from CN=AdminSDHolder,CN=System,... immediately.' `
                'Find-ADScoutAdminSDHolderAce' $x.DistinguishedName `
                "Find-ADScoutAdminSDHolderAce | Where-Object { `$_.IdentityReference -match '$iref' }"))
        }
        foreach ($x in @($rd.GPOWritePermissions)) {
            $sev  = if ($x.AppliesToPrivOu) { 'Critical' } else { 'High' }
            $iref = $x.IdentityReference
            $gpo  = $x.GPOName
            [void]$f.Add((New-ADScoutFinding $sev 'GPO Abuse' 'GPO write permission' `
                $iref "GPO: $gpo; OUs: $($x.LinkedOUs); Rights: $($x.Rights)" `
                $x.AbuseNote `
                'Review whether this principal requires GPO write access. Prefer read-only delegation.' `
                'Find-ADScoutGPOWritePermission' $x.DistinguishedName `
                "Find-ADScoutGPOWritePermission | Where-Object { `$_.GPOName -eq '$gpo' -and `$_.IdentityReference -match '$iref' }"))
        }
        foreach ($x in @($rd.TargetedKerberoastPaths)) {
            $attk = $x.AttackerPrincipal
            $tgt  = $x.TargetUser
            [void]$f.Add((New-ADScoutFinding 'High' 'Kerberos' 'Targeted Kerberoast path' `
                $attk "Can set SPN on $tgt via $($x.Rights)" `
                'GenericAll/GenericWrite on a user allows setting an SPN and Kerberoasting the TGS, even if the account had no SPN.' `
                'Remove the write access or restrict SPN writes via Validated-SPN.' `
                'Find-ADScoutTargetedKerberoastPath' $x.DistinguishedName `
                "Get-ADScoutObjectAcl -Identity '$tgt' | Where-Object { `$_.IdentityReference -match '$attk' } | Format-List"))
        }
    }

    $rank  = @{Critical=0; High=1; Medium=2; Low=3; Info=4}
    $items = @($f | Where-Object { $null -ne $_ } | Sort-Object @{Expression={$rank[$_.Severity]}}, Category, Title, Target)
    $script:ADScoutLastFindings = $items
    return $items
    } # end end{}
}

# =============================================================================
# OUTPUT / REPORTING
# =============================================================================

function New-ADScoutHtmlReport {
<#
.SYNOPSIS
Creates a lightweight offline HTML report for an ADScout run.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$RunData,
        [Parameter(Mandatory)][string]$OutputPath
    )
    function ConvertTo-ADScoutHtmlTable {
        param($Rows, [string]$Title)
        $items = @($Rows)
        if ($items.Count -eq 0) { return "<h2>$Title</h2><p>No rows.</p>" }
        return ($items | ConvertTo-Html -Fragment -PreContent "<h2>$Title</h2>") -join [Environment]::NewLine
    }
    $findings  = @($RunData.Findings)
    $critical  = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high      = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
    $generated = [System.Net.WebUtility]::HtmlEncode((Get-Date).ToString())
    $html = @"
<!doctype html><html>
<head><meta charset="utf-8"/><title>ADScoutPS Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1f2933}
h1{margin-bottom:0}.meta{color:#5b6773;margin-top:4px}
.summary{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}
.card{border:1px solid #d9e2ec;border-radius:8px;padding:12px 16px;min-width:140px;background:#f8fafc}
table{border-collapse:collapse;width:100%;margin-bottom:28px;font-size:13px}
th,td{border:1px solid #d9e2ec;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#eef2f7}
</style></head>
<body>
<h1>ADScoutPS Report</h1>
<div class="meta">Generated: $generated &nbsp;|&nbsp; Version: $script:ADScoutVersion</div>
<div class="summary">
  <div class="card"><strong>Findings</strong><br/>$($findings.Count)</div>
  <div class="card"><strong>Critical</strong><br/>$critical</div>
  <div class="card"><strong>High</strong><br/>$high</div>
  <div class="card"><strong>Users</strong><br/>$(@($RunData.Users).Count)</div>
  <div class="card"><strong>Computers</strong><br/>$(@($RunData.Computers).Count)</div>
</div>
$(ConvertTo-ADScoutHtmlTable -Rows ($findings | Sort-Object Severity,Category,Title) -Title 'Findings')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.PrivilegedGroupMembers -Title 'Privileged Group Members')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.Delegation            -Title 'Delegation Review')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.PasswordPolicies      -Title 'Password Policy')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.DomainTrusts          -Title 'Domain Trusts')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.DomainControllers     -Title 'Domain Controllers')
</body></html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    return $OutputPath
}

function Show-ADScoutFindingsGui {
<#
.SYNOPSIS
Shows selected ADScout views in Out-GridView when available, otherwise console table.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Findings','PrivilegedGroups','Delegation','Users','Computers','All')]
        [string]$View = 'Findings',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [switch]$IncludeAclSweep, [switch]$SkipAclSweep,
        [object[]]$Findings
    )
    $grid = [bool](Get-Command Out-GridView -ErrorAction SilentlyContinue)
    switch ($View) {
        'PrivilegedGroups' { $data = @(Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Privileged Group Members' }
        'Delegation'       { $data = @(Find-ADScoutConstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) + @(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Delegation Review' }
        'Users'            { $data = @(Get-ADScoutUser     -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Users' }
        'Computers'        { $data = @(Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Computers' }
        default            { $data = if ($Findings) { @($Findings) } else { @(Get-ADScoutFinding -Server $Server -Credential $Credential -SearchBase $SearchBase -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep) }; $title = 'ADScoutPS - Findings Dashboard' }
    }
    if ($grid) { $data | Out-GridView -Title $title }
    else        { Write-Warning 'Out-GridView unavailable; falling back to console.'; $data | Format-Table -AutoSize }
    if ($View -eq 'All' -and $grid) {
        Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase | Out-GridView -Title 'ADScoutPS - Privileged Groups'
        Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase | Out-GridView -Title 'ADScoutPS - Users'
    }
}

# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

# =============================================================================
# COLLECTION LAYER
# =============================================================================

function Build-ADScoutIndexes {
<#
.SYNOPSIS
Builds fast in-memory lookup indexes from collected RunData for path traversal.
.DESCRIPTION
Called internally by Invoke-ADScoutCollection. Builds:
  GroupMembershipIndex -- groupDN -> array of member DNs (for "who is in this group")
  UserGroupIndex       -- objectDN -> array of group DNs  (for "what groups is this in")
  TierZeroObjects      -- set of DNs/names considered Tier 0
  ObjectByDN           -- DN -> object reference for fast lookup
  ObjectBySam          -- sAMAccountName -> object reference
#>
    param([PSCustomObject]$RunData)

    # -- ObjectByDN and ObjectBySam --
    $byDn  = @{}
    $bySam = @{}
    foreach ($obj in (@($RunData.Users) + @($RunData.Groups) + @($RunData.Computers))) {
        $dn = Get-ADScoutSafeProperty $obj 'DistinguishedName'
        if ($dn) { $byDn[$dn] = $obj }
        foreach ($keyName in @('SamAccountName','Name','DnsHostName')) {
            $key = Get-ADScoutSafeProperty $obj $keyName
            if ($key -and -not $bySam.ContainsKey($key)) { $bySam[$key] = $obj }
        }
    }

    # -- GroupMembershipIndex: groupDN -> [memberDNs] --
    $groupIdx = @{}
    foreach ($entry in @($RunData.PrivilegedGroupMembers)) {
        $memberDn = Get-ADScoutSafeProperty $entry 'DistinguishedName'
        $rootGroup = Get-ADScoutSafeProperty $entry 'Group'
        if (-not $memberDn -or -not $rootGroup) { continue }
        # Find group DN via bySam
        $groupObj = if ($bySam.ContainsKey($rootGroup)) { $bySam[$rootGroup] } else { $null }
        $groupDn  = if ($groupObj) { Get-ADScoutSafeProperty $groupObj 'DistinguishedName' } else { $rootGroup }
        if (-not $groupIdx.ContainsKey($groupDn)) { $groupIdx[$groupDn] = [System.Collections.ArrayList]@() }
        [void]$groupIdx[$groupDn].Add($memberDn)
    }
    # Also index from raw Groups collection
    foreach ($grp in @($RunData.Groups)) {
        $dn      = Get-ADScoutSafeProperty $grp 'DistinguishedName'
        $members = Get-ADScoutSafeProperty $grp 'Member'
        if (-not $dn) { continue }
        if (-not $groupIdx.ContainsKey($dn)) { $groupIdx[$dn] = [System.Collections.ArrayList]@() }
        if ($members) {
            foreach ($m in ($members -split ';')) {
                $m = $m.Trim()
                if ($m -and -not $groupIdx[$dn].Contains($m)) { [void]$groupIdx[$dn].Add($m) }
            }
        }
    }

    # -- UserGroupIndex: objectDN -> [groupDNs] --
    $userGroupIdx = @{}
    foreach ($user in @($RunData.Users)) {
        $dn       = Get-ADScoutSafeProperty $user 'DistinguishedName'
        $memberOf = Get-ADScoutSafeProperty $user 'MemberOf'
        if (-not $dn) { continue }
        $userGroupIdx[$dn] = [System.Collections.ArrayList]@()
        if ($memberOf) {
            foreach ($g in ($memberOf -split ';')) {
                $g = $g.Trim()
                if ($g) { [void]$userGroupIdx[$dn].Add($g) }
            }
        }
    }

    # -- TierZeroObjects: canonical Tier 0 set --
    $t0Names = @(
        'Domain Admins','Enterprise Admins','Schema Admins','Administrators',
        'Domain Controllers','Read-only Domain Controllers','Group Policy Creator Owners',
        'DnsAdmins','Account Operators','Backup Operators','Server Operators','Print Operators'
    )
    $t0Dns = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    # Add by name match
    foreach ($grp in @($RunData.Groups)) {
        $name = Get-ADScoutSafeProperty $grp 'Name'
        $dn   = Get-ADScoutSafeProperty $grp 'DistinguishedName'
        if ($name -and $dn -and $t0Names -contains $name) { [void]$t0Dns.Add($dn) }
    }
    # Add DCs
    foreach ($dc in @($RunData.DomainControllers)) {
        $dn = Get-ADScoutSafeProperty $dc 'DistinguishedName'
        if ($dn) { [void]$t0Dns.Add($dn) }
    }
    # Add DA members
    foreach ($entry in @($RunData.PrivilegedGroupMembers) | Where-Object { (Get-ADScoutSafeProperty $_ 'Group') -eq 'Domain Admins' }) {
        $dn = Get-ADScoutSafeProperty $entry 'DistinguishedName'
        if ($dn) { [void]$t0Dns.Add($dn) }
    }
    # Add DCSync-capable non-standard principals to Tier 0
    foreach ($x in @($RunData.DCSyncRights) | Where-Object { $_.Severity -eq 'Critical' }) {
        $target = Get-ADScoutSafeProperty $x 'IdentityReference'
        if ($target) { [void]$t0Dns.Add($target) }
    }

    [PSCustomObject]@{
        GroupMembershipIndex = $groupIdx
        UserGroupIndex       = $userGroupIdx
        TierZeroObjects      = $t0Dns
        ObjectByDN           = $byDn
        ObjectBySam          = $bySam
    }
}

function Invoke-ADScoutCollection {
<#
.SYNOPSIS
Collects all AD data and returns a structured RunData object.
.DESCRIPTION
This is the collection layer. Returns a single RunData object containing all
collected data, pre-built indexes for path traversal, and metadata.
Pass the result to Get-ADScoutFinding, Get-ADScoutPathHint, New-ADScoutHtmlReport,
Show-ADScoutFindingsGui, Export-ADScoutRun, or Get-ADScoutSummary.

Collection is performed once. All analysis functions consume the RunData object
without re-querying LDAP.
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Standard
$data | Get-ADScoutFinding | Get-ADScoutSummary
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Deep
Get-ADScoutPathHint -RunData $data
New-ADScoutHtmlReport -RunData $data -OutputPath .\report.html
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Standard -Server dc01.corp.local -Credential $cred
Export-ADScoutRun -RunData $data -Path .\snapshot.json
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Quick','Standard','Deep')][string]$Preset = 'Standard',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [switch]$SkipAclSweep, [switch]$IncludeAclSweep,
        [switch]$LabMode
    )

    $runAcl = $IncludeAclSweep.IsPresent -or ($Preset -eq 'Deep')
    if ($SkipAclSweep) { $runAcl = $false }

    $connParams = @{ Server=$Server; Credential=$Credential; SearchBase=$SearchBase }

    Write-Host "[*] ADScoutPS v$script:ADScoutVersion -- collecting ($Preset)..." -ForegroundColor Cyan

    # -- Core objects (all presets) --
    Write-Host '[*] Core objects...' -ForegroundColor DarkGray
    $users     = @(Get-ADScoutUser             @connParams)
    $groups    = @(Get-ADScoutGroup            @connParams)
    $computers = @(Get-ADScoutComputer         @connParams)
    $dcs       = @(Get-ADScoutDomainController @connParams)
    $domInfo   = Get-ADScoutDomainInfo         @connParams

    # -- Extended (Standard+) --
    $gpos = @(); $ous = @(); $linkedGpos = @(); $trusts = @(); $crossForest = @()
    if ($Preset -ne 'Quick') {
        Write-Host '[*] GPOs, OUs, trusts...' -ForegroundColor DarkGray
        $gpos       = @(Get-ADScoutGPO         -Server $Server -Credential $Credential)
        $ous        = @(Get-ADScoutOU          @connParams)
        $linkedGpos = @(Get-ADScoutLinkedGPO   @connParams)
        $trusts     = @(Get-ADScoutDomainTrust @connParams)
    }

    # -- Security checks (all presets) --
    Write-Host '[*] Kerberos, delegation, shadow credentials...' -ForegroundColor DarkGray
    $pwPolicy   = @(Get-ADScoutPasswordPolicy       @connParams)
    $maq        = @(Get-ADScoutMachineAccountQuota  @connParams)
    $pwInDesc   = @(Find-ADScoutPasswordInDescription @connParams -LabMode:$LabMode)
    $spns       = @(Find-ADScoutSPNAccount          @connParams)
    $asrep      = @(Find-ADScoutASREPAccount        @connParams)
    $shadowCred = @(Find-ADScoutShadowCredential    @connParams)
    $dcsyncRights = @(Find-ADScoutDCSyncRight       @connParams)
    $delegation = @(
        @(Find-ADScoutUnconstrainedDelegation @connParams) +
        @(Find-ADScoutConstrainedDelegation   @connParams)
    )
    $adminSDOrphans = @(Find-ADScoutAdminSDHolderOrphan @connParams)
    $weakUac        = @(Find-ADScoutWeakUacFlag         @connParams)
    $laps           = @(Get-ADScoutLapsStatus           @connParams)
    $stale          = @(Find-ADScoutOldComputer -Days 90 @connParams)

    Write-Host '[*] Privileged group membership...' -ForegroundColor DarkGray
    $privMembers = @(Get-ADScoutGroupReport -PrivilegedOnly -Recursive @connParams)
    $privPaths   = @($privMembers | Where-Object { $_.MemberType -eq 'user' } |
                     Select-Object Group, ParentGroup, Member, MemberType, Depth, Path, DistinguishedName)

    # -- ACL sweep (opt-in) --
    $aclPaths = @(); $adminSDHolderAces = @(); $gpoWritePerms = @()
    $targetedKerb = @()
    if ($runAcl) {
        Write-Host '[*] ACL sweep (this may take a moment)...' -ForegroundColor Cyan
        $aclPaths         = @(Find-ADScoutAclAttackPath         @connParams)
        $adminSDHolderAces= @(Find-ADScoutAdminSDHolderAce      @connParams)
        $gpoWritePerms    = @(Find-ADScoutGPOWritePermission     @connParams)
        $targetedKerb     = @(Find-ADScoutTargetedKerberoastPath @connParams)
        $crossForest      = @(Get-ADScoutCrossForestEnum         @connParams)
    }

    # -- Assemble RunData --
    $runData = [PSCustomObject][ordered]@{
        # Metadata
        Meta = [PSCustomObject]@{
            Version     = $script:ADScoutVersion
            Preset      = $Preset
            AclSweep    = $runAcl
            LabMode     = $LabMode.IsPresent
            Timestamp   = Get-Date
            Server      = $Server
            SearchBase  = $SearchBase
            DomainInfo  = $domInfo
        }
        # Raw collections
        Users                = $users
        Groups               = $groups
        Computers            = $computers
        DomainControllers    = $dcs
        GPOs                 = $gpos
        OUs                  = $ous
        LinkedGPOs           = $linkedGpos
        DomainTrusts         = $trusts
        PasswordPolicies     = $pwPolicy
        MachineAccountQuota  = $maq
        PasswordInDescription= $pwInDesc
        SPNAccounts          = $spns
        ASREPAccounts        = $asrep
        ShadowCredentials    = $shadowCred
        DCSyncRights         = $dcsyncRights
        Delegation           = $delegation
        AdminSDHolderObjects = $adminSDOrphans
        PrivilegedGroupMembers = $privMembers
        PrivilegePaths       = $privPaths
        WeakUacFlags         = $weakUac
        LapsStatus           = $laps
        StaleComputers       = $stale
        AclAttackPaths       = $aclPaths
        AdminSDHolderAces    = $adminSDHolderAces
        GPOWritePermissions  = $gpoWritePerms
        TargetedKerberoastPaths = $targetedKerb
        CrossForest          = $crossForest
        # Analysis outputs -- populated after collection
        Indexes              = $null
        Findings             = @()
        PathHints            = @()
    }

    # -- Build indexes --
    Write-Host '[*] Building traversal indexes...' -ForegroundColor DarkGray
    $runData.Indexes = Build-ADScoutIndexes -RunData $runData

    # Store as the active session RunData -- analysis functions use this automatically
    $script:ADScoutLastRun = $runData

    Write-Host "[+] Collection complete -- $($users.Count) users, $($computers.Count) computers, $($dcs.Count) DCs" -ForegroundColor Green
    Write-Host "[+] RunData stored in session -- Get-QuickWins, Get-Findings, Get-PathHints work without -RunData" -ForegroundColor DarkGray
    return $runData
}

function Export-ADScoutRun {
<#
.SYNOPSIS
Exports a RunData object to a JSON snapshot for offline analysis.
.EXAMPLE
Export-ADScoutRun -RunData $data -Path .\snapshot.json
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$RunData,
        [Parameter(Mandatory)][string]$Path
    )
    # Exclude Indexes (not serializable cleanly) -- rebuilt on import
    $export = [ordered]@{}
    foreach ($prop in $RunData.PSObject.Properties) {
        if ($prop.Name -eq 'Indexes') { continue }
        $export[$prop.Name] = $prop.Value
    }
    $export | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "[+] Run exported to $Path" -ForegroundColor Green
}

function Import-ADScoutRun {
<#
.SYNOPSIS
Imports a RunData JSON snapshot for offline analysis.
.DESCRIPTION
Rebuilds traversal indexes automatically on import.
.EXAMPLE
$data = Import-ADScoutRun -Path .\snapshot.json
Get-ADScoutFinding -RunData $data | Get-ADScoutSummary
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $raw     = Get-Content $Path -Raw | ConvertFrom-Json
    $runData = [PSCustomObject]$raw
    # Rebuild indexes
    $runData | Add-Member -NotePropertyName 'Indexes' -NotePropertyValue $null -Force
    $runData.Indexes = Build-ADScoutIndexes -RunData $runData
    $script:ADScoutLastRun = $runData
    Write-Host "[+] Run imported from $Path ($(($runData.Meta).Timestamp))" -ForegroundColor Green
    Write-Host "[+] RunData stored in session -- Get-QuickWins, Get-Findings, Get-PathHints work without -RunData" -ForegroundColor DarkGray
    return $runData
}

# =============================================================================
# PATH CHAIN ENGINE
# =============================================================================

function Get-ADScoutPathHint {
<#
.SYNOPSIS
Discovers chained attack paths from collected RunData.
.DESCRIPTION
Walks relationships between collected objects to find multi-hop privilege
escalation paths without re-querying LDAP. Requires RunData from
Invoke-ADScoutCollection or Import-ADScoutRun.

Chain types detected:
  ACE->Kerberoast   -- principal has GenericAll/Write on user with or without SPN
                       (can set SPN and Kerberoast)
  ACE->DA           -- principal has abusable ACE on a user/group that is in DA
  ACE->T0           -- principal has abusable ACE on a Tier 0 object directly
  Group->DA         -- non-obvious nested group path to Domain Admins
  SPN->Privesc      -- Kerberoastable account is itself privileged (adminCount=1)
  ASREP->Privesc    -- AS-REP roastable account has group membership worth cracking for
  Write->ShadowCred -- principal with write on user can add shadow credential

Each chain includes the full hop sequence, terminal impact, and suggested next command.
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Deep
Get-ADScoutPathHint -RunData $data
.EXAMPLE
Get-ADScoutPathHint -RunData $data -From 'helpdesk'
.EXAMPLE
Get-ADScoutPathHint -RunData $data -To 'Domain Admins'
.EXAMPLE
Get-ADScoutPathHint -RunData $data | Sort-Object ChainSeverity | Format-List
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][PSCustomObject]$RunData,
        [string]$From,
        [string]$To
    )

    $RunData = Resolve-ADScoutRunData -RunData $RunData

    if (-not $RunData.Indexes) {
        Write-Warning 'RunData has no indexes -- rebuilding...'
        $RunData.Indexes = Build-ADScoutIndexes -RunData $RunData
    }

    # Auto-populate findings if empty
    if (-not $RunData.Findings -or $RunData.Findings.Count -eq 0) {
        Write-Host '[*] Findings not yet populated -- running Get-ADScoutFinding...' -ForegroundColor DarkGray
        $RunData.Findings = @(Get-ADScoutFinding -RunData $RunData)
    }

    $idx     = $RunData.Indexes
    $t0      = $idx.TierZeroObjects
    $byDn    = $idx.ObjectByDN
    $bySam   = $idx.ObjectBySam
    $chains  = [System.Collections.ArrayList]@()

    function Add-Chain {
        param($Severity, $Type, $Principal, $Hops, $TerminalImpact, $NextCommand)
        if ($From -and $Principal -notmatch [regex]::Escape($From)) { return }
        if ($To   -and $TerminalImpact -notmatch [regex]::Escape($To)) { return }
        [void]$chains.Add([PSCustomObject][ordered]@{
            ChainSeverity  = $Severity
            ChainType      = $Type
            Principal      = $Principal
            HopCount       = $Hops.Count
            Hops           = ($Hops -join ' --> ')
            TerminalImpact = $TerminalImpact
            NextCommand    = $NextCommand
        })
    }

    # Helper: is a DN or name Tier 0?
    function Test-IsTierZero {
        param([string]$Identity)
        if ($t0.Contains($Identity)) { return $true }
        foreach ($dn in $t0) { if ($dn -match [regex]::Escape($Identity)) { return $true } }
        return $false
    }

    # Helper: get group names a DN is member of
    function Get-GroupsForDn {
        param([string]$Dn)
        $result = @()
        if ($idx.UserGroupIndex.ContainsKey($Dn)) {
            $result = @($idx.UserGroupIndex[$Dn])
        }
        return $result
    }

    # Helper: is DN a DA member?
    function Test-IsDaMember {
        param([string]$Dn)
        $groups = Get-GroupsForDn -Dn $Dn
        foreach ($g in $groups) {
            if ($g -match 'CN=Domain Admins') { return $true }
        }
        # Check via PrivilegedGroupMembers
        foreach ($entry in @($RunData.PrivilegedGroupMembers)) {
            $entDn = Get-ADScoutSafeProperty $entry 'DistinguishedName'
            $entGrp = Get-ADScoutSafeProperty $entry 'Group'
            if ($entDn -eq $Dn -and $entGrp -eq 'Domain Admins') { return $true }
        }
        return $false
    }

    # -------------------------------------------------------------------------
    # Chain Type 1: ACE -> Kerberoast (targeted)
    # Principal has GenericAll/GenericWrite on a user -- can set SPN and Kerberoast
    # -------------------------------------------------------------------------
    foreach ($path in @($RunData.TargetedKerberoastPaths)) {
        $attacker = Get-ADScoutSafeProperty $path 'AttackerPrincipal'
        $target   = Get-ADScoutSafeProperty $path 'TargetUser'
        $rights   = Get-ADScoutSafeProperty $path 'Rights'
        if (-not $attacker -or -not $target) { continue }

        # Is the target already privileged?
        $targetObj    = if ($bySam.ContainsKey($target)) { $bySam[$target] } else { $null }
        $targetDn     = if ($targetObj) { Get-ADScoutSafeProperty $targetObj 'DistinguishedName' } else { $null }
        $targetIsPriv = $targetDn -and (Test-IsDaMember -Dn $targetDn)
        $targetIsT0   = $targetDn -and (Test-IsTierZero -Identity $targetDn)

        $sev     = if ($targetIsPriv -or $targetIsT0) { 'Critical' } else { 'High' }
        $impact  = if ($targetIsPriv) { "Kerberoast $target (DA member) -- crack hash = DA" }
                   elseif ($targetIsT0) { "Kerberoast $target (Tier 0) -- crack hash = Tier 0 access" }
                   else { "Kerberoast $target -- crack hash = access as $target" }

        Add-Chain $sev 'ACE->Kerberoast' $attacker `
            @("$attacker has $rights on $target", "Set SPN on $target", "Request TGS", "Crack offline") `
            $impact "Find-ADScoutTargetedKerberoastPath | Where-Object TargetUser -eq '$target'"
    }

    # -------------------------------------------------------------------------
    # Chain Type 2: ACE -> DA (indirect)
    # Principal has abusable ACE on a user who is a DA member
    # -------------------------------------------------------------------------
    foreach ($ace in @($RunData.AclAttackPaths)) {
        $attacker   = Get-ADScoutSafeProperty $ace 'IdentityReference'
        $targetObj2 = Get-ADScoutSafeProperty $ace 'TargetObject'
        $rights2    = Get-ADScoutSafeProperty $ace 'Rights'
        $tType      = Get-ADScoutSafeProperty $ace 'TargetType'
        if (-not $attacker -or -not $targetObj2) { continue }
        if ($tType -ne 'User') { continue }

        # Is target a DA?
        $tObj  = if ($bySam.ContainsKey($targetObj2)) { $bySam[$targetObj2] } else { $null }
        $tDn   = if ($tObj) { Get-ADScoutSafeProperty $tObj 'DistinguishedName' } else { $null }
        if (-not $tDn) { continue }
        if (Test-IsDaMember -Dn $tDn) {
            Add-Chain 'Critical' 'ACE->DA' $attacker `
                @("$attacker has $rights2 on $targetObj2", "$targetObj2 is a Domain Admin", "Abuse $rights2 = control DA account") `
                "Control Domain Admin account $targetObj2" `
                "Get-ADScoutObjectAcl -Identity '$targetObj2' | Where-Object { `$_.IdentityReference -match '$attacker' }"
        }
    }

    # -------------------------------------------------------------------------
    # Chain Type 3: ACE -> Tier 0 (direct)
    # Principal has abusable ACE directly on a Tier 0 group (not user -- covered above)
    # -------------------------------------------------------------------------
    foreach ($ace in @($RunData.AclAttackPaths)) {
        $attacker = Get-ADScoutSafeProperty $ace 'IdentityReference'
        $target3  = Get-ADScoutSafeProperty $ace 'TargetObject'
        $rights3  = Get-ADScoutSafeProperty $ace 'Rights'
        $tType3   = Get-ADScoutSafeProperty $ace 'TargetType'
        if (-not $attacker -or -not $target3) { continue }
        if ($tType3 -eq 'User') { continue }  # covered in Type 2

        $tObj3 = if ($bySam.ContainsKey($target3)) { $bySam[$target3] } else { $null }
        $tDn3  = if ($tObj3) { Get-ADScoutSafeProperty $tObj3 'DistinguishedName' } else { $null }
        if ($tDn3 -and (Test-IsTierZero -Identity $tDn3)) {
            Add-Chain 'Critical' 'ACE->Tier0' $attacker `
                @("$attacker has $rights3 on $target3 ($tType3)", "$target3 is Tier 0", "Abuse $rights3 = Tier 0 control") `
                "Direct Tier 0 control via $target3" `
                "Get-ADScoutObjectAcl -Identity '$target3'"
        }
    }

    # -------------------------------------------------------------------------
    # Chain Type 4: SPN account is privileged
    # Kerberoastable account has adminCount=1 or is a DA -- high-value crack target
    # -------------------------------------------------------------------------
    foreach ($spn in @($RunData.SPNAccounts)) {
        $sam       = Get-ADScoutSafeProperty $spn 'SamAccountName'
        $adminCnt  = Get-ADScoutSafeProperty $spn 'AdminCount'
        $dn        = if ($bySam.ContainsKey($sam)) { Get-ADScoutSafeProperty $bySam[$sam] 'DistinguishedName' } else { $null }
        $isPriv    = ($adminCnt -eq '1') -or ($dn -and (Test-IsDaMember -Dn $dn))
        if (-not $isPriv) { continue }
        $sev    = if ($dn -and (Test-IsDaMember -Dn $dn)) { 'Critical' } else { 'High' }
        $impact = if ($sev -eq 'Critical') { "Crack hash = Domain Admin ($sam)" } else { "Crack hash = privileged access ($sam, adminCount=1)" }
        Add-Chain $sev 'SPN->Privesc' "Any authenticated user" `
            @("$sam has SPN (Kerberoastable)", "Request TGS for $sam", "Crack hash") `
            $impact "Find-ADScoutSPNAccount | Where-Object SamAccountName -eq '$sam'"
    }

    # -------------------------------------------------------------------------
    # Chain Type 5: AS-REP account has group memberships worth noting
    # -------------------------------------------------------------------------
    foreach ($ar in @($RunData.ASREPAccounts)) {
        $sam  = Get-ADScoutSafeProperty $ar 'SamAccountName'
        $dn   = if ($bySam.ContainsKey($sam)) { Get-ADScoutSafeProperty $bySam[$sam] 'DistinguishedName' } else { $null }
        if (-not $dn) { continue }
        $isDA = Test-IsDaMember -Dn $dn
        $isT0 = Test-IsTierZero -Identity $dn
        if (-not $isDA -and -not $isT0) { continue }
        $sev    = if ($isDA) { 'Critical' } else { 'High' }
        $impact = if ($isDA) { "Crack AS-REP hash = Domain Admin ($sam)" } else { "Crack AS-REP hash = Tier 0 access ($sam)" }
        Add-Chain $sev 'ASREP->Privesc' "Unauthenticated" `
            @("$sam has preauth disabled (AS-REP roastable)", "Request AS-REP without credentials", "Crack hash") `
            $impact "Find-ADScoutASREPAccount | Where-Object SamAccountName -eq '$sam'"
    }

    # -------------------------------------------------------------------------
    # Chain Type 6: GPO write -> Tier 0 OU
    # Principal can modify GPO linked to DC/privileged OU
    # -------------------------------------------------------------------------
    foreach ($gpo in @($RunData.GPOWritePermissions) | Where-Object { (Get-ADScoutSafeProperty $_ 'AppliesToPrivOu') -eq $true }) {
        $principal = Get-ADScoutSafeProperty $gpo 'IdentityReference'
        $gpoName   = Get-ADScoutSafeProperty $gpo 'GPOName'
        $linkedOUs = Get-ADScoutSafeProperty $gpo 'LinkedOUs'
        $rights6   = Get-ADScoutSafeProperty $gpo 'Rights'
        if (-not $principal -or -not $gpoName) { continue }
        Add-Chain 'Critical' 'GPOWrite->Tier0' $principal `
            @("$principal has $rights6 on GPO '$gpoName'", "GPO is linked to privileged OU: $linkedOUs", "Modify GPO = code exec as SYSTEM on all in-scope machines") `
            "SYSTEM execution on Tier 0 machines via GPO '$gpoName'" `
            "Find-ADScoutGPOWritePermission | Where-Object { `$_.GPOName -eq '$gpoName' }"
    }

    # -------------------------------------------------------------------------
    # Chain Type 7: DCSync -> credential dump
    # Non-standard DCSync right -- always a terminal path
    # -------------------------------------------------------------------------
    foreach ($f in @($RunData.Findings) | Where-Object {
        (Get-ADScoutSafeProperty $_ 'Category') -eq 'Replication Rights' -and
        (Get-ADScoutSafeProperty $_ 'Severity') -eq 'Critical' }) {
        $principal = Get-ADScoutSafeProperty $f 'Target'
        $evidence  = Get-ADScoutSafeProperty $f 'Evidence'
        if (-not $principal) { continue }
        Add-Chain 'Critical' 'DCSync->CredDump' $principal `
            @("$principal holds $evidence", "Can replicate all credential material from DC") `
            "Full domain compromise via DCSync ($principal)" `
            "Find-ADScoutDCSyncRight | Where-Object Severity -eq 'Critical'"
    }

    $result = @($chains | Sort-Object @{Expression={
        switch ($_.ChainSeverity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} }
    }}, ChainType, Principal)

    $RunData.PathHints = $result
    return $result
}

# =============================================================================
# UPDATED INVOKE-ADSCOUT (now calls Invoke-ADScoutCollection)
# =============================================================================

function Invoke-ADScout {
<#
.SYNOPSIS
All-in-one operator command. Collects, analyzes, exports, and summarizes.
.DESCRIPTION
Calls Invoke-ADScoutCollection internally. For interactive/scripted use,
prefer calling Invoke-ADScoutCollection directly and passing RunData to
individual functions.

Quick    -- fast core collection, no GPO/OU/trust enumeration, no ACL sweep.
Standard -- adds GPOs, OUs, trusts, password policy, privileged group report.
Deep     -- full collection including ACL sweep and path hint engine.
.EXAMPLE
Invoke-ADScout -Preset Quick
.EXAMPLE
Invoke-ADScout -Preset Deep -Report
.EXAMPLE
$r = Invoke-ADScout -Preset Standard -NoExport
$r.RunData | Get-ADScoutPathHint
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Quick','Standard','Deep')][string]$Preset = 'Standard',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [string]$OutputPath = 'ADScout-Results',
        [ValidateSet('CSV','JSON','Both')][string]$OutputFormat = 'Both',
        [switch]$SkipAclSweep, [switch]$IncludeAclSweep,
        [switch]$LabMode,
        [switch]$Gui,
        [ValidateSet('Findings','PrivilegedGroups','Delegation','Users','Computers','All')]
        [string]$View = 'Findings',
        [switch]$Report, [switch]$NoExport
    )

    # -- Collect --
    $runData = Invoke-ADScoutCollection -Preset $Preset -Server $Server -Credential $Credential `
               -SearchBase $SearchBase -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep `
               -LabMode:$LabMode

    # -- Analyze --
    Write-Host '[*] Running findings engine...' -ForegroundColor DarkGray
    $findings = @(Get-ADScoutFinding -RunData $runData)
    $runData.Findings = $findings

    # -- Path hints (Deep or explicit ACL sweep) --
    if ($runData.Meta.AclSweep) {
        Write-Host '[*] Running path chain engine...' -ForegroundColor DarkGray
        $runData.PathHints = @(Get-ADScoutPathHint -RunData $runData)
    }

    # -- Export --
    $runPath = $null
    if (-not $NoExport) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $runPath   = Join-Path $OutputPath "Run-$timestamp"
        New-Item -ItemType Directory -Path $runPath -Force | Out-Null

        $keys = @('Users','Groups','Computers','DomainControllers','GPOs','OUs','LinkedGPOs',
                  'DomainTrusts','PasswordPolicies','MachineAccountQuota','PasswordInDescription',
                  'SPNAccounts','ASREPAccounts','ShadowCredentials','DCSyncRights','Delegation',
                  'AdminSDHolderObjects','PrivilegedGroupMembers','PrivilegePaths','WeakUacFlags',
                  'LapsStatus','StaleComputers','AclAttackPaths','AdminSDHolderAces',
                  'GPOWritePermissions','TargetedKerberoastPaths','CrossForest','Findings','PathHints')

        foreach ($k in $keys) {
            $val = $runData.$k
            if ($null -eq $val) { continue }
            $base = Join-Path $runPath $k
            if ($OutputFormat -in @('CSV','Both'))  { @($val) | Export-Csv "$base.csv" -NoTypeInformation }
            if ($OutputFormat -in @('JSON','Both')) { @($val) | ConvertTo-Json -Depth 8 | Out-File "$base.json" -Encoding UTF8 }
        }

        $summaryLines = @(
            '# ADScoutPS Summary', '',
            "Version   : $script:ADScoutVersion",
            "Preset    : $Preset",
            "ACL sweep : $($runData.Meta.AclSweep)",
            "LabMode   : $($runData.Meta.LabMode)",
            "Timestamp : $($runData.Meta.Timestamp)", '',
            '| Collection | Count |', '|---|---:|'
        ) + ($keys | ForEach-Object { "| $_ | $(@($runData.$_).Count) |" })
        $summaryLines | Out-File (Join-Path $runPath 'summary.md') -Encoding UTF8

        if ($Report) {
            New-ADScoutHtmlReport -RunData $runData -OutputPath (Join-Path $runPath 'report.html') | Out-Null
        }

        # Snapshot export
        Export-ADScoutRun -RunData $runData -Path (Join-Path $runPath 'snapshot.json')

        Write-Host "[+] Results written to $runPath" -ForegroundColor Green
    }

    # -- Summary --
    Write-Host ''
    Write-Host "[!] Critical : $(@($findings | Where-Object { $_.Severity -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "[!] High     : $(@($findings | Where-Object { $_.Severity -eq 'High'     }).Count)" -ForegroundColor Yellow
    Write-Host "[!] Medium   : $(@($findings | Where-Object { $_.Severity -eq 'Medium'   }).Count)" -ForegroundColor DarkYellow
    if ($runData.Meta.AclSweep -and $runData.PathHints.Count -gt 0) {
        Write-Host "[!] Chains   : $($runData.PathHints.Count) attack path(s) chained" -ForegroundColor Magenta
    }

    $findings | Get-ADScoutSummary

    if ($Gui) {
        Show-ADScoutFindingsGui -View $View -Findings $findings
    }

    # Return rich object
    [PSCustomObject]@{
        RunData                 = $runData
        OutputPath              = $runPath
        Preset                  = $Preset
        AclSweep                = $runData.Meta.AclSweep
        Findings                = $findings.Count
        Critical                = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High                    = @($findings | Where-Object { $_.Severity -eq 'High'     }).Count
        Medium                  = @($findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
        Low                     = @($findings | Where-Object { $_.Severity -eq 'Low'      }).Count
        PathHints               = $runData.PathHints.Count
        PasswordInDesc          = $runData.PasswordInDescription.Count
        ShadowCredentials       = $runData.ShadowCredentials.Count
        AclAttackPaths          = $runData.AclAttackPaths.Count
        GPOWritePermissions     = $runData.GPOWritePermissions.Count
        TargetedKerberoastPaths = $runData.TargetedKerberoastPaths.Count
        Users                   = $runData.Users.Count
        Computers               = $runData.Computers.Count
        DomainControllers       = $runData.DomainControllers.Count
        StaleComputers          = $runData.StaleComputers.Count
    }
}

# =============================================================================
# TAB COMPLETION (inlined -- no companion file needed)
# =============================================================================

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName Preset -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    'Quick','Standard','Deep' | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"Preset: $_") }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout,Show-ADScoutFindingsGui -ParameterName View -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    'Findings','PrivilegedGroups','Delegation','Users','Computers','All' | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"View: $_") }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName OutputFormat -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    'CSV','JSON','Both' | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"Format: $_") }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName OutputPath -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    Get-ChildItem -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_.FullName,$_.Name,'ParameterValue',$_.FullName) }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout,Get-ADScoutDomainInfo,Get-ADScoutUser,Get-ADScoutGroup,Get-ADScoutComputer,Find-ADScoutSPNAccount,Find-ADScoutASREPAccount,Find-ADScoutUnconstrainedDelegation,Find-ADScoutConstrainedDelegation,Get-ADScoutObjectAcl,Find-ADScoutInterestingAce,Get-ADScoutGroupMember,Get-ADScoutGroupReport -ParameterName Server -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    $candidates = @()
    try { $root = [ADSI]'LDAP://RootDSE'; if ($root.dnsHostName) { $candidates += $root.dnsHostName.ToString() } } catch {}
    $envLogonServer = $env:LOGONSERVER -replace '^\\\\', ''
    if ($envLogonServer) { $candidates += $envLogonServer }
    $candidates | Where-Object { $_ -and $_ -like "$wordToComplete*" } | Sort-Object -Unique |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"DC: $_") }
}

Register-ArgumentCompleter -CommandName Get-ADScoutObjectAcl,Find-ADScoutInterestingAce -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    try {
        $root = [ADSI]'LDAP://RootDSE'; $baseDn = $root.defaultNamingContext; if (-not $baseDn) { return }
        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50; $searcher.SizeLimit = 25
        $safeWord = $wordToComplete -replace "'"
        $searcher.Filter = if ([string]::IsNullOrWhiteSpace($safeWord)) {
            '(|(objectClass=organizationalUnit)(objectClass=group)(objectCategory=person)(objectCategory=computer))'
        } else { "(|(name=*$safeWord*)(samAccountName=*$safeWord*))" }
        [void]$searcher.PropertiesToLoad.Add('name'); [void]$searcher.PropertiesToLoad.Add('samAccountName'); [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        foreach ($result in $searcher.FindAll()) {
            $display = if ($result.Properties.Contains('samaccountname')) { $result.Properties.samaccountname[0].ToString() }
                       elseif ($result.Properties.Contains('name'))       { $result.Properties.name[0].ToString() }
                       else { $result.Properties.distinguishedname[0].ToString() }
            [System.Management.Automation.CompletionResult]::new("'$display'", $display, 'ParameterValue', $display)
        }
    } catch { return }
}

Register-ArgumentCompleter -CommandName Get-ADScoutGroupMember,Get-ADScoutGroupReport -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    try {
        $root = [ADSI]'LDAP://RootDSE'; $baseDn = $root.defaultNamingContext; if (-not $baseDn) { return }
        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50; $searcher.SizeLimit = 25
        $safeWord = $wordToComplete -replace "'"
        $searcher.Filter = if ([string]::IsNullOrWhiteSpace($safeWord)) { '(objectClass=group)' }
                           else { "(&(objectClass=group)(|(name=*$safeWord*)(samAccountName=*$safeWord*)))" }
        [void]$searcher.PropertiesToLoad.Add('name'); [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        foreach ($result in $searcher.FindAll()) {
            if ($result.Properties.Contains('name')) {
                $name = $result.Properties.name[0].ToString()
                [System.Management.Automation.CompletionResult]::new("'$name'", $name, 'ParameterValue', $name)
            }
        }
    } catch { return }
}

Register-ArgumentCompleter -CommandName Get-ADScoutGroupReport -ParameterName GroupName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    try {
        $root = [ADSI]'LDAP://RootDSE'; $baseDn = $root.defaultNamingContext; if (-not $baseDn) { return }
        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50; $searcher.SizeLimit = 25
        $safeWord = $wordToComplete -replace "'"
        $searcher.Filter = if ([string]::IsNullOrWhiteSpace($safeWord)) { '(objectClass=group)' }
                           else { "(&(objectClass=group)(|(name=*$safeWord*)(samAccountName=*$safeWord*)))" }
        [void]$searcher.PropertiesToLoad.Add('name')
        foreach ($result in $searcher.FindAll()) {
            if ($result.Properties.Contains('name')) {
                $name = $result.Properties.name[0].ToString()
                [System.Management.Automation.CompletionResult]::new("'$name'", $name, 'ParameterValue', $name)
            }
        }
    } catch { return }
}

# =============================================================================
# SUMMARY
# =============================================================================

function Get-ADScoutQuickWins {
<#
.SYNOPSIS
Answers one question: what is the shortest path to DA right now?
.DESCRIPTION
No noise. No LAPS gaps, stale computers, or informational findings.
Just the things worth trying, in exploitation order.

Priority order:
  1. Credentials/flags in readable AD fields (instant win)
  2. AS-REP roastable accounts that are DA members or adminCount=1
  3. Kerberoastable accounts that are DA members or adminCount=1
  4. Unconstrained delegation hosts (coerce + capture TGT)
  5. Non-privileged principals with DCSync rights
  6. ACL attack paths to Tier 0 objects
  7. Targeted Kerberoast paths (GenericWrite -> set SPN -> crack)
  8. Any user with a nested group path to Domain Admins
  9. GPO write permissions on privileged OUs

Requires RunData from Invoke-ADScoutCollection.
For full path chain analysis use Get-ADScoutPathHint -RunData $data.
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Standard -LabMode
Get-ADScoutQuickWins -RunData $data
.EXAMPLE
$data = Invoke-ADScoutCollection -Preset Deep -LabMode
Get-ADScoutQuickWins -RunData $data | Format-List
.EXAMPLE
# All in one
$r = Invoke-ADScout -Preset Standard -LabMode -NoExport
Get-ADScoutQuickWins -RunData $r.RunData
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][PSCustomObject]$RunData
    )
    begin { $rd = $null }
    process { if ($RunData) { $rd = $RunData } }
    end {
        $rd = Resolve-ADScoutRunData -RunData $rd
        if (-not $rd) { return }

        # Ensure indexes exist
        if (-not $rd.Indexes) { $rd.Indexes = Build-ADScoutIndexes -RunData $rd }

        $idx    = $rd.Indexes
        $bySam  = $idx.ObjectBySam
        $wins   = [System.Collections.ArrayList]@()
        $rank   = 0

        function Add-Win {
            param($Priority, $Category, $Title, $Target, $Why, $ManualVerify, $Evidence='')
            [void]$wins.Add([PSCustomObject][ordered]@{
                Priority     = $Priority
                Category     = $Category
                Title        = $Title
                Target       = $Target
                Why          = $Why
                Evidence     = $Evidence
                ManualVerify = $ManualVerify
            })
        }

        # Helper: is account a DA member or adminCount=1?
        function Get-AccountPrivLevel {
            param([string]$Sam)
            $obj       = if ($bySam.ContainsKey($Sam)) { $bySam[$Sam] } else { $null }
            $dn        = if ($obj) { Get-ADScoutSafeProperty $obj 'DistinguishedName' } else { $null }
            $adminCnt  = if ($obj) { Get-ADScoutSafeProperty $obj 'AdminCount' } else { $null }
            $isAdmin   = $adminCnt -eq '1'
            $isDA      = $false
            if ($dn) {
                foreach ($entry in @($rd.PrivilegedGroupMembers) | Where-Object {
                    (Get-ADScoutSafeProperty $_ 'Group') -eq 'Domain Admins'
                }) {
                    if ((Get-ADScoutSafeProperty $entry 'DistinguishedName') -eq $dn) { $isDA = $true; break }
                }
            }
            [PSCustomObject]@{ IsDA=$isDA; IsAdmin=$isAdmin; DN=$dn }
        }

        # =============================================================
        # 1. Credentials / flags in readable fields
        # =============================================================
        foreach ($x in @($rd.PasswordInDescription)) {
            $rank++
            Add-Win $rank 'Credential Exposure' 'Readable credential/flag in AD field' `
                $x.SamAccountName `
                "Field '$($x.Field)' is readable by all authenticated users -- value may be a password or flag." `
                "Find-ADScoutPasswordInDescription | Where-Object SamAccountName -eq '$($x.SamAccountName)'" `
                "Field=$($x.Field); Value=$($x.Value)"
        }

        # =============================================================
        # 2. AS-REP roastable -- DA or adminCount=1 first
        # =============================================================
        $asrepPriv  = @()
        $asrepOther = @()
        foreach ($x in @($rd.ASREPAccounts)) {
            $sam  = Get-ADScoutObjectDisplayName $x
            $priv = Get-AccountPrivLevel -Sam $sam
            if ($priv.IsDA -or $priv.IsAdmin) { $asrepPriv  += $x }
            else                              { $asrepOther += $x }
        }
        foreach ($x in ($asrepPriv + $asrepOther)) {
            $sam  = Get-ADScoutObjectDisplayName $x
            $priv = Get-AccountPrivLevel -Sam $sam
            $rank++
            $label = if ($priv.IsDA) { 'AS-REP roastable DA member -- crack = Domain Admin' }
                     elseif ($priv.IsAdmin) { 'AS-REP roastable adminCount=1 -- crack = privileged account' }
                     else { 'AS-REP roastable account' }
            Add-Win $rank 'AS-REP Roast' $label $sam `
                'No Kerberos preauthentication required -- request AS-REP without credentials and crack offline.' `
                "Find-ADScoutASREPAccount | Where-Object { `$_.SamAccountName -eq '$sam' } | Select-Object SamAccountName,UacFlags,AdminCount"
        }

        # =============================================================
        # 3. Kerberoastable -- DA or adminCount=1 first
        # =============================================================
        $spnPriv  = @()
        $spnOther = @()
        foreach ($x in @($rd.SPNAccounts)) {
            $sam  = Get-ADScoutObjectDisplayName $x
            $priv = Get-AccountPrivLevel -Sam $sam
            if ($priv.IsDA -or $priv.IsAdmin) { $spnPriv  += $x }
            else                              { $spnOther += $x }
        }
        foreach ($x in ($spnPriv + $spnOther)) {
            $sam  = Get-ADScoutObjectDisplayName $x
            $spn  = Get-ADScoutSafeProperty $x 'ServicePrincipalName'
            $priv = Get-AccountPrivLevel -Sam $sam
            $rank++
            $label = if ($priv.IsDA) { 'Kerberoastable DA member -- crack = Domain Admin' }
                     elseif ($priv.IsAdmin) { 'Kerberoastable adminCount=1 -- crack = privileged account' }
                     else { 'Kerberoastable service account' }
            Add-Win $rank 'Kerberoast' $label $sam `
                'Request TGS for SPN, crack offline. High value if account is privileged.' `
                "Find-ADScoutSPNAccount | Where-Object SamAccountName -eq '$sam' | Select-Object SamAccountName,ServicePrincipalName,AdminCount" `
                $spn
        }

        # =============================================================
        # 4. Unconstrained delegation
        # =============================================================
        foreach ($x in @($rd.Delegation) | Where-Object {
            (Get-ADScoutSafeProperty $_ 'Type') -ne 'KCD' -and
            (Get-ADScoutSafeProperty $_ 'Type') -ne 'RBCD'
        }) {
            $name = Get-ADScoutObjectDisplayName $x
            $rank++
            Add-Win $rank 'Unconstrained Delegation' 'Coerce auth to this host -- capture TGT' $name `
                'Any user whose TGT is cached on this host can be impersonated. Coerce a DC to authenticate here via PrinterBug or PetitPotam.' `
                "Find-ADScoutUnconstrainedDelegation | Where-Object { `$_.Name -eq '$name' -or `$_.SamAccountName -eq '$name' }"
        }

        # =============================================================
        # 5. Non-standard DCSync rights
        # =============================================================
        foreach ($x in @($rd.DCSyncRights) | Where-Object { $_.Severity -eq 'Critical' }) {
            $iref = $x.IdentityReference
            $rank++
            Add-Win $rank 'DCSync' 'Non-standard DCSync right -- dump all hashes' $iref `
                "This principal can replicate credential material from the DC. If you control it, run DCSync." `
                "Find-ADScoutDCSyncRight | Where-Object { `$_.IdentityReference -eq '$iref' }" `
                $x.RightName
        }

        # =============================================================
        # 6. ACL attack paths to Tier 0
        # =============================================================
        foreach ($x in @($rd.AclAttackPaths)) {
            $iref = $x.IdentityReference
            $tgt  = $x.TargetObject
            $rank++
            Add-Win $rank 'ACL Attack Path' "Abusable ACE on $($x.TargetType): $tgt" $iref `
                "$($x.Rights) on $tgt. Abuse this right to escalate." `
                "Get-ADScoutObjectAcl -Identity '$tgt' | Where-Object { `$_.IdentityReference -match '$iref' } | Format-List" `
                "$($x.Rights) [$($x.ObjectType)]"
        }

        # =============================================================
        # 7. Targeted Kerberoast paths
        # =============================================================
        foreach ($x in @($rd.TargetedKerberoastPaths)) {
            $attk = $x.AttackerPrincipal
            $tgt  = $x.TargetUser
            $rank++
            Add-Win $rank 'Targeted Kerberoast' "Set SPN on $tgt and Kerberoast" $attk `
                "$attk has $($x.Rights) on $tgt. Set a SPN, request TGS, crack offline." `
                "Get-ADScoutObjectAcl -Identity '$tgt' | Where-Object { `$_.IdentityReference -match '$attk' } | Format-List"
        }

        # =============================================================
        # 8. Nested group paths to DA
        # =============================================================
        foreach ($entry in @($rd.PrivilegePaths) | Where-Object {
            (Get-ADScoutSafeProperty $_ 'Group') -eq 'Domain Admins' -and
            (Get-ADScoutSafeProperty $_ 'IsNested') -eq $true
        }) {
            $member = Get-ADScoutSafeProperty $entry 'Member'
            $path   = Get-ADScoutSafeProperty $entry 'Path'
            $rank++
            Add-Win $rank 'Privilege Path' 'Nested group path to Domain Admins' $member `
                "Account reaches Domain Admins via nested group: $path" `
                "Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive | Where-Object { `$_.MemberSamAccountName -eq '$member' }" `
                $path
        }

        # =============================================================
        # 9. GPO write on privileged OUs
        # =============================================================
        foreach ($x in @($rd.GPOWritePermissions) | Where-Object { (Get-ADScoutSafeProperty $_ 'AppliesToPrivOu') -eq $true }) {
            $iref = $x.IdentityReference
            $gpo  = $x.GPOName
            $rank++
            Add-Win $rank 'GPO Abuse' "Write access to GPO '$gpo' (privileged OU)" $iref `
                "Modify this GPO to execute code as SYSTEM on all machines in scope: $($x.LinkedOUs)" `
                "Find-ADScoutGPOWritePermission | Where-Object { `$_.GPOName -eq '$gpo' }" `
                "Linked OUs: $($x.LinkedOUs)"
        }

        if ($wins.Count -eq 0) {
            Write-Host '[*] No quick wins identified with current collection. Try -Preset Deep -IncludeAclSweep for ACL-based paths.' -ForegroundColor DarkYellow
            return
        }

        # Output with color
        Write-Host ''
        Write-Host "  ADScoutPS -- Quick Wins ($($wins.Count) found)" -ForegroundColor Cyan
        Write-Host "  ============================================" -ForegroundColor Cyan
        Write-Host ''

        foreach ($w in $wins) {
            $color = switch ($w.Category) {
                'Credential Exposure'  { 'Red'     }
                'AS-REP Roast'         { 'Red'     }
                'Kerberoast'           { 'Yellow'  }
                'DCSync'               { 'Red'     }
                'ACL Attack Path'      { 'Red'     }
                'Unconstrained Delegation' { 'Red' }
                'Targeted Kerberoast'  { 'Yellow'  }
                'Privilege Path'       { 'Yellow'  }
                'GPO Abuse'            { 'Red'     }
                default                { 'White'   }
            }
            Write-Host "  [$($w.Priority)] $($w.Category)" -ForegroundColor $color
            Write-Host "      Title  : $($w.Title)"        -ForegroundColor White
            Write-Host "      Target : $($w.Target)"       -ForegroundColor White
            if ($w.Evidence) {
                Write-Host "      Evidence: $($w.Evidence)" -ForegroundColor DarkGray
            }
            Write-Host "      Why    : $($w.Why)"          -ForegroundColor DarkGray
            Write-Host "      Verify : $($w.ManualVerify)" -ForegroundColor Cyan
            Write-Host ''
        }

        return @($wins)
    }
}


function Get-ADScoutSummary {
<#
.SYNOPSIS
Prints a concise, color-coded summary of findings grouped by what's actionable.
.DESCRIPTION
Designed to give an immediate read on what was found after a collection run.
Pass findings from Get-ADScoutFinding or Invoke-ADScout, or run standalone
to collect findings automatically.
.EXAMPLE
Get-ADScoutFinding -SkipAclSweep | Get-ADScoutSummary
.EXAMPLE
Get-ADScoutSummary  # collects findings automatically with -SkipAclSweep
.EXAMPLE
$results = Invoke-ADScout -Preset Standard -NoExport
Get-ADScoutSummary -Findings $results.Findings
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][object[]]$Findings,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    begin   { $collected = [System.Collections.ArrayList]@() }
    process { if ($Findings) { foreach ($f in $Findings) { [void]$collected.Add($f) } } }
    end {
        if ($collected.Count -eq 0) {
            # Try session RunData first, fall back to live collection
            $rd = $script:ADScoutLastRun
            if ($rd -and $rd.Findings -and $rd.Findings.Count -gt 0) {
                Write-Host '[*] Using session RunData findings...' -ForegroundColor DarkGray
                $collected = [System.Collections.ArrayList]@($rd.Findings)
            } else {
                Write-Host '[*] No findings passed -- running Get-Findings ...' -ForegroundColor Cyan
                $collected = [System.Collections.ArrayList]@(Get-ADScoutFinding -SkipAclSweep)
            }
        }

        $all = @($collected | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Severity'] })

        Write-Host ''
        Write-Host '+==========================================+' -ForegroundColor Cyan
        Write-Host '|         ADScoutPS -- Finding Summary       |' -ForegroundColor Cyan
        Write-Host '+==========================================+' -ForegroundColor Cyan
        Write-Host ''

        # Severity counts
        $critical = @($all | Where-Object { $_.Severity -eq 'Critical' }).Count
        $high     = @($all | Where-Object { $_.Severity -eq 'High'     }).Count
        $medium   = @($all | Where-Object { $_.Severity -eq 'Medium'   }).Count
        $low      = @($all | Where-Object { $_.Severity -eq 'Low'      }).Count
        $info     = @($all | Where-Object { $_.Severity -eq 'Info'     }).Count

        Write-Host '  Severity Breakdown' -ForegroundColor White
        if ($critical -gt 0) { Write-Host "    Critical : $critical" -ForegroundColor Red }
        if ($high     -gt 0) { Write-Host "    High     : $high"     -ForegroundColor Yellow }
        if ($medium   -gt 0) { Write-Host "    Medium   : $medium"   -ForegroundColor DarkYellow }
        if ($low      -gt 0) { Write-Host "    Low      : $low"      -ForegroundColor Gray }
        if ($info     -gt 0) { Write-Host "    Info     : $info"     -ForegroundColor DarkGray }
        Write-Host ''

        # Actionable hit checks -- ordered by exploitation directness
        $checks = @(
            @{ Pattern='Sensitive content in user-readable';     Label='Cleartext creds/flags in AD fields'; Color='Red'        }
            @{ Pattern='AS-REP roast candidate';                Label='AS-REP Roast';                    Color='Red'        }
            @{ Pattern='Non-standard ACE on AdminSDHolder';     Label='AdminSDHolder persistence ACE';   Color='Red'        }
            @{ Pattern='Abusable ACE on';                       Label='ACL attack path on HVT';          Color='Red'        }
            @{ Pattern='DCSync-related replication right';      Label='DCSync path';                     Color='Red'        }
            @{ Pattern='Unconstrained delegation';              Label='Unconstrained Delegation';         Color='Red'        }
            @{ Pattern='GPO write permission';                  Label='GPO write (linked to priv OU)';   Color='Red'        }
            @{ Pattern='Machine account quota is non-zero';     Label='Non-zero machine account quota';  Color='Yellow'     }
            @{ Pattern='SPN-bearing user account';              Label='Kerberoast';                      Color='Yellow'     }
            @{ Pattern='Targeted Kerberoast path';              Label='Targeted Kerberoast path';        Color='Yellow'     }
            @{ Pattern='RBCD delegation';                       Label='RBCD abuse';                      Color='Yellow'     }
            @{ Pattern='KCD delegation';                        Label='KCD delegation';                  Color='Yellow'     }
            @{ Pattern='msDS-KeyCredentialLink present';        Label='Shadow credentials';              Color='Yellow'     }
            @{ Pattern='Interesting ACE on domain root';        Label='Interesting ACE on domain root';  Color='Yellow'     }
            @{ Pattern='Weak password policy';                  Label='Weak password policy';            Color='Yellow'     }
            @{ Pattern='Weak/review-worthy UAC flag';           Label='Weak UAC flags';                  Color='DarkYellow' }
            @{ Pattern='adminCount=1';                          Label='adminCount=1 objects';            Color='DarkYellow' }
            @{ Pattern='No visible LAPS metadata';              Label='No LAPS coverage';                Color='DarkYellow' }
            @{ Pattern='Stale computer account';                Label='Stale computers';                 Color='Gray'       }
        )

        Write-Host '  Actionable Findings' -ForegroundColor White
        $anyHit = $false
        foreach ($c in $checks) {
            $hits = @($all | Where-Object { $null -ne $_.Title -and $_.Title -match $c.Pattern -and $_.Severity -ne 'Info' })
            if ($hits.Count -gt 0) {
                $anyHit = $true
                Write-Host "    [+] $($c.Label): $($hits.Count) hit(s)" -ForegroundColor $c.Color
                $hits | ForEach-Object { Write-Host "        -> $($_.Target)" -ForegroundColor DarkGray }
            }
        }
        if (-not $anyHit) { Write-Host '    None above threshold.' -ForegroundColor DarkGray }

        Write-Host ''
        Write-Host '  Inventory (Info)' -ForegroundColor White
        $dcCount    = @($all | Where-Object { $null -ne $_.Title -and $_.Title -match 'Domain controller discovered' }).Count
        $trustCount = @($all | Where-Object { $null -ne $_.Title -and $_.Title -match 'Domain trust present'        }).Count
        Write-Host "    Domain Controllers : $dcCount"    -ForegroundColor DarkGray
        Write-Host "    Domain Trusts      : $trustCount" -ForegroundColor DarkGray
        Write-Host ''
    }
}

# =============================================================================
# =============================================================================
# ALIASES
# Short-form aliases for interactive/lab use.
# Full function names always work -- these just save typing mid-engagement.
# =============================================================================

# Primary operator workflow
Set-Alias -Name Collect          -Value Invoke-ADScoutCollection
Set-Alias -Name Get-QuickWins    -Value Get-ADScoutQuickWins
Set-Alias -Name Get-Findings     -Value Get-ADScoutFinding
Set-Alias -Name Get-PathHints    -Value Get-ADScoutPathHint
Set-Alias -Name Get-Summary      -Value Get-ADScoutSummary

# Collection
Set-Alias -Name Get-Users        -Value Get-ADScoutUser
Set-Alias -Name Get-Groups       -Value Get-ADScoutGroup
Set-Alias -Name Get-Computers    -Value Get-ADScoutComputer
Set-Alias -Name Get-DCs          -Value Get-ADScoutDomainController
Set-Alias -Name Get-Trusts       -Value Get-ADScoutDomainTrust
Set-Alias -Name Get-Policy       -Value Get-ADScoutPasswordPolicy
Set-Alias -Name Get-GPOs         -Value Get-ADScoutGPO
Set-Alias -Name Get-OUs          -Value Get-ADScoutOU

# Kerberos / credential
Set-Alias -Name Find-ASREP       -Value Find-ADScoutASREPAccount
Set-Alias -Name Find-SPNs        -Value Find-ADScoutSPNAccount
Set-Alias -Name Find-Shadow      -Value Find-ADScoutShadowCredential
Set-Alias -Name Find-Passwords   -Value Find-ADScoutPasswordInDescription
Set-Alias -Name Find-Delegation  -Value Find-ADScoutDelegationHint

# ACL / privilege
Set-Alias -Name Get-ADACL        -Value Get-ADScoutObjectAcl
Set-Alias -Name Show-Gui         -Value Show-ADScoutFindingsGui
Set-Alias -Name Find-Interesting -Value Find-ADScoutInterestingAce
Set-Alias -Name Find-LocalAdmin  -Value Find-ADScoutLocalAdminAccess
Set-Alias -Name Find-DCSync      -Value Find-ADScoutDCSyncRight
Set-Alias -Name Find-AclPaths    -Value Find-ADScoutAclAttackPath
Set-Alias -Name Get-Members      -Value Get-ADScoutGroupMember

# Export / import
Set-Alias -Name Export-Run       -Value Export-ADScoutRun
Set-Alias -Name Import-Run       -Value Import-ADScoutRun

# =============================================================================
# ENTRY POINT
# Behavior depends on how the file is loaded:
#
#   Import-Module .\ADScoutPS.ps1          -- loads functions, auto-runs Collect
#   Import-Module .\ADScoutPS.ps1 -LabMode -- loads functions, auto-runs Collect -LabMode  
#   . .\ADScoutPS.ps1 -LoadOnly            -- loads functions only, no collection
#   . .\ADScoutPS.ps1                      -- loads functions, auto-runs Collect
#   .\ADScoutPS.ps1 -Preset Deep -Report   -- full Invoke-ADScout run with export/report
# =============================================================================

$invocationName = $MyInvocation.InvocationName

if ($LoadOnly) {
    # Explicit load-only -- just register functions and aliases, nothing else
    Write-Host "[+] ADScoutPS v$script:ADScoutVersion loaded. Run: Collect -Preset Standard -LabMode" -ForegroundColor Cyan

} elseif ($invocationName -eq '' -or $invocationName -eq 'Import-Module') {
    # Import-Module context -- auto-collect with sensible defaults
    Write-Host "[*] ADScoutPS v$script:ADScoutVersion -- auto-collecting..." -ForegroundColor Cyan
    Invoke-ADScoutCollection -Preset $Preset -Server $Server -Credential $Credential `
        -SearchBase $SearchBase -SkipAclSweep:$SkipAclSweep `
        -IncludeAclSweep:$IncludeAclSweep -LabMode:$LabMode | Out-Null
    Write-Host "[+] Ready. Run: Get-QuickWins" -ForegroundColor Green

} elseif ($invocationName -eq '.') {
    # Dot-source without -LoadOnly -- auto-collect
    Write-Host "[*] ADScoutPS v$script:ADScoutVersion -- auto-collecting..." -ForegroundColor Cyan
    Invoke-ADScoutCollection -Preset $Preset -Server $Server -Credential $Credential `
        -SearchBase $SearchBase -SkipAclSweep:$SkipAclSweep `
        -IncludeAclSweep:$IncludeAclSweep -LabMode:$LabMode | Out-Null
    Write-Host "[+] Ready. Run: Get-QuickWins" -ForegroundColor Green

} else {
    # Direct script execution -- full Invoke-ADScout with export/report/GUI
    Invoke-ADScout -Preset $Preset -Server $Server -Credential $Credential `
        -SearchBase $SearchBase -OutputPath $OutputPath -OutputFormat $OutputFormat `
        -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep `
        -LabMode:$LabMode -Gui:$Gui -View $View -Report:$Report -NoExport:$NoExport
}
