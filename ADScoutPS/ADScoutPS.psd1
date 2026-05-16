@{
    RootModule = 'ADScoutPS.psm1'
    ModuleVersion = '0.3.0'
    GUID = '1d245b66-e6c7-4e94-a8c7-4c0c4b9c8a31'
    Author = 'ADScoutPS Lab Build'
    CompanyName = 'Personal Lab'
    Copyright = '(c) 2026. For authorized lab and assessment use only.'
    Description = 'Read-only PowerShell Active Directory enumeration module with GPO, ACL, ACE, SPN, and summary reporting helpers.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-ADScoutDomainInfo','Get-ADScoutUser','Get-ADScoutGroup','Get-ADScoutComputer',
        'Find-ADScoutSPNAccount','Find-ADScoutAdminGroup','Get-ADScoutOU','Get-ADScoutGPO',
        'Get-ADScoutLinkedGPO','Get-ADScoutObjectAcl','Find-ADScoutInterestingAce',
        'Get-ADScoutGroupMember','Find-ADScoutOldComputer','Find-ADScoutDelegationComputer',
        'Find-ADScoutPrivilegedUser','Invoke-ADScout'
    )
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('ActiveDirectory','LDAP','GPO','ACL','Lab','Enumeration') } }
}
