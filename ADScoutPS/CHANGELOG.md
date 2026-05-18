# Changelog

## v1.4.1

Bug fixes based on post-release code review. No new capabilities.

- **Fixed missing `function Find-ADScoutAdminGroup` declaration** — function body was present but the declaration line was dropped during v1.4.0 refactor. File would fail to parse without this fix.
- **Fixed `Get-ADScoutComputer` missing `description` field** — `description` was absent from both the LDAP property list and the output object. `Find-ADScoutPasswordInDescription` silently returned no computer results as a consequence.
- **Added `IdentitySid` to all ACE output objects** — `Get-ADScoutObjectAcl` now resolves each `IdentityReference` to a `SecurityIdentifier` string via `NTAccount.Translate()` with a graceful `$null` fallback on resolution failure.
- **Replaced name-pattern-based privileged identity exclusion with `Test-ADScoutPrivilegedIdentity`** — new helper function used by all four ACL sweep functions (`Find-ADScoutAclAttackPath`, `Find-ADScoutAdminSDHolderAce`, `Find-ADScoutGPOWritePermission`, `Find-ADScoutTargetedKerberoastPath`). Checks resolved SID suffix first (locale-safe: `-512`, `-516`, `-518`, `-519`, `-544`, `S-1-5-18`, `S-1-5-9`) and falls back to display name matching. Fixes silent false negatives on non-English AD where group names are localized (e.g. `Domänen-Admins`, `Administrateurs`).

## v1.4.0

Major capability additions. All ACE output now includes resolved human-readable right names.

- **Full extended rights GUID resolution** — `$script:ADScoutGuidMap` is a static table of 60+ AD schema and extended rights GUIDs. `Resolve-ADScoutGuid` wraps it. Every ACE object from `Get-ADScoutObjectAcl` now includes `ObjectType` and `InheritedObjectType` as resolved names (e.g. `User-Force-Change-Password`, `DS-Replication-Get-Changes-All`) alongside raw GUIDs in `ObjectTypeGuid` and `InheritedObjectTypeGuid`.
- **`Find-ADScoutDCSyncRight` updated** — filter now matches on `ObjectTypeGuid` (raw GUID). `RightName` field shows the resolved right name.
- **`Get-ADScoutMachineAccountQuota`** — reads `ms-DS-MachineAccountQuota`. Non-zero surfaces as High finding. Included in all presets.
- **`Find-ADScoutShadowCredential`** — LDAP filter on `(msDS-KeyCredentialLink=*)`. Returns `SamAccountName`, `ObjectClass`, `KeyCredentialCount`. Computer accounts with exactly one entry are Medium; anything else is High.
- **`Find-ADScoutAdminSDHolderAce`** — sweeps `CN=AdminSDHolder,CN=System,<domain>` for non-standard ACEs. Critical findings. ACL sweep only.
- **`Find-ADScoutGPOWritePermission`** — maps GPO ACLs to linked OU names. Privileged OU match is Critical; any GPO write is High. ACL sweep only.
- **`Find-ADScoutTargetedKerberoastPath`** — per-user ACL sweep for `GenericAll`/`GenericWrite`. ACL sweep only.
- **`Get-ADScoutCrossForestEnum`** — follows trust links, probes reachable trusted domains. Runs under Standard and Deep presets.
- **`Get-ADScoutDomainTrust` updated** — decoded `TrustDirection`, `TrustType`, `SIDFilteringEnabled`, `IsTransitive`, `IsForestTrust`.
- **`HasShadowCredential` added** to `Get-ADScoutUser` and `Get-ADScoutComputer`.
- **`Get-ADScoutSummary` updated** — covers AdminSDHolder, GPO write, MAQ, shadow credentials, targeted Kerberoast in banner.
- **`Invoke-ADScout` return object expanded** — includes `ShadowCredentials`, `AdminSDHolderAces`, `GPOWritePermissions`, `TargetedKerberoastPaths` counts.
- **`Test-ADScoutEnvironment` updated** — reports `MachineAccountQuota` in preflight output.

## v1.3.0

- Removed duplicate function definitions from v1.1.
- Fixed `Find-ADScoutOldComputer` — `-Days` parameter now used correctly via `[datetime]::FromFileTime()`.
- Stale computer accounts now surface as Low findings in `Get-ADScoutFinding`.
- DCSync severity matching switched to SID suffixes (locale-safe).
- Fixed completion script path resolution (`$PSCommandPath` instead of `$PSScriptRoot`).
- Cleaned up `SkipAclSweep` bool cast in `Invoke-ADScout`.
- `Find-ADScoutSPNAccount` now returns `AdminCount`.
- `Invoke-ADScout` summary object includes `StaleComputers` and `Low` counts.

## v1.2.0 — WorldClassFoundation

- Added `Test-ADScoutEnvironment` preflight validation.
- Added `Get-ADScoutVersion`.
- Added normalized findings with identity/timestamp fields.
- Added `Invoke-ADScout -Preset Quick|Standard|Deep`.
- Added HTML report output (`-Report`).
- Added GUI view selection.
- Added `Get-ADScoutPrivilegePath`.

## v1.1.0

- Bugfixes for missing properties and ACL parameter binding.
