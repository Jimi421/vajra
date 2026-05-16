Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module ..\ADScoutPS\ADScoutPS.psd1 -Force
Invoke-ADScout -SkipAclSweep
