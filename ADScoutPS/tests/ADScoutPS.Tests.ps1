Describe 'ADScoutPS static quality checks' {
    BeforeAll { $RepoRoot = Split-Path -Parent $PSScriptRoot }
    It 'has expected core files' {
        Test-Path (Join-Path $RepoRoot 'ADScout.ps1') | Should -BeTrue
        Test-Path (Join-Path $RepoRoot 'ADScoutPS\ADScoutPS.psm1') | Should -BeTrue
        Test-Path (Join-Path $RepoRoot 'ADScoutPS\ADScoutPS.psd1') | Should -BeTrue
    }
    It 'manifest can be inspected' {
        { Test-ModuleManifest (Join-Path $RepoRoot 'ADScoutPS\ADScoutPS.psd1') } | Should -Not -Throw
    }
    It 'standalone supports LoadOnly' {
        (Get-Content (Join-Path $RepoRoot 'ADScout.ps1') -Raw) | Should -Match 'LoadOnly'
    }
    It 'module contains normalized finding fields' {
        $content = Get-Content (Join-Path $RepoRoot 'ADScoutPS\ADScoutPS.psm1') -Raw
        $content | Should -Match 'WhyItMatters'
        $content | Should -Match 'RecommendedReview'
        $content | Should -Match 'SourceCommand'
    }
}
