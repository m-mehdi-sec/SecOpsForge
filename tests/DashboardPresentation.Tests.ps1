Describe 'SecOpsForge dashboard presentation' {
    BeforeAll {
        $renderer = Join-Path $PSScriptRoot '..\scripts\New-SecOpsForgeHtmlReport.ps1'
        $source = Get-Content -LiteralPath $renderer -Raw -Encoding utf8
    }
    It 'retains the offline restrictive CSP' {
        $source | Should -Match "script-src 'none'"
        $source | Should -Match "connect-src 'none'"
    }
    It 'uses an inline geometric SVG mark' {
        $source | Should -Match "aria-label='SecOpsForge security symbol'"
        $source | Should -Match "<svg viewBox='0 0 48 48'"
    }
    It 'labels the report as a snapshot' {
        $source | Should -Match 'Snapshot, not live monitoring'
    }
    It 'uses native disclosure for finding details' {
        $source | Should -Match '<details open><summary>'
    }
    It 'retains the HTML encoder for report data' {
        $source | Should -Match 'WebUtility]::HtmlEncode'
    }
    It 'keeps export protection outside the repository' {
        $source | Should -Match 'Assert-OutsideRepository -Path \$OutputPath'
    }
}
