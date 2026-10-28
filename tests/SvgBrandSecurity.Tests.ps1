Describe 'SVG branding security validation' {
    BeforeAll {
        $script:generatorPath = Join-Path $PSScriptRoot '..\scripts\New-SecOpsForgeHtmlReport.ps1'
        $script:generator = Get-Content -LiteralPath $script:generatorPath -Raw
        $script:tokens = $null
        $script:errors = $null
        $script:ast = [System.Management.Automation.Language.Parser]::ParseInput($script:generator, [ref]$script:tokens, [ref]$script:errors)
        $script:iconFunction = $script:ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ProductIcon' }, $true) | Select-Object -First 1
        if (-not $script:iconFunction) { throw 'Get-ProductIcon function not found.' }
        . ([scriptblock]::Create($script:iconFunction.Extent.Text))
        $script:oldHome = $env:USERPROFILE
        $env:USERPROFILE = Join-Path $TestDrive 'TestUser'
        $script:assetDir = Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports\BrandAssets'
        New-Item -ItemType Directory -Path $script:assetDir -Force | Out-Null
    }
    AfterAll { $env:USERPROFILE = $script:oldHome }
    It 'parses the generator without PowerShell syntax errors' {
        @($script:errors).Count | Should -Be 0
    }
    It 'allows a minimal valid SVG and embeds it without a network URL' {
        Set-Content -LiteralPath (Join-Path $script:assetDir 'entra-id.svg') -Value '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0L1 1"/></svg>'
        $result = Get-ProductIcon -Id 'identity'
        $result | Should -Match 'data:image/svg\+xml;base64,'
    }
    It 'allows safe local SVG gradients used by Microsoft Intune icons' {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="paint1"><stop offset="0" stop-color="#123456"/></linearGradient></defs><rect width="10" height="10" fill="url(#paint1)"/></svg>'
        Set-Content -LiteralPath (Join-Path $script:assetDir 'intune.svg') -Value $svg
        Get-ProductIcon -Id 'devices' | Should -Match 'data:image/svg\+xml;base64,'
    }
    It 'rejects non-local SVG paint references' {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://example.org/paint)"/></svg>'
        Set-Content -LiteralPath (Join-Path $script:assetDir 'intune.svg') -Value $svg
        { Get-ProductIcon -Id 'devices' } | Should -Throw '*Unsafe or invalid*'
    }
    It 'rejects DTD and entity declarations' {
        Set-Content -LiteralPath (Join-Path $script:assetDir 'entra-id.svg') -Value '<!DOCTYPE svg [<!ENTITY x "test">]><svg xmlns="http://www.w3.org/2000/svg"><title>&x;</title></svg>'
        { Get-ProductIcon -Id 'identity' } | Should -Throw '*Unsafe or invalid*'
    }
    It 'rejects script elements' {
        Set-Content -LiteralPath (Join-Path $script:assetDir 'entra-id.svg') -Value '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        { Get-ProductIcon -Id 'identity' } | Should -Throw '*Unsafe or invalid*'
    }
    It 'rejects event-handler attributes' {
        Set-Content -LiteralPath (Join-Path $script:assetDir 'entra-id.svg') -Value '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)" />'
        { Get-ProductIcon -Id 'identity' } | Should -Throw '*Unsafe or invalid*'
    }
    It 'rejects external resources and CSS url references' {
        Set-Content -LiteralPath (Join-Path $script:assetDir 'entra-id.svg') -Value '<svg xmlns="http://www.w3.org/2000/svg"><path fill="url(https://example.org/x)"/></svg>'
        { Get-ProductIcon -Id 'identity' } | Should -Throw '*Unsafe or invalid*'
    }
    It 'rejects foreign namespaces and image elements' {
        Set-Content -LiteralPath (Join-Path $script:assetDir 'entra-id.svg') -Value '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.org/x"/></svg>'
        { Get-ProductIcon -Id 'identity' } | Should -Throw '*Unsafe or invalid*'
    }
    It 'omits missing product icons' {
        Get-ProductIcon -Id 'incidents' | Should -BeNullOrEmpty
    }
}
