
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Test-SecOpsForgeGraphConnection' {

    It 'Exports the Graph connection function' {
        Get-Command Test-SecOpsForgeGraphConnection |
            Should -Not -BeNullOrEmpty
    }

    It 'Returns a disconnected status when Graph is unavailable' {
        Mock Get-Command {
            $null
        } -ParameterFilter {
            $Name -eq 'Get-MgContext'
        } -ModuleName SecOpsForge

        $result = Test-SecOpsForgeGraphConnection

        $result.Connected | Should -BeFalse
        $result.HasReadScope | Should -BeFalse
        $result.Status | Should -Be 'Graph authentication module is not available'
    }

    It 'Does not expose account identifiers in the result' {
        $result = Test-SecOpsForgeGraphConnection

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'Account'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'TenantId'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'AccessToken'
    }
}
