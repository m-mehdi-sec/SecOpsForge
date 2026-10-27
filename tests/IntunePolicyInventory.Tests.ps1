
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Get-SecOpsForgeIntunePolicyInventory' {

    BeforeEach {
        Mock Get-Command {
            [PSCustomObject]@{
                Name = 'Invoke-MgGraphRequest'
            }
        } -ParameterFilter {
            $Name -eq 'Invoke-MgGraphRequest'
        } -ModuleName SecOpsForge

        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes = @('DeviceManagementConfiguration.Read.All')
            }
        } -ModuleName SecOpsForge

        Mock Invoke-MgGraphRequest {
            @{
                value = @(
                    @{
                        id = 'policy-1'
                        platforms = 'windows10'
                        technologies = 'mdm'
                    },
                    @{
                        id = 'policy-2'
                        platforms = 'windows10'
                        technologies = 'mdm'
                    }
                )
            }
        } -ModuleName SecOpsForge
    }

    It 'Counts configuration policies correctly' {
        $result = Get-SecOpsForgeIntunePolicyInventory

        $result.ConfigurationPolicyCount | Should -Be 2
    }

    It 'Returns schema version 1.0' {
        $result = Get-SecOpsForgeIntunePolicyInventory

        $result.SchemaVersion | Should -Be '1.0'
    }

    It 'Does not expose policy identifiers' {
        $result = Get-SecOpsForgeIntunePolicyInventory

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'PolicyId'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'PolicyName'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'TenantId'
    }

    It 'Rejects missing configuration read permission' {
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes = @('User.Read.All')
            }
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeIntunePolicyInventory
        } | Should -Throw '*DeviceManagementConfiguration.Read.All*'
    }

    It 'Fails safely when the Graph API fails' {
        Mock Invoke-MgGraphRequest {
            throw 'Simulated Graph API failure'
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeIntunePolicyInventory
        } | Should -Throw '*No report was generated*'
    }
}
