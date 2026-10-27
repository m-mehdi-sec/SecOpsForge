
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Get-SecOpsForgePrivilegedAccessInventory' {

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
                Scopes = @('RoleManagement.Read.Directory')
            }
        } -ModuleName SecOpsForge

        Mock Invoke-MgGraphRequest {
            if ($Uri -match '/roleAssignments') {
                return @{
                    value = @(
                        @{
                            roleDefinitionId = 'global-admin-role'
                            principalId = 'principal-1'
                        },
                        @{
                            roleDefinitionId = 'global-admin-role'
                            principalId = 'principal-2'
                        },
                        @{
                            roleDefinitionId = 'security-reader-role'
                            principalId = 'principal-1'
                        }
                    )
                }
            }

            if ($Uri -match '/roleDefinitions') {
                return @{
                    value = @(
                        @{
                            id = 'global-admin-role'
                            templateId = '62e90394-69f5-4237-9190-012177145e10'
                        },
                        @{
                            id = 'security-reader-role'
                            templateId = 'security-reader-template'
                        }
                    )
                }
            }

            throw 'Unexpected Graph endpoint.'
        } -ModuleName SecOpsForge
    }

    It 'Counts Global Administrator assignments correctly' {
        $result = Get-SecOpsForgePrivilegedAccessInventory

        $result.TotalRoleAssignments | Should -Be 3
        $result.GlobalAdminAssignments | Should -Be 2
        $result.OtherRoleAssignments | Should -Be 1
        $result.UniquePrivilegedPrincipals | Should -Be 2
    }

    It 'Returns schema version 1.0' {
        $result = Get-SecOpsForgePrivilegedAccessInventory

        $result.SchemaVersion | Should -Be '1.0'
    }

    It 'Does not expose principal identifiers' {
        $result = Get-SecOpsForgePrivilegedAccessInventory

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'PrincipalId'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'Account'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'TenantId'
    }

    It 'Rejects missing role management permission' {
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes = @('User.Read.All')
            }
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgePrivilegedAccessInventory
        } | Should -Throw '*RoleManagement.Read.Directory*'
    }

    It 'Fails safely when the Graph API fails' {
        Mock Invoke-MgGraphRequest {
            throw 'Simulated Graph API failure'
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgePrivilegedAccessInventory
        } | Should -Throw '*No report was generated*'
    }
}
