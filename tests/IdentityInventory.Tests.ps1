
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Get-SecOpsForgeIdentityInventory' {

    BeforeEach {
        Mock Get-Command {
            [PSCustomObject]@{ Name = 'Invoke-MgGraphRequest' }
        } -ParameterFilter {
            $Name -eq 'Invoke-MgGraphRequest'
        } -ModuleName SecOpsForge

        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes  = @('User.Read.All')
            }
        } -ModuleName SecOpsForge

        Mock Invoke-MgGraphRequest {
            @{
                value = @(
                    @{
                        accountEnabled = $true
                        userType = 'Member'
                        assignedLicenses = @('license-1')
                    },
                    @{
                        accountEnabled = $false
                        userType = 'Member'
                        assignedLicenses = @()
                    },
                    @{
                        accountEnabled = $true
                        userType = 'Guest'
                        assignedLicenses = @()
                    }
                )
            }
        } -ModuleName SecOpsForge
    }

    It 'Returns accurate identity counts' {
        $result = Get-SecOpsForgeIdentityInventory

        $result.TotalUsers | Should -Be 3
        $result.EnabledUsers | Should -Be 2
        $result.DisabledUsers | Should -Be 1
        $result.MemberUsers | Should -Be 2
        $result.GuestUsers | Should -Be 1
        $result.LicensedUsers | Should -Be 1
        $result.UnlicensedUsers | Should -Be 2
    }

    It 'Returns schema version 1.0' {
        $result = Get-SecOpsForgeIdentityInventory

        $result.SchemaVersion | Should -Be '1.0'
    }

    It 'Does not return user identifiers' {
        $result = Get-SecOpsForgeIdentityInventory

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'UserPrincipalName'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'UserId'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'Account'
    }

    It 'Rejects missing User.Read.All permission' {
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes  = @('User.Read')
            }
        } -ModuleName SecOpsForge

        { Get-SecOpsForgeIdentityInventory } |
            Should -Throw '*User.Read.All*'
    }
}
