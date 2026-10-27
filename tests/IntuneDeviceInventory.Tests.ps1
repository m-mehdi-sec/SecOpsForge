
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Get-SecOpsForgeIntuneDeviceInventory' {

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
                Scopes = @('DeviceManagementManagedDevices.Read.All')
            }
        } -ModuleName SecOpsForge

        Mock Invoke-MgGraphRequest {
            @{
                value = @(
                    @{
                        operatingSystem = 'Windows'
                        complianceState = 'compliant'
                    },
                    @{
                        operatingSystem = 'Windows'
                        complianceState = 'noncompliant'
                    },
                    @{
                        operatingSystem = 'Android'
                        complianceState = 'unknown'
                    }
                )
            }
        } -ModuleName SecOpsForge
    }

    It 'Counts managed devices correctly' {
        $result = Get-SecOpsForgeIntuneDeviceInventory

        $result.TotalManagedDevices | Should -Be 3
        $result.WindowsDevices | Should -Be 2
        $result.CompliantDevices | Should -Be 1
        $result.NoncompliantDevices | Should -Be 1
        $result.OtherCompliance | Should -Be 1
    }

    It 'Returns schema version 1.0' {
        $result = Get-SecOpsForgeIntuneDeviceInventory

        $result.SchemaVersion | Should -Be '1.0'
    }

    It 'Does not expose device identifiers' {
        $result = Get-SecOpsForgeIntuneDeviceInventory

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'DeviceId'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'DeviceName'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'UserPrincipalName'
    }

    It 'Rejects missing Intune read permission' {
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes = @('User.Read.All')
            }
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeIntuneDeviceInventory
        } | Should -Throw '*DeviceManagementManagedDevices.Read.All*'
    }

    It 'Fails safely when the Graph API fails' {
        Mock Invoke-MgGraphRequest {
            throw 'Simulated Graph API failure'
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeIntuneDeviceInventory
        } | Should -Throw '*No report was generated*'
    }
}
