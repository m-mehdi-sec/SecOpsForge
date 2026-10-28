
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Get-SecOpsForgeDefenderIncidentInventory' {

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
                Scopes = @('SecurityIncident.Read.All')
            }
        } -ModuleName SecOpsForge

        Mock Invoke-MgGraphRequest {
            @{
                value = @(
                    @{
                        status = 'active'
                        severity = 'high'
                    },
                    @{
                        status = 'resolved'
                        severity = 'informational'
                    },
                    @{
                        status = 'resolved'
                        severity = 'medium'
                    }
                )
            }
        } -ModuleName SecOpsForge
    }

    It 'Counts incidents and severity correctly' {
        $result = Get-SecOpsForgeDefenderIncidentInventory

        $result.TotalIncidents | Should -Be 3
        $result.ActiveIncidents | Should -Be 1
        $result.ResolvedIncidents | Should -Be 2
        $result.HighSeverity | Should -Be 1
        $result.MediumSeverity | Should -Be 1
        $result.InformationalSeverity | Should -Be 1
    }

    It 'Returns schema version 1.0' {
        $result = Get-SecOpsForgeDefenderIncidentInventory

        $result.SchemaVersion | Should -Be '1.0'
    }

    It 'Does not expose incident identifiers' {
        $result = Get-SecOpsForgeDefenderIncidentInventory

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'IncidentId'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'DeviceName'

        $result.PSObject.Properties.Name |
            Should -Not -Contain 'UserPrincipalName'
    }

    It 'Rejects missing incident read permission' {
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'test@example.invalid'
                Scopes = @('User.Read.All')
            }
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeDefenderIncidentInventory
        } | Should -Throw '*SecurityIncident.Read.All*'
    }

    It 'Fails safely when the Graph API fails' {
        Mock Invoke-MgGraphRequest {
            throw 'Simulated Graph API failure'
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeDefenderIncidentInventory
        } | Should -Throw '*No report was generated*'
    }

    It 'Uses a maximum page size of 50' {
        Get-SecOpsForgeDefenderIncidentInventory | Out-Null

        Should -Invoke Invoke-MgGraphRequest `
            -ModuleName SecOpsForge `
            -Times 1 `
            -ParameterFilter {
                $Uri -match '\$top=50'
            }
    }
}
