
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'New-SecOpsForgeSecurityPostureReport' {

    BeforeEach {
        Mock Get-SecOpsForgeIdentityInventory {
            [PSCustomObject]@{ TotalUsers = 3 }
        } -ModuleName SecOpsForge

        Mock Get-SecOpsForgePrivilegedAccessInventory {
            [PSCustomObject]@{ TotalRoleAssignments = 2 }
        } -ModuleName SecOpsForge

        Mock Get-SecOpsForgeIntuneDeviceInventory {
            [PSCustomObject]@{ TotalManagedDevices = 1 }
        } -ModuleName SecOpsForge

        Mock Get-SecOpsForgeIntunePolicyInventory {
            [PSCustomObject]@{ TotalPolicies = 1 }
        } -ModuleName SecOpsForge

        Mock Get-SecOpsForgeDefenderIncidentInventory {
            [PSCustomObject]@{ TotalIncidents = 1 }
        } -ModuleName SecOpsForge
    }

    It 'Combines all five security inventories' {
        $report = New-SecOpsForgeSecurityPostureReport

        $report.Identity.TotalUsers | Should -Be 3
        $report.PrivilegedAccess.TotalRoleAssignments | Should -Be 2
        $report.IntuneDevices.TotalManagedDevices | Should -Be 1
        $report.IntunePolicies.TotalPolicies | Should -Be 1
        $report.DefenderIncidents.TotalIncidents | Should -Be 1
    }

    It 'Includes report metadata' {
        $report = New-SecOpsForgeSecurityPostureReport

        $report.SchemaVersion | Should -Be '1.0'
        $report.ReportType | Should -Be 'SecurityPosture'
        $report.GeneratedAtUtc | Should -Not -BeNullOrEmpty
    }

    It 'Does not create a file without OutputPath' {
        $report = New-SecOpsForgeSecurityPostureReport

        $report | Should -Not -BeNullOrEmpty
    }

    It 'Exports valid JSON when OutputPath is provided' {
        $path = Join-Path $TestDrive 'posture.json'

        New-SecOpsForgeSecurityPostureReport `
            -OutputPath $path | Out-Null

        Test-Path -LiteralPath $path | Should -BeTrue

        $json = Get-Content -LiteralPath $path -Raw |
            ConvertFrom-Json

        $json.ReportType | Should -Be 'SecurityPosture'
        $json.DefenderIncidents.TotalIncidents | Should -Be 1
    }

    It 'Rejects an output directory that does not exist' {
        $path = Join-Path $TestDrive 'missing/posture.json'

        {
            New-SecOpsForgeSecurityPostureReport -OutputPath $path
        } | Should -Throw '*No complete report was generated*'
    }

    It 'Fails safely when an inventory fails' {
        Mock Get-SecOpsForgeDefenderIncidentInventory {
            throw 'Simulated inventory failure'
        } -ModuleName SecOpsForge

        {
            New-SecOpsForgeSecurityPostureReport
        } | Should -Throw '*No complete report was generated*'
    }
}
