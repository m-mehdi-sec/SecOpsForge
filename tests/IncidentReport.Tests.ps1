
Describe 'New-SecOpsForgeIncidentReport' {

    BeforeAll {
        Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
    }

    It 'Creates a valid JSON incident report' {
        $path = Join-Path $TestDrive 'incident.json'

        New-SecOpsForgeIncidentReport `
            -IncidentId 1 `
            -Title 'EICAR test file prevented' `
            -DeviceName 'W11-CLIENT' `
            -Status 'Resolved' `
            -Classification 'InformationalExpectedActivity' `
            -OutputPath $path | Out-Null

        $report = Get-Content -LiteralPath $path -Raw |
            ConvertFrom-Json

        $report.IncidentId | Should -Be 1
        $report.DeviceName | Should -Be 'W11-CLIENT'
        $report.Status | Should -Be 'Resolved'
        $report.Classification | Should -Be 'InformationalExpectedActivity'
        $report.SchemaVersion | Should -Be '1.0'
    }

    It 'Rejects an invalid incident status' {
        $path = Join-Path $TestDrive 'invalid.json'

        $errorRecord = $null

        try {
            New-SecOpsForgeIncidentReport `
                -IncidentId 1 `
                -Title 'Test incident' `
                -DeviceName 'W11-CLIENT' `
                -Status 'InvalidStatus' `
                -Classification 'TruePositive' `
                -OutputPath $path `
                -ErrorAction Stop | Out-Null
        }
        catch {
            $errorRecord = $_
        }

        $errorRecord | Should -Not -BeNullOrEmpty
        (Test-Path -LiteralPath $path) | Should -Be $false
    }
}


