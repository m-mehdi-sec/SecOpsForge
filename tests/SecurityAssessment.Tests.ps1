
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force

    function New-TestAssessmentReport {
        [PSCustomObject]@{
            Identity = [PSCustomObject]@{
                TotalUsers = 3
            }
            PrivilegedAccess = [PSCustomObject]@{
                GlobalAdminAssignments = 2
            }
            IntuneDevices = [PSCustomObject]@{
                NoncompliantDevices = 0
            }
            IntunePolicies = [PSCustomObject]@{
                ConfigurationPolicyCount = 1
            }
            DefenderIncidents = [PSCustomObject]@{
                ActiveIncidents = 0
            }
        }
    }
}

Describe 'Get-SecOpsForgeSecurityAssessment' {

    It 'Returns no findings for the baseline scenario' {
        $report = New-TestAssessmentReport

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.FindingCount | Should -Be 0
        @($result.Findings).Count | Should -Be 0
    }

    It 'Detects active Defender incidents' {
        $report = New-TestAssessmentReport
        $report.DefenderIncidents.ActiveIncidents = 2

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.Findings.RuleId | Should -Contain 'SEC-001'
    }

    It 'Detects noncompliant Intune devices' {
        $report = New-TestAssessmentReport
        $report.IntuneDevices.NoncompliantDevices = 1

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.Findings.RuleId | Should -Contain 'SEC-002'
    }

    It 'Detects missing modern Intune configuration policies' {
        $report = New-TestAssessmentReport
        $report.IntunePolicies.ConfigurationPolicyCount = 0

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.Findings.RuleId | Should -Contain 'SEC-003'
    }

    It 'Flags more than two Global Administrator assignments for review' {
        $report = New-TestAssessmentReport
        $report.PrivilegedAccess.GlobalAdminAssignments = 3

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.Findings.RuleId | Should -Contain 'SEC-004'
    }

    It 'Detects multiple findings in the same report' {
        $report = New-TestAssessmentReport
        $report.DefenderIncidents.ActiveIncidents = 1
        $report.IntuneDevices.NoncompliantDevices = 1

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.FindingCount | Should -Be 2
        $result.Findings.RuleId | Should -Contain 'SEC-001'
        $result.Findings.RuleId | Should -Contain 'SEC-002'
    }

    It 'Rejects incomplete reports' {
        $report = New-TestAssessmentReport
        $report.IntuneDevices = $null

        {
            Get-SecOpsForgeSecurityAssessment -Report $report
        } | Should -Throw '*incomplete*'
    }

    It 'Includes assessment metadata' {
        $report = New-TestAssessmentReport

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.SchemaVersion | Should -Be '1.0'
        $result.AssessmentType | Should -Be 'SecurityPostureAssessment'
        $result.GeneratedAtUtc | Should -Not -BeNullOrEmpty
    }
}
