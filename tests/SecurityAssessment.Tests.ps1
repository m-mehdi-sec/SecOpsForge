
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

    It 'Marks baseline as having no detected indicators, not as risk-free' {
        $result = Get-SecOpsForgeSecurityAssessment -Report (New-TestAssessmentReport)

        $result.AssessmentStatus | Should -Be 'NoIndicatorsDetected'
        $result.UnknownCount | Should -Be 0
        $result.ChecksEvaluated | Should -Be 4
        $result.ChecksTotal | Should -Be 4
    }

    It 'Includes a reason, aggregate evidence, and verification for a finding' {
        $report = New-TestAssessmentReport
        $report.DefenderIncidents.ActiveIncidents = 2

        $result = Get-SecOpsForgeSecurityAssessment -Report $report
        $finding = @($result.Findings | Where-Object RuleId -EQ 'SEC-001')[0]

        $finding.Reason | Should -Not -BeNullOrEmpty
        $finding.Evidence | Should -Be 'ActiveIncidents: 2'
        $finding.Recommendation | Should -Not -BeNullOrEmpty
        $finding.Verification | Should -Not -BeNullOrEmpty
        $result.AssessmentStatus | Should -Be 'ReviewRequired'
    }

    It 'Treats a missing counter as unknown rather than zero' {
        $report = New-TestAssessmentReport
        $report.IntunePolicies.PSObject.Properties.Remove('ConfigurationPolicyCount')

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.FindingCount | Should -Be 0
        $result.UnknownCount | Should -Be 1
        $result.UnknownChecks.RuleId | Should -Contain 'SEC-003'
        $result.AssessmentStatus | Should -Be 'InsufficientData'
    }

    It 'Treats a null counter as unknown' {
        $report = New-TestAssessmentReport
        $report.IntuneDevices.NoncompliantDevices = $null

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.UnknownChecks.RuleId | Should -Contain 'SEC-002'
        $result.FindingCount | Should -Be 0
    }

    It 'Treats a negative counter as invalid' {
        $report = New-TestAssessmentReport
        $report.DefenderIncidents.ActiveIncidents = -1

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.UnknownChecks.RuleId | Should -Contain 'SEC-001'
        $result.UnknownCount | Should -Be 1
    }

    It 'Treats a string counter as invalid' {
        $report = New-TestAssessmentReport
        $report.PrivilegedAccess.GlobalAdminAssignments = 'unknown'

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.UnknownChecks.RuleId | Should -Contain 'SEC-004'
        $result.FindingCount | Should -Be 0
    }

    It 'Separates detected findings from unknown checks' {
        $report = New-TestAssessmentReport
        $report.DefenderIncidents.ActiveIncidents = 1
        $report.IntuneDevices.NoncompliantDevices = $null

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.FindingCount | Should -Be 1
        $result.UnknownCount | Should -Be 1
        $result.ChecksEvaluated | Should -Be 3
        $result.AssessmentStatus | Should -Be 'ReviewRequiredWithDataGaps'
    }

    It 'Does not flag two Global Administrator assignments' {
        $report = New-TestAssessmentReport
        $report.PrivilegedAccess.GlobalAdminAssignments = 2

        $result = Get-SecOpsForgeSecurityAssessment -Report $report

        $result.Findings.RuleId | Should -Not -Contain 'SEC-004'
    }

}
