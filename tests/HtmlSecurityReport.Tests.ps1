BeforeAll {
    $script:generator = Join-Path $PSScriptRoot '../scripts/New-SecOpsForgeHtmlReport.ps1'

    function New-TestPosture {
        [PSCustomObject]@{
            SchemaVersion    = '1.0'
            ReportType       = 'SecurityPosture'
            GeneratedAtUtc   = '2026-10-28T12:00:00Z'
            Identity         = [PSCustomObject]@{ TotalUsers=4; EnabledUsers=3; DisabledUsers=1; GuestUsers=1; UnlicensedUsers=1 }
            PrivilegedAccess = [PSCustomObject]@{ TotalRoleAssignments=2; GlobalAdminAssignments=1; OtherRoleAssignments=1; UniquePrivilegedPrincipals=2 }
            IntuneDevices    = [PSCustomObject]@{ TotalManagedDevices=2; WindowsDevices=2; CompliantDevices=2; NoncompliantDevices=0; OtherCompliance=0 }
            IntunePolicies   = [PSCustomObject]@{ ConfigurationPolicyCount=2 }
            DefenderIncidents= [PSCustomObject]@{ TotalIncidents=1; ActiveIncidents=0; ResolvedIncidents=1; HighSeverity=0; MediumSeverity=0; LowSeverity=1; InformationalSeverity=0; OtherSeverity=0 }
        }
    }

    function New-TestAssessment {
        [PSCustomObject]@{
            SchemaVersion    = '1.0'
            AssessmentType   = 'SecurityPostureAssessment'
            AssessmentStatus = 'NoIndicatorsDetected'
            FindingCount     = 0
            Findings         = @()
            UnknownCount     = 0
            UnknownChecks    = @()
            ChecksEvaluated  = 4
            ChecksTotal      = 4
            GeneratedAtUtc   = '2026-10-28T12:00:01Z'
        }
    }

    function Write-TestInputs {
        param([string]$Directory, [object]$Posture, [object]$Assessment)
        $null = New-Item -ItemType Directory -Path $Directory -Force
        $postureFile = Join-Path $Directory 'security-posture.json'
        $assessmentFile = Join-Path $Directory 'security-assessment.json'
        $Posture | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $postureFile -Encoding utf8
        $Assessment | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $assessmentFile -Encoding utf8
        return [PSCustomObject]@{ Posture = $postureFile; Assessment = $assessmentFile; Output = (Join-Path $Directory 'security-report.html') }
    }

    function Invoke-TestRenderer {
        param([object]$Paths)
        & $script:generator -PosturePath $Paths.Posture -AssessmentPath $Paths.Assessment -OutputPath $Paths.Output
    }
}

Describe 'SecOpsForge offline HTML report' {
    It 'creates a standalone HTML report from synthetic data' {
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'basic') -Posture (New-TestPosture) -Assessment (New-TestAssessment)
        $result = Invoke-TestRenderer -Paths $paths
        $result.ReportCreated | Should -BeTrue
        $result.Findings | Should -Be 0
        $result.AssessmentStatus | Should -Be 'NoIndicatorsDetected'
        $html = Get-Content -LiteralPath $paths.Output -Raw
        $html | Should -Match 'Security Operations Report'
        $html | Should -Match 'No indicators detected'
        $html | Should -Match 'This is not a guarantee'
        $html | Should -Match 'Identity &amp; access'
        $html | Should -Match 'Defender incidents'
        $html | Should -Match 'Content-Security-Policy'
        $html | Should -Not -Match '(?i)<script[\s>]'
        $html | Should -Not -Match '(?i)<link\s+[^>]*href'
    }

    It 'renders a finding, action and verification safely' {
        $posture = New-TestPosture
        $assessment = New-TestAssessment
        $assessment.Findings = @([PSCustomObject]@{
            RuleId = 'SEC-001'; Severity = 'High'; Category = 'Defender';
            Title = 'Active incidents <script>alert(1)</script>';
            Reason = 'Synthetic incident'; Evidence = 'ActiveIncidents: 1';
            Recommendation = 'Investigate <img src=x onerror=alert(1)>';
            Verification = 'Check the incident status'
        })
        $assessment.FindingCount = 1
        $assessment.AssessmentStatus = 'ReviewRequired'
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'finding') -Posture $posture -Assessment $assessment
        $null = Invoke-TestRenderer -Paths $paths
        $html = Get-Content -LiteralPath $paths.Output -Raw
        $html | Should -Match 'High-priority indicators'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
        $html | Should -Match 'Check the incident status'
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Not -Match '<img src=x onerror='
    }

    It 'shows insufficient data and unknown-check remediation' {
        $assessment = New-TestAssessment
        $assessment.UnknownChecks = @([PSCustomObject]@{
            RuleId='SEC-003'; Category='Intune'; Metric='ConfigurationPolicyCount';
            Reason='Missing counter'; Recommendation='Verify inventory first'
        })
        $assessment.UnknownCount = 1
        $assessment.ChecksEvaluated = 3
        $assessment.AssessmentStatus = 'InsufficientData'
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'unknown') -Posture (New-TestPosture) -Assessment $assessment
        $null = Invoke-TestRenderer -Paths $paths
        $html = Get-Content -LiteralPath $paths.Output -Raw
        $html | Should -Match 'Insufficient data'
        $html | Should -Match 'SEC-003'
        $html | Should -Match 'Verify inventory first'
    }

    It 'treats a missing inventory counter as not reported instead of zero' {
        $posture = New-TestPosture
        $posture.IntuneDevices.PSObject.Properties.Remove('CompliantDevices')
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'missing') -Posture $posture -Assessment (New-TestAssessment)
        $result = Invoke-TestRenderer -Paths $paths
        $result.MissingMetrics | Should -Be 1
        $html = Get-Content -LiteralPath $paths.Output -Raw
        $html | Should -Match 'Not reported'
        $html | Should -Match 'Data gaps require review'
        $html | Should -Match 'devices.CompliantDevices'
    }

    It 'does not expose unrelated raw fields in the HTML' {
        $posture = New-TestPosture
        $posture | Add-Member -NotePropertyName 'TenantId' -NotePropertyValue 'PRIVATE-TENANT-DO-NOT-EMIT'
        $posture.Identity | Add-Member -NotePropertyName 'AccessToken' -NotePropertyValue 'PRIVATE-TOKEN-DO-NOT-EMIT'
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'privacy') -Posture $posture -Assessment (New-TestAssessment)
        $null = Invoke-TestRenderer -Paths $paths
        $html = Get-Content -LiteralPath $paths.Output -Raw
        $html | Should -Not -Match 'PRIVATE-TENANT-DO-NOT-EMIT'
        $html | Should -Not -Match 'PRIVATE-TOKEN-DO-NOT-EMIT'
    }

    It 'backs up an existing HTML report before replacement' {
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'backup') -Posture (New-TestPosture) -Assessment (New-TestAssessment)
        $null = Invoke-TestRenderer -Paths $paths
        $original = Get-Content -LiteralPath $paths.Output -Raw
        $result = Invoke-TestRenderer -Paths $paths
        $result.BackupPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $result.BackupPath | Should -BeTrue
        (Get-Content -LiteralPath $result.BackupPath -Raw) | Should -Be $original
    }

    It 'refuses to write HTML inside the Git repository' {
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'repo-guard') -Posture (New-TestPosture) -Assessment (New-TestAssessment)
        $paths.Output = Join-Path $PSScriptRoot 'DO-NOT-CREATE-security-report.html'
        { Invoke-TestRenderer -Paths $paths } | Should -Throw '*outside the Git repository*'
        Test-Path -LiteralPath $paths.Output | Should -BeFalse
    }

    It 'rejects an incomplete posture document' {
        $posture = New-TestPosture
        $posture.PSObject.Properties.Remove('IntunePolicies')
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'incomplete') -Posture $posture -Assessment (New-TestAssessment)
        { Invoke-TestRenderer -Paths $paths } | Should -Throw '*inventory section*'
        Test-Path -LiteralPath $paths.Output | Should -BeFalse
    }

    It 'rejects inconsistent assessment counts without writing HTML' {
        $assessment = New-TestAssessment
        $assessment.FindingCount = 2
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'counts') -Posture (New-TestPosture) -Assessment $assessment
        { Invoke-TestRenderer -Paths $paths } | Should -Throw '*counts are invalid*'
        Test-Path -LiteralPath $paths.Output | Should -BeFalse
    }

    It 'rejects malformed JSON without writing HTML' {
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'invalid-json') -Posture (New-TestPosture) -Assessment (New-TestAssessment)
        Set-Content -LiteralPath $paths.Assessment -Value '{invalid-json' -Encoding utf8
        { Invoke-TestRenderer -Paths $paths } | Should -Throw '*could not be parsed*'
        Test-Path -LiteralPath $paths.Output | Should -BeFalse
    }

    It 'rejects an unexpected schema version' {
        $posture = New-TestPosture
        $posture.SchemaVersion = '999.0'
        $paths = Write-TestInputs -Directory (Join-Path $TestDrive 'schema') -Posture $posture -Assessment (New-TestAssessment)
        { Invoke-TestRenderer -Paths $paths } | Should -Throw '*Unexpected JSON report schema*'
        Test-Path -LiteralPath $paths.Output | Should -BeFalse
    }
}
