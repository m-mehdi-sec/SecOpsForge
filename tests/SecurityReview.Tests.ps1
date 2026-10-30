
BeforeAll {
    $script:reviewScript = Join-Path $PSScriptRoot '../scripts/Invoke-SecOpsForgeSecurityReview.ps1'

    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Invoke-SecOpsForgeSecurityReview' {

    BeforeEach {
        $script:originalUserProfile = $env:USERPROFILE
        $env:USERPROFILE = $TestDrive

        # Start each test with a clean temporary report directory.
        $testReportDirectory = Join-Path $TestDrive 'SecOpsForge-Private-Reports'

        if (Test-Path -LiteralPath $testReportDirectory) {
            Remove-Item -LiteralPath $testReportDirectory -Recurse -Force
        }

        Mock Import-Module {}

        Mock New-SecOpsForgeSecurityPostureReport {
            [PSCustomObject]@{
                SchemaVersion = '1.0'
                ReportType = 'SecurityPosture'
                Identity = [PSCustomObject]@{
                    TotalUsers = 3
                }
            }
        }

        Mock Get-SecOpsForgeSecurityAssessment {
            [PSCustomObject]@{
                SchemaVersion = '1.0'
                AssessmentType = 'SecurityPostureAssessment'
                FindingCount = 0
                Findings = @()
            }
        }
    }

    AfterEach {
        $env:USERPROFILE = $script:originalUserProfile
    }

    It 'Runs the security review successfully' {
        $result = & $script:reviewScript

        $result.ReviewSucceeded | Should -BeTrue
        $result.ReportSections | Should -Be 5
        $result.FindingCount | Should -Be 0
    }

    It 'Reports six inventory areas with Defender data' {
        $testToken = 'synthetic-test-token'

        Mock New-SecOpsForgeSecurityPostureReport {
            param($DefenderAccessToken)

            [PSCustomObject]@{
                SchemaVersion = '1.0'
                ReportType = 'SecurityPosture'
                Identity = [PSCustomObject]@{
                    TotalUsers = 3
                }
                DefenderDevices = [PSCustomObject]@{
                    TotalDevices = 1
                    Devices = @()
                }
            }
        }

        $result = & $script:reviewScript -DefenderAccessToken $testToken

        $result.ReviewSucceeded | Should -BeTrue
        $result.ReportSections | Should -Be 6

        Should -Invoke New-SecOpsForgeSecurityPostureReport `
            -Times 1 `
            -Exactly `
            -ParameterFilter {
                $DefenderAccessToken -eq $testToken
            }
    }
    It 'Exports both JSON reports' {
        & $script:reviewScript | Out-Null

        $directory = Join-Path $TestDrive 'SecOpsForge-Private-Reports'

        Test-Path (Join-Path $directory 'security-posture.json') |
            Should -BeTrue

        Test-Path (Join-Path $directory 'security-assessment.json') |
            Should -BeTrue
    }

    It 'Creates valid JSON documents' {
        & $script:reviewScript | Out-Null

        $directory = Join-Path $TestDrive 'SecOpsForge-Private-Reports'

        $posture = Get-Content (
            Join-Path $directory 'security-posture.json'
        ) -Raw | ConvertFrom-Json

        $assessment = Get-Content (
            Join-Path $directory 'security-assessment.json'
        ) -Raw | ConvertFrom-Json

        $posture.ReportType | Should -Be 'SecurityPosture'
        $assessment.AssessmentType | Should -Be 'SecurityPostureAssessment'
    }

    It 'Uses the assessment result in the summary' {
        Mock Get-SecOpsForgeSecurityAssessment {
            [PSCustomObject]@{
                AssessmentType = 'SecurityPostureAssessment'
                FindingCount = 2
                Findings = @()
            }
        }

        $result = & $script:reviewScript

        $result.FindingCount | Should -Be 2
    }

    It 'Fails safely when the assessment fails' {
        Mock Get-SecOpsForgeSecurityAssessment {
            throw 'Simulated assessment failure'
        }

        {
            & $script:reviewScript
        } | Should -Throw '*Security review failed*'

        $directory = Join-Path $TestDrive 'SecOpsForge-Private-Reports'

        Test-Path (Join-Path $directory 'security-posture.json') |
            Should -BeFalse

        Test-Path (Join-Path $directory 'security-assessment.json') |
            Should -BeFalse
    }

    It 'Replaces existing reports with valid JSON' {
        $directory = Join-Path $TestDrive 'SecOpsForge-Private-Reports'

        New-Item -ItemType Directory -Path $directory -Force |
            Out-Null

        $posturePath = Join-Path $directory 'security-posture.json'
        $assessmentPath = Join-Path $directory 'security-assessment.json'

        Set-Content -LiteralPath $posturePath -Value 'old report'
        Set-Content -LiteralPath $assessmentPath -Value 'old assessment'

        & $script:reviewScript | Out-Null

        $posture = Get-Content -LiteralPath $posturePath -Raw |
            ConvertFrom-Json

        $assessment = Get-Content -LiteralPath $assessmentPath -Raw |
            ConvertFrom-Json

        $posture.ReportType | Should -Be 'SecurityPosture'
        $assessment.AssessmentType | Should -Be 'SecurityPostureAssessment'
    }

    It 'Removes temporary files after successful export' {
        & $script:reviewScript | Out-Null

        $directory = Join-Path $TestDrive 'SecOpsForge-Private-Reports'

        $temporaryFiles = @(
            Get-ChildItem -LiteralPath $directory -Filter '*.tmp' -File
        )

        $temporaryFiles.Count | Should -Be 0
    }
}
