BeforeAll {
    $script:htmlScript = Join-Path $PSScriptRoot '../scripts/New-SecOpsForgeHtmlReport.ps1'
    $script:privateDir = Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports'
}

Describe 'Defender HTML integration' {

    BeforeAll {
        $script:posture = [PSCustomObject]@{
            SchemaVersion = '1.0'
            ReportType = 'SecurityPosture'
            GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            Identity = [PSCustomObject]@{}
            PrivilegedAccess = [PSCustomObject]@{}
            IntuneDevices = [PSCustomObject]@{}
            IntunePolicies = [PSCustomObject]@{}
            DefenderIncidents = [PSCustomObject]@{}
        }

        $script:assessment = [PSCustomObject]@{
            SchemaVersion = '1.0'
            AssessmentType = 'SecurityPostureAssessment'
            AssessmentStatus = 'NoIndicatorsDetected'
            FindingCount = 0
            Findings = @()
            UnknownCount = 0
            UnknownChecks = @()
            ChecksEvaluated = 4
            ChecksTotal = 4
            GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    BeforeEach {
        $script:testDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:testDir -Force | Out-Null

        $script:posturePath = Join-Path $script:testDir 'posture.json'
        $script:assessmentPath = Join-Path $script:testDir 'assessment.json'
        $script:htmlPath = Join-Path $script:testDir 'report.html'

        $script:postureCopy = $script:posture |
            ConvertTo-Json -Depth 10 |
            ConvertFrom-Json

        $script:assessment |
            ConvertTo-Json -Depth 10 |
            Set-Content $script:assessmentPath -Encoding utf8
    }

    It 'Displays five inventory areas without Defender devices' {
        $script:postureCopy.PSObject.Properties.Remove('DefenderDevices')

        $script:postureCopy |
            ConvertTo-Json -Depth 10 |
            Set-Content $script:posturePath -Encoding utf8

        & $script:htmlScript `
            -PosturePath $script:posturePath `
            -AssessmentPath $script:assessmentPath `
            -OutputPath $script:htmlPath | Out-Null

        $html = Get-Content $script:htmlPath -Raw

        $html | Should -Match 'Inventory areas included'
        $html | Should -Match "class='kpi-value'>5</div>"
        $html | Should -Not -Match "id='defenderdevices'"
    }

    It 'Displays six areas without exposing Defender device names' {
        $script:postureCopy | Add-Member `
            -NotePropertyName DefenderDevices `
            -NotePropertyValue ([PSCustomObject]@{
                TotalDevices = 1
                Devices = @(
                    [PSCustomObject]@{
                        ComputerName = 'private-test-device'
                        OnboardingStatus = 'Onboarded'
                        HealthStatus = 'Active'
                        ExposureLevel = 'Medium'
                    }
                )
            }) -Force

        $script:postureCopy |
            ConvertTo-Json -Depth 10 |
            Set-Content $script:posturePath -Encoding utf8

        & $script:htmlScript `
            -PosturePath $script:posturePath `
            -AssessmentPath $script:assessmentPath `
            -OutputPath $script:htmlPath | Out-Null

        $html = Get-Content $script:htmlPath -Raw

        $html | Should -Match "class='kpi-value'>6</div>"
        $html | Should -Match "id='defenderdevices'"
        $html | Should -Not -Match 'private-test-device'
    }

    It 'Rejects inconsistent Defender device counts' {
        $script:postureCopy | Add-Member `
            -NotePropertyName DefenderDevices `
            -NotePropertyValue ([PSCustomObject]@{
                TotalDevices = 2
                Devices = @(
                    [PSCustomObject]@{
                        ComputerName = 'test-device'
                    }
                )
            }) -Force

        $script:postureCopy |
            ConvertTo-Json -Depth 10 |
            Set-Content $script:posturePath -Encoding utf8

        {
            & $script:htmlScript `
                -PosturePath $script:posturePath `
                -AssessmentPath $script:assessmentPath `
                -OutputPath $script:htmlPath
        } | Should -Throw '*Invalid Defender device inventory data*'

        Test-Path $script:htmlPath | Should -BeFalse
    }
}
