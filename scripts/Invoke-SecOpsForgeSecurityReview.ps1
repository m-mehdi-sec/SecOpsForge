
[CmdletBinding()]
param([string]$DefenderAccessToken)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot '../src/SecOpsForge/SecOpsForge.psm1'
$reportDirectory = Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports'

$repoRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..')
).TrimEnd('\', '/')

$outputRoot = [System.IO.Path]::GetFullPath(
    $reportDirectory
).TrimEnd('\', '/')

if (
    $outputRoot.Equals(
        $repoRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or
    $outputRoot.StartsWith(
        $repoRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase
    )
) {
    throw 'Reports must be stored outside the Git repository.'
}

Import-Module $modulePath -Force -ErrorAction Stop

$tempPosture = $null
$tempAssessment = $null

try {
    $report = New-SecOpsForgeSecurityPostureReport -DefenderAccessToken $DefenderAccessToken -ErrorAction Stop
    $assessment = Get-SecOpsForgeSecurityAssessment `
        -Report $report `
        -ErrorAction Stop

    $postureJson = $report | ConvertTo-Json -Depth 10 -ErrorAction Stop
    $assessmentJson = $assessment | ConvertTo-Json -Depth 10 -ErrorAction Stop

    # Validate both JSON documents before writing files.
    $postureJson | ConvertFrom-Json -ErrorAction Stop | Out-Null
    $assessmentJson | ConvertFrom-Json -ErrorAction Stop | Out-Null

    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        New-Item -ItemType Directory `
            -Path $reportDirectory `
            -Force `
            -ErrorAction Stop | Out-Null
    }

    $posturePath = Join-Path $reportDirectory 'security-posture.json'
    $assessmentPath = Join-Path $reportDirectory 'security-assessment.json'

    $runId = [guid]::NewGuid().ToString('N')

    $tempPosture = Join-Path $reportDirectory "$runId-posture.tmp"
    $tempAssessment = Join-Path $reportDirectory "$runId-assessment.tmp"

    $encoding = [System.Text.UTF8Encoding]::new($false)

    # Stage both reports before replacing existing files.
    [System.IO.File]::WriteAllText(
        $tempPosture,
        $postureJson,
        $encoding
    )

    [System.IO.File]::WriteAllText(
        $tempAssessment,
        $assessmentJson,
        $encoding
    )

    # Replace each report only after both temporary files exist.
    [System.IO.File]::Move(
        $tempPosture,
        $posturePath,
        $true
    )

    [System.IO.File]::Move(
        $tempAssessment,
        $assessmentPath,
        $true
    )

    [PSCustomObject]@{
        ReviewSucceeded = $true
        ReportSections = 5 + [int]($null -ne $report.PSObject.Properties['DefenderDevices'])
        FindingCount = $assessment.FindingCount
        PostureExported = $true
        AssessmentExported = $true
    }
}
catch {
    throw 'Security review failed. Check the Graph connection and report configuration.'
}
finally {
    foreach ($tempFile in @($tempPosture, $tempAssessment)) {
        if ($tempFile -and (Test-Path -LiteralPath $tempFile)) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}
