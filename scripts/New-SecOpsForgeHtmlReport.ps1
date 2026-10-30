[CmdletBinding()]
param(
    [string]$PosturePath = (Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports/security-posture.json'),
    [string]$AssessmentPath = (Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports/security-assessment.json'),
    [string]$OutputPath = (Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports/security-report.html')
)

$ErrorActionPreference = 'Stop'

function Get-ReportField {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return ,$property.Value
}

function ConvertTo-SafeHtml {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Test-ValidCounter {
    param([AllowNull()][object]$Value)
    return (
        ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) -and
        $Value -ge 0
    )
}

function Get-SafeCounter {
    param([object]$Section, [string]$Field, [string]$SectionName)
    $value = Get-ReportField -Object $Section -Name $Field
    if (Test-ValidCounter $value) { return [string]$value }
    $script:missingMetrics.Add("$SectionName.$Field") | Out-Null
    return 'Not reported'
}

function New-MetricCard {
    param([string]$Name, [string]$Value)
    $safeName = ConvertTo-SafeHtml $Name
    $safeValue = ConvertTo-SafeHtml $Value
    return "<div class='metric'><div class='metric-value'>$safeValue</div><div class='metric-label'>$safeName</div></div>"
}

function New-InventorySection {
    param([string]$Id, [string]$Title, [string]$Description, [object]$Section, [string[]]$Fields, [string[]]$Labels)
    $tiles = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Fields.Count; $i++) {
        $value = Get-SafeCounter -Section $Section -Field $Fields[$i] -SectionName $Id
        $tiles.Add((New-MetricCard -Name $Labels[$i] -Value $value))
    }
    $safeId = ConvertTo-SafeHtml $Id
    $safeTitle = ConvertTo-SafeHtml $Title
    $safeDescription = ConvertTo-SafeHtml $Description
    $productIcon = Get-ProductIcon -Id $Id
    return "<section class='panel inventory' id='$safeId'><div class='section-title'><div class='product-heading'>$productIcon<h2>$safeTitle</h2></div><p>$safeDescription</p></div><div class='metric-grid'>$($tiles -join "`n")</div></section>"
}

function Get-ProductIcon {
    param([string]$Id)
    $iconNames = @{
        identity = 'entra-id.svg'
        privileged = 'entra-id.svg'
        devices = 'intune.svg'
        policies = 'intune.svg'
        incidents = 'defender-xdr.svg'
        defenderdevices = 'defender-xdr.svg'
    }
    $name = $iconNames[$Id]
    if (-not $name) { return '' }
    $iconPath = Join-Path (Join-Path $env:USERPROFILE 'SecOpsForge-Private-Reports\BrandAssets') $name
    if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) { return '' }
    $file = Get-Item -LiteralPath $iconPath
    if ($file.Length -gt 100KB -or $file.Length -eq 0) {
        throw "Invalid product icon size: $name"
    }
    $svg = [System.IO.File]::ReadAllText($iconPath)
    # Parse XML with DTDs and external resolution disabled. Reject unsupported SVG
    # constructs instead of trying to sanitize arbitrary active SVG content.
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 102400
    $allowedElements = @('svg','g','path','rect','circle','ellipse','line','polyline','polygon',
        'defs','linearGradient','radialGradient','stop','clipPath','mask','title','desc')
    $svgNamespace = 'http://www.w3.org/2000/svg'
    try {
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($svg), $settings)
        try {
            $document = [System.Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($reader)
        } finally {
            $reader.Dispose()
        }
        if ($null -eq $document.DocumentElement -or
            $document.DocumentElement.LocalName -cne 'svg' -or
            $document.DocumentElement.NamespaceURI -cne $svgNamespace) {
            throw 'Invalid SVG root.'
        }
        $nodes = @($document.SelectNodes('//*'))
        foreach ($node in $nodes) {
            if ($node.NamespaceURI -cne $svgNamespace -or
                $node.LocalName -cnotin $allowedElements) {
                throw 'Disallowed SVG element.'
            }
            foreach ($attribute in $node.Attributes) {
                if ($attribute.NamespaceURI -eq 'http://www.w3.org/2000/xmlns/') { continue }
                if ($attribute.NamespaceURI -ne '' -and
                    $attribute.NamespaceURI -ne 'http://www.w3.org/XML/1998/namespace') {
                    throw 'Disallowed SVG attribute namespace.'
                }
                # Permit only fragment-local SVG paint references such as
                # fill="url(#gradient1)". External URL references remain blocked.
                $valueWithoutLocalPaintRefs = [regex]::Replace(
                    $attribute.Value,
                    'url\s*\(\s*#[A-Za-z_][A-Za-z0-9_.:-]*\s*\)',
                    '',
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                )
                if ($attribute.LocalName -match '^(?i:on[a-z]+|href|style)$' -or
                    $valueWithoutLocalPaintRefs -match '(?i)url\s*\(|https?\s*:\s*//|javascript\s*:|data\s*:|@import|expression\s*\(') {
                    throw 'Disallowed SVG attribute.'
                }
            }
        }
        if ($document.SelectNodes('//comment() | //processing-instruction()').Count -gt 0) {
            throw 'Disallowed SVG metadata.'
        }
    } catch {
        throw "Unsafe or invalid product SVG: $name"
    }
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($svg))
    $alt = switch ($Id) {
        { $_ -in 'identity','privileged' } { 'Microsoft Entra ID' }
        { $_ -in 'devices','policies' } { 'Microsoft Intune' }
        default { 'Microsoft Defender XDR' }
    }
    return "<img class='product-icon' src='data:image/svg+xml;base64,$base64' alt='$alt' width='38' height='38'>"
}

function Get-SeverityStyle {
    param([AllowNull()][object]$Severity)
    switch ([string]$Severity) {
        'High' { return 'high' }
        'Medium' { return 'medium' }
        'Low' { return 'low' }
        'Informational' { return 'info' }
        default { return 'unknown' }
    }
}

function Assert-OutsideRepository {
    param([string]$Path, [string]$RepositoryRoot, [string]$Purpose)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
    if (
        $fullPath.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "$Purpose must be outside the Git repository."
    }
    return $fullPath
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$postureFullPath = Assert-OutsideRepository -Path $PosturePath -RepositoryRoot $repositoryRoot -Purpose 'Posture JSON'
$assessmentFullPath = Assert-OutsideRepository -Path $AssessmentPath -RepositoryRoot $repositoryRoot -Purpose 'Assessment JSON'
$outputFullPath = Assert-OutsideRepository -Path $OutputPath -RepositoryRoot $repositoryRoot -Purpose 'HTML report'

if ($postureFullPath -eq $outputFullPath -or $assessmentFullPath -eq $outputFullPath) {
    throw 'Output must not replace an input JSON report.'
}
if (-not (Test-Path -LiteralPath $postureFullPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $assessmentFullPath -PathType Leaf)) {
    throw 'Required private JSON reports were not found.'
}

foreach ($path in @($postureFullPath, $assessmentFullPath)) {
    $fileInfo = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($fileInfo.Length -gt 4MB) { throw 'JSON report exceeds the 4 MB input limit.' }
}

try {
    $posture = Get-Content -LiteralPath $postureFullPath -Raw -Encoding utf8 -ErrorAction Stop |
        ConvertFrom-Json -Depth 16 -ErrorAction Stop
    $assessment = Get-Content -LiteralPath $assessmentFullPath -Raw -Encoding utf8 -ErrorAction Stop |
        ConvertFrom-Json -Depth 16 -ErrorAction Stop
}
catch {
    throw 'Private JSON report could not be parsed. No HTML was written.'
}

if ((Get-ReportField $posture 'SchemaVersion') -ne '1.0' -or
    (Get-ReportField $posture 'ReportType') -ne 'SecurityPosture' -or
    (Get-ReportField $assessment 'SchemaVersion') -ne '1.0' -or
    (Get-ReportField $assessment 'AssessmentType') -ne 'SecurityPostureAssessment') {
    throw 'Unexpected JSON report schema or report type.'
}

$sections = [ordered]@{}
foreach ($name in @('Identity','PrivilegedAccess','IntuneDevices','IntunePolicies','DefenderIncidents')) {
    $section = Get-ReportField $posture $name
    if ($null -eq $section -or $section -is [string] -or $section -is [array]) {
        throw "Required inventory section $name is missing or invalid."
    }
    $sections[$name] = $section
}

$rawFindings = Get-ReportField $assessment 'Findings'
$rawUnknown = Get-ReportField $assessment 'UnknownChecks'
if ($rawFindings -isnot [array] -or $rawUnknown -isnot [array]) {
    throw 'Assessment finding collections are missing or invalid.'
}
$findings = @($rawFindings)
$unknownChecks = @($rawUnknown)
$findingCount = Get-ReportField $assessment 'FindingCount'
$unknownCount = Get-ReportField $assessment 'UnknownCount'
$checksEvaluated = Get-ReportField $assessment 'ChecksEvaluated'
$checksTotal = Get-ReportField $assessment 'ChecksTotal'
if (-not (Test-ValidCounter $findingCount) -or -not (Test-ValidCounter $unknownCount) -or
    -not (Test-ValidCounter $checksEvaluated) -or -not (Test-ValidCounter $checksTotal) -or
    $findingCount -ne $findings.Count -or $unknownCount -ne $unknownChecks.Count -or
    ($checksEvaluated + $unknownCount) -ne $checksTotal) {
    throw 'Assessment counts are invalid or inconsistent.'
}

$expectedStatus = if ($findingCount -gt 0 -and $unknownCount -gt 0) {
    'ReviewRequiredWithDataGaps'
} elseif ($findingCount -gt 0) {
    'ReviewRequired'
} elseif ($unknownCount -gt 0) {
    'InsufficientData'
} else {
    'NoIndicatorsDetected'
}
if ((Get-ReportField $assessment 'AssessmentStatus') -cne $expectedStatus) {
    throw 'Assessment status does not match its findings and data gaps.'
}

$script:missingMetrics = [System.Collections.Generic.List[string]]::new()
$inventoryHtml = @(
    New-InventorySection -Id 'identity' -Title 'Identity & access' -Description 'Aggregated Microsoft Entra ID account inventory.' `
        -Section $sections.Identity -Fields @('TotalUsers','EnabledUsers','DisabledUsers','GuestUsers','UnlicensedUsers') `
        -Labels @('Total users','Enabled','Disabled','Guest accounts','Unlicensed')
    New-InventorySection -Id 'privileged' -Title 'Privileged access' -Description 'Administrative role assignment indicators; individual identities are not included.' `
        -Section $sections.PrivilegedAccess -Fields @('TotalRoleAssignments','GlobalAdminAssignments','OtherRoleAssignments','UniquePrivilegedPrincipals') `
        -Labels @('Role assignments','Global admin assignments','Other assignments','Unique privileged principals')
    New-InventorySection -Id 'devices' -Title 'Intune managed devices' -Description 'Device enrollment and reported compliance state.' `
        -Section $sections.IntuneDevices -Fields @('TotalManagedDevices','WindowsDevices','CompliantDevices','NoncompliantDevices','OtherCompliance') `
        -Labels @('Managed devices','Windows devices','Compliant','Noncompliant','Other / unknown compliance')
    New-InventorySection -Id 'policies' -Title 'Intune configuration policies' -Description 'Modern configurationPolicies endpoint only; other Intune policy types are outside this count.' `
        -Section $sections.IntunePolicies -Fields @('ConfigurationPolicyCount') -Labels @('Modern configuration policies')
    New-InventorySection -Id 'incidents' -Title 'Microsoft Defender incidents' -Description 'Aggregated incident status and severity, not a complete endpoint security assessment.' `
        -Section $sections.DefenderIncidents -Fields @('TotalIncidents','ActiveIncidents','ResolvedIncidents','HighSeverity','MediumSeverity','LowSeverity','InformationalSeverity','OtherSeverity') `
        -Labels @('Total incidents','Active','Resolved','High severity','Medium severity','Low severity','Informational','Other severity')
) -join "`n"

# Optional Defender device inventory.
$defenderDeviceSection = Get-ReportField $posture 'DefenderDevices'
$inventoryAreaCount = 5

if ($null -ne $defenderDeviceSection) {
    if ($defenderDeviceSection -is [string] -or
        $defenderDeviceSection -is [array]) {
        throw 'Invalid Defender device inventory section.'
    }

    $totalDefenderDevices = Get-ReportField $defenderDeviceSection 'TotalDevices'
    $defenderDeviceRecords = Get-ReportField $defenderDeviceSection 'Devices'

    if (-not (Test-ValidCounter $totalDefenderDevices) -or
        $defenderDeviceRecords -isnot [array] -or
        $totalDefenderDevices -ne $defenderDeviceRecords.Count) {
        throw 'Invalid Defender device inventory data.'
    }

    $inventoryAreaCount = 6

    $inventoryHtml += "`n" + (
        New-InventorySection -Id 'defenderdevices' `
            -Title 'Microsoft Defender devices' `
            -Description 'Read-only Defender endpoint inventory. Individual device names are not displayed.' `
            -Section $defenderDeviceSection `
            -Fields @('TotalDevices') `
            -Labels @('Defender devices')
    )
}

$severityCounts = [ordered]@{ High = 0; Medium = 0; Low = 0; Informational = 0; Unknown = 0 }
$findingRows = [System.Collections.Generic.List[string]]::new()
foreach ($finding in $findings) {
    if ($null -eq $finding -or $finding -is [string] -or $finding -is [array]) {
        throw 'Assessment contains an invalid finding.'
    }
    $severity = [string](Get-ReportField $finding 'Severity')
    $severityClass = Get-SeverityStyle $severity
    if ($severityClass -eq 'unknown') { $severityCounts.Unknown++ }
    else { $severityCounts[$severity]++ }
    $rule = ConvertTo-SafeHtml (Get-ReportField $finding 'RuleId')
    $title = ConvertTo-SafeHtml (Get-ReportField $finding 'Title')
    $category = ConvertTo-SafeHtml (Get-ReportField $finding 'Category')
    $level = ConvertTo-SafeHtml $(if ($severity) { $severity } else { 'Unknown' })
    $reason = ConvertTo-SafeHtml (Get-ReportField $finding 'Reason')
    $evidence = ConvertTo-SafeHtml (Get-ReportField $finding 'Evidence')
    $recommendation = ConvertTo-SafeHtml (Get-ReportField $finding 'Recommendation')
    $verification = ConvertTo-SafeHtml (Get-ReportField $finding 'Verification')
    $findingCard = @"
<article class='finding'>
    <div class='finding-heading'><span class='rule'>$rule</span><span class='pill $severityClass'>$level</span><span class='category'>$category</span></div>
    <h3>$title</h3><p>$reason</p>
    <details open><summary>Evidence, recommended action &amp; verification</summary>
    <div class='finding-detail'><strong>Evidence</strong><span>$evidence</span></div>
    <div class='finding-detail'><strong>Recommended action</strong><span>$recommendation</span></div>
    <div class='finding-detail'><strong>Verification</strong><span>$verification</span></div>
    </details>
</article>
"@
    $findingRows.Add($findingCard)
}
if ($findingRows.Count -eq 0) {
    $findingRows.Add("<div class='empty-state'>No indicators were detected by the currently implemented rules. This is not a guarantee that the environment is secure.</div>")
}

$unknownRows = [System.Collections.Generic.List[string]]::new()
foreach ($check in $unknownChecks) {
    if ($null -eq $check -or $check -is [string] -or $check -is [array]) {
        throw 'Assessment contains an invalid unknown-check entry.'
    }
    $rule = ConvertTo-SafeHtml (Get-ReportField $check 'RuleId')
    $metric = ConvertTo-SafeHtml (Get-ReportField $check 'Metric')
    $reason = ConvertTo-SafeHtml (Get-ReportField $check 'Reason')
    $action = ConvertTo-SafeHtml (Get-ReportField $check 'Recommendation')
    $unknownRows.Add("<li><strong>$rule - $metric</strong><span>$reason $action</span></li>")
}
foreach ($metric in $script:missingMetrics) {
    $unknownRows.Add("<li><strong>Missing inventory metric</strong><span>$(ConvertTo-SafeHtml $metric) is missing or invalid in the JSON input.</span></li>")
}
if ($unknownRows.Count -eq 0) {
    $unknownRows.Add('<li><strong>No missing indicators reported</strong><span>The four implemented assessment checks returned usable counters. The assessment does not cover all possible security risks.</span></li>')
}

$highestLevel = if ($findingCount -eq 0 -and $unknownCount -gt 0) {
    'Insufficient data'
} elseif ($severityCounts.High -gt 0) {
    'High-priority indicators'
} elseif ($severityCounts.Medium -gt 0) {
    'Medium-priority indicators'
} elseif ($severityCounts.Low -gt 0) {
    'Low-priority indicators'
} elseif ($findingCount -gt 0) {
    'Indicators require review'
} else {
    'No indicators detected'
}
if ($script:missingMetrics.Count -gt 0 -and $findingCount -eq 0) { $highestLevel = 'Data gaps require review' }
$summary = switch ($expectedStatus) {
    'ReviewRequiredWithDataGaps' { 'Security indicators require investigation and one or more checks could not be evaluated.' }
    'ReviewRequired' { 'At least one rule-based security indicator requires investigation.' }
    'InsufficientData' { 'The assessment could not evaluate all implemented checks. Do not interpret missing information as a passing result.' }
    default { 'The currently implemented rules detected no security indicators. This does not establish that the tenant is risk-free.' }
}
if ($script:missingMetrics.Count -gt 0) {
    $summary += ' Additional inventory metrics are missing or invalid.'
}
$displayStatus = ConvertTo-SafeHtml $highestLevel
$displaySummary = ConvertTo-SafeHtml $summary
$statusDetail = ConvertTo-SafeHtml $displayStatus
$generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
$postureGenerated = ConvertTo-SafeHtml (Get-ReportField $posture 'GeneratedAtUtc')
$assessmentGenerated = ConvertTo-SafeHtml (Get-ReportField $assessment 'GeneratedAtUtc')

$severityBars = [System.Collections.Generic.List[string]]::new()
foreach ($key in $severityCounts.Keys) {
    $count = $severityCounts[$key]
    $width = if ($findingCount -gt 0) { [Math]::Round(($count / $findingCount) * 100, 1) } else { 0 }
    $class = Get-SeverityStyle $key
    $severityBars.Add("<div class='bar-row'><span>$(ConvertTo-SafeHtml $key)</span><div class='bar-track'><div class='bar-fill $class' style='width: $width%'></div></div><strong>$count</strong></div>")
}

$html = @"
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv='Content-Security-Policy' content="default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; connect-src 'none'; img-src data:; script-src 'none'; style-src 'unsafe-inline'">
<meta name='referrer' content='no-referrer'>
<title>SecOpsForge | Security Operations Report</title>
<style>
:root { color-scheme: dark; --bg:#08111e; --surface:#111e30; --surface2:#17263a; --line:#26384e; --text:#ebf3ff; --muted:#98aec9; --accent:#44c7c1; --high:#ff657c; --medium:#f3b85f; --low:#68bbfb; --info:#8f9bee; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin:0; background:var(--bg); color:var(--text); font: 15px/1.55 'Segoe UI',Arial,sans-serif; }
body:before { content:''; position:fixed; inset:0; z-index:-1; background:radial-gradient(ellipse at 80% 0%,#142b42 0%,transparent 48%); pointer-events:none; }
a { color:#a5ebe4; text-decoration:none; }
a:hover { text-decoration:underline; }
.shell { display:grid; grid-template-columns:238px minmax(0,1fr); min-height:100vh; }
.sidebar { position:sticky; top:0; align-self:start; height:100vh; padding:30px 20px; border-right:1px solid var(--line); background:#0b1727; }
.brand { display:flex; align-items:center; gap:12px; margin:0 0 38px; }
.mark { display:grid; place-items:center; width:40px; height:40px; border:1px solid #357b81; border-radius:12px; font-weight:800; color:#70e5dc; background:#12353c; }
.brand strong { display:block; font-size:17px; letter-spacing:.1px; }
.brand small { color:var(--muted); font-size:11px; letter-spacing:1.4px; text-transform:uppercase; }
.nav-label { margin:25px 10px 9px; text-transform:uppercase; letter-spacing:1.5px; font-size:10px; color:#65809e; }
nav a { display:block; padding:10px 12px; margin:2px 0; border-radius:8px; color:#afbed2; font-size:13px; }
nav a:hover { background:#172b41; color:white; text-decoration:none; }
.sidebar-note { margin-top:auto; border-top:1px solid var(--line); padding:18px 8px; color:var(--muted); font-size:12px; }
.main { max-width:1460px; min-width:0; width:100%; margin:0 auto; padding:35px clamp(18px,4vw,62px) 60px; }
.topline { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px; color:#99b2c9; font-size:12px; letter-spacing:.8px; text-transform:uppercase; }
.classification { color:#9be1dd; border:1px solid #2d6f71; background:#123237; border-radius:6px; padding:5px 11px; font-size:11px; }
h1 { margin:25px 0 5px; font-size:clamp(30px,3.8vw,47px); letter-spacing:-1.6px; line-height:1.15; }
.subtitle { margin:0 0 29px; color:var(--muted); font-size:15px; }
.hero { display:grid; grid-template-columns:1.5fr 1fr; gap:18px; }
.panel { background:linear-gradient(135deg,#14243a,#101c2d); border:1px solid var(--line); border-radius:15px; padding:24px; box-shadow:0 8px 25px #00000018; }
.status { border-left:4px solid var(--accent); background:linear-gradient(120deg,#14313d,#122137); }
.eyebrow { text-transform:uppercase; letter-spacing:1.8px; font-size:11px; font-weight:700; color:var(--accent); }
.status h2 { font-size:27px; margin:14px 0 12px; letter-spacing:-.5px; }
.status p { color:#bfd2e2; margin:0; }
.meta { display:grid; gap:12px; align-content:center; }
.meta div { display:flex; justify-content:space-between; gap:18px; border-bottom:1px solid var(--line); padding-bottom:11px; font-size:12px; }
.meta span { color:var(--muted); }
.meta strong { text-align:right; overflow-wrap:anywhere; }
.kpis { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:19px 0 33px; }
.kpi { background:var(--surface); border:1px solid var(--line); border-radius:13px; padding:18px 20px; }
.kpi-value { font-size:29px; font-weight:750; letter-spacing:-1px; line-height:1.3; }
.kpi-label { font-size:12px; color:var(--muted); margin-top:5px; }
.section-title { margin:0 0 19px; }
.section-title h2 { font-size:20px; margin:0 0 5px; letter-spacing:-.3px; }
.section-title p { color:var(--muted); font-size:13px; margin:0; }
.content-section { margin:30px 0; }
.split { display:grid; grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr); gap:18px; }
.pill { display:inline-block; padding:4px 10px; border-radius:99px; border:1px solid; font-size:11px; font-weight:750; }
.pill.high { color:var(--high); border-color:#844052; background:#3b1a29; }
.pill.medium { color:var(--medium); border-color:#81603a; background:#342a1e; }
.pill.low { color:var(--low); border-color:#366887; background:#182f41; }
.pill.info { color:var(--info); border-color:#494b7d; background:#252442; }
.pill.unknown { color:#e3e6ec; border-color:#657181; background:#2b3440; }
.finding { background:#0c1929; border:1px solid var(--line); border-radius:11px; padding:19px; margin-top:13px; }
.finding-heading { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
.rule { font:700 12px Consolas,monospace; color:#78dbd5; }
.category { color:var(--muted); font-size:12px; }
.finding h3 { margin:12px 0 7px; font-size:17px; }
.finding p { color:#b8cbda; margin:0 0 13px; font-size:13px; }
.finding-detail { display:grid; grid-template-columns:125px 1fr; gap:12px; padding:9px 0; border-top:1px solid #223348; font-size:13px; overflow-wrap:anywhere; }
.finding-detail strong { color:#8fb2ca; }
.finding-detail span { color:#dbe7f5; }
.empty-state { color:#b5c9d9; padding:22px; background:#0d1d2e; border:1px dashed #33506a; border-radius:10px; }
.bar-row { display:grid; grid-template-columns:100px 1fr 26px; align-items:center; gap:13px; margin:17px 0; font-size:12px; color:#b7c9d8; }
.bar-row strong { text-align:right; }
.bar-track { height:9px; overflow:hidden; border-radius:99px; background:#263a50; }
.bar-fill { height:100%; border-radius:99px; background:#6a849c; }
.bar-fill.high { background:var(--high); }.bar-fill.medium { background:var(--medium); }.bar-fill.low { background:var(--low); }.bar-fill.info { background:var(--info); }
.inventory { margin:0; align-self:start; }
.product-heading { display:flex; align-items:center; gap:13px; margin-bottom:7px; }
.product-heading h2 { margin:0; }
.product-icon { width:38px; height:38px; flex:none; object-fit:contain; }
.inventory-grid { align-items:start; }

.inventory-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px; }
.inventory-grid .inventory:last-child { grid-column:1 / -1; }
.metric-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); gap:12px; }
.metric { border:1px solid #263b51; background:#0c1b2c; border-radius:11px; padding:16px; min-width:0; }
.metric-value { font-size:23px; font-weight:730; line-height:1.2; overflow-wrap:anywhere; }
.metric-value:has(+ .metric-label) { font-variant-numeric:tabular-nums; }
.metric-label { margin-top:8px; font-size:12px; color:var(--muted); }
.quality-list { list-style:none; padding:0; margin:0; }
.quality-list li { display:grid; gap:4px; padding:13px 0; border-bottom:1px solid var(--line); font-size:13px; }
.quality-list li strong { color:#dfedfb; overflow-wrap:anywhere; }
.quality-list li span { color:#a8c0d2; overflow-wrap:anywhere; }
.limitations { padding-left:20px; color:#b2c7d8; font-size:13px; }
.limitations li { margin:9px 0; }
footer { margin-top:38px; padding-top:21px; border-top:1px solid var(--line); color:#7e9ab3; font-size:12px; }
/* Dashboard refinement: offline-only, no scripts or external assets. */
:root { --focus:#8cf3eb; }
:focus-visible { outline:2px solid var(--focus); outline-offset:3px; }
.sidebar { display:flex; flex-direction:column; }
.sidebar-note { margin-top:auto; }
nav a { transition:background .16s ease,color .16s ease; }
nav a:focus-visible { background:#172b41; }
.kpi { position:relative; overflow:hidden; }
.kpi:before { content:''; position:absolute; inset:0 auto 0 0; width:3px; background:#367d8a; }
.kpi:nth-child(2):before { background:#6888cb; }
.kpi:nth-child(3):before { background:#d3a95d; }
.kpi:nth-child(4):before { background:#70bba9; }
.metric { transition:border-color .15s ease; }
.metric:hover { border-color:#427084; }
.content-section { scroll-margin-top:22px; }
.section-title h2 { display:flex; align-items:center; gap:9px; }
.section-title h2:before { content:''; display:inline-block; width:5px; height:17px; border-radius:3px; background:var(--accent); }
.dashboard-note { margin:16px 0 0; padding:12px 15px; border:1px solid #355063; border-radius:10px; background:#102437; color:#bad0df; font-size:12px; }
.dashboard-note strong { color:#d7f4f1; }
.finding details { border-top:1px solid #223348; padding-top:10px; }
.finding summary { cursor:pointer; color:#8ee1da; font-weight:700; font-size:13px; }
.finding summary:hover { color:#bdf5ef; }
.finding details[open] summary { margin-bottom:12px; }
.bar-row { grid-template-columns:100px minmax(0,1fr) 26px; }
.bar-track { min-width:0; }
@media (prefers-reduced-motion:reduce) { html { scroll-behavior:auto; } *,*:before,*:after { transition:none!important; } }
@media (max-width:1100px) { .shell { grid-template-columns:1fr; } .sidebar { position:static; height:auto; padding:13px 20px; border-right:0; border-bottom:1px solid var(--line); } .sidebar nav,.sidebar-note,.nav-label { display:none; } .brand { margin:0; } .main { padding-top:25px; } }
@media (max-width:740px) { .hero,.split,.inventory-grid { grid-template-columns:1fr; } .kpis { grid-template-columns:repeat(2,minmax(0,1fr)); } .inventory-grid .inventory:last-child { grid-column:auto; } .panel { padding:18px; } .finding-detail { grid-template-columns:1fr; gap:2px; } }
@media print { :root { color-scheme:light; --bg:#fff; --surface:#fff; --surface2:#fff; --line:#ccd4dd; --text:#17212d; --muted:#45586b; } body { color:#17212d; background:#fff; } body:before,.sidebar { display:none; } .shell { display:block; } .main { max-width:none; padding:0; } .panel,.kpi,.metric,.finding { background:white!important; box-shadow:none; color:#17212d; break-inside:avoid; } .status h2,.status p,.finding p,.finding-detail span,.quality-list li span,.metric-value { color:#17212d; } a { color:#17212d; } .classification { color:#17212d; } }
</style>
</head>
<body>
<div class='shell'>
<aside class='sidebar' aria-label='Report navigation'>
  <div class='brand'><div class='mark' aria-label='SecOpsForge security symbol'>
<svg viewBox='0 0 48 48' width='34' height='34' fill='none' xmlns='http://www.w3.org/2000/svg' aria-hidden='true'>
  <path d='M24 5 L39 13 V30 L24 42 L9 30 V13 Z'
        stroke='#49D5CF' stroke-width='2.2' stroke-linejoin='round'/>
  <path d='M16 17 L24 12 L32 18 L30 29 L22 34 L15 27 Z'
        stroke='#49D5CF' stroke-width='1.8' stroke-linejoin='round'/>
  <path d='M16 17 L30 29 M24 12 L22 34 M32 18 L15 27'
        stroke='#49D5CF' stroke-width='1.2' opacity='0.65'/>
  <circle cx='16' cy='17' r='2.7' fill='#49D5CF'/>
  <circle cx='24' cy='12' r='2.7' fill='#49D5CF'/>
  <circle cx='32' cy='18' r='2.7' fill='#49D5CF'/>
  <circle cx='30' cy='29' r='2.7' fill='#49D5CF'/>
  <circle cx='22' cy='34' r='2.7' fill='#49D5CF'/>
  <circle cx='15' cy='27' r='2.7' fill='#49D5CF'/>
</svg>
</div><div><strong>SecOpsForge</strong><small>Security operations</small></div></div>
  <div class='nav-label'>Report navigation</div>
  <nav><a href='#overview'>Executive summary</a><a href='#findings'>Security findings</a><a href='#coverage'>Security indicators</a><a href='#quality'>Data quality</a><a href='#limitations'>Scope &amp; limitations</a></nav>
  <div class='sidebar-note'>Offline report<br>No Microsoft Graph calls<br>No external assets</div>
</aside>
<main class='main'>
  <div class='topline'><span>Security assessment / Local HTML export</span><span class='classification'>Private &bull; Local report</span></div>
  <h1>Security Operations Dashboard</h1>
  <p class='subtitle'>Offline security review snapshot | Rule-based assessment and aggregated Microsoft security inventory</p>
  <div id='overview' class='hero'>
    <section class='panel status'><div class='eyebrow'>Executive summary</div><h2>$displayStatus</h2><p>$displaySummary</p></section>
    <section class='panel meta' aria-label='Report metadata'>
      <div><span>Assessment status</span><strong>$statusDetail</strong></div>
      <div><span>Posture collected</span><strong>$postureGenerated</strong></div>
      <div><span>Assessment collected</span><strong>$assessmentGenerated</strong></div>
      <div><span>HTML generated</span><strong>$generatedAt</strong></div>
    </section>
  </div>
  <div class='kpis'>
    <div class='kpi'><div class='kpi-value'>$findingCount</div><div class='kpi-label'>Rule-based findings</div></div>
    <div class='kpi'><div class='kpi-value'>$checksEvaluated / $checksTotal</div><div class='kpi-label'>Checks evaluated</div></div>
    <div class='kpi'><div class='kpi-value'>$unknownCount</div><div class='kpi-label'>Unknown assessment checks</div></div>
    <div class='kpi'><div class='kpi-value'>$inventoryAreaCount</div><div class='kpi-label'>Inventory areas included</div></div>
  </div>
  <div class='dashboard-note'><strong>Snapshot, not live monitoring.</strong> Metrics reflect the collected JSON reports and the implemented assessment rules. No threat activity or security score is inferred.</div>
  <section id='findings' class='content-section split'>
    <div class='panel'><div class='section-title'><h2>Security findings</h2><p>Recommendations and verification steps are generated by the existing assessment engine.</p></div>$($findingRows -join "`n")</div>
    <div class='panel'><div class='section-title'><h2>Severity distribution</h2><p>Number of findings by recorded severity, not an overall security score.</p></div>$($severityBars -join "`n")</div>
  </section>
  <section id='coverage' class='content-section'><div class='section-title'><h2>Security inventory</h2><p>Aggregated indicators from $inventoryAreaCount collection areas. No raw identities or tenant identifiers are included.</p></div><div class='inventory-grid'>$inventoryHtml</div></section>
  <section id='quality' class='content-section split'>
    <div class='panel'><div class='section-title'><h2>Data quality &amp; unknowns</h2><p>$unknownCount unknown assessment checks; $($script:missingMetrics.Count) missing or invalid displayed inventory metrics.</p></div><ul class='quality-list'>$($unknownRows -join "`n")</ul></div>
    <div class='panel' id='limitations'><div class='section-title'><h2>Scope &amp; limitations</h2><p>Read these notes before interpreting the results.</p></div>
      <ul class='limitations'>
        <li>Only the implemented rule-based assessment checks are evaluated; no complete tenant security audit or guarantee is provided.</li>
        <li>A zero finding count means no implemented indicators triggered, not that the environment is safe.</li>
        <li>Missing or malformed input metrics are shown as Not reported and must not be interpreted as zero.</li>
        <li>Intune configuration policy counts cover the modern configurationPolicies endpoint only, not every policy type or assignment.</li>
        <li>Defender incident figures do not establish complete threat coverage. Optional Defender device inventory reports device presence, not a complete endpoint security assessment.</li>
        <li>Input reports are expected to come from the same review. This renderer cannot cryptographically verify that they belong to the same run.</li>
        <li>This report is a local private export. Avoid publishing it or opening it on shared systems.</li>
      </ul>
    </div>
  </section>
  <footer>SecOpsForge &middot; Microsoft Security Operations Research Lab &middot; Generated offline &middot; Private assessment</footer>
</main></div>
</body>
</html>
"@

$outputDirectory = Split-Path -Parent $outputFullPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw 'HTML output directory does not exist. Create a private directory first.'
}
if ([IO.Path]::GetExtension($outputFullPath) -ine '.html') {
    throw 'HTML output path must end with .html.'
}

$encoding = [System.Text.UTF8Encoding]::new($false)
$tempPath = Join-Path $outputDirectory ([guid]::NewGuid().ToString('N') + '.html.tmp')
$backupPath = $null
try {
    [System.IO.File]::WriteAllText($tempPath, $html, $encoding)
    if (Test-Path -LiteralPath $outputFullPath -PathType Leaf) {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')
        $suffix = [guid]::NewGuid().ToString('N').Substring(0,8)
        $backupPath = "$outputFullPath.$stamp-$suffix.bak"
        [System.IO.File]::Copy($outputFullPath, $backupPath, $false)
    }
    [System.IO.File]::Move($tempPath, $outputFullPath, $true)
}
finally {
    if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

[PSCustomObject]@{
    ReportCreated     = $true
    OutputPath        = $outputFullPath
    BackupPath        = $backupPath
    Findings          = $findingCount
    UnknownChecks     = $unknownCount
    MissingMetrics    = $script:missingMetrics.Count
    AssessmentStatus  = $expectedStatus
}
