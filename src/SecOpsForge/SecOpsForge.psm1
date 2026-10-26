
function Get-SecOpsForgeEnvironment {
    [CmdletBinding()]
    param()

    $tools = @('git', 'gh')

    foreach ($tool in $tools) {
        [PSCustomObject]@{
            Tool      = $tool
            Installed = [bool](Get-Command $tool -ErrorAction SilentlyContinue)
        }
    }

    [PSCustomObject]@{
        Tool      = 'Pester'
        Installed = [bool](Get-Module -ListAvailable Pester)
    }

    [PSCustomObject]@{
        Tool      = 'PowerShell 7+'
        Installed = ($PSVersionTable.PSVersion.Major -ge 7)
    }
}

function New-SecOpsForgeIncidentReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 2147483647)]
        [int]$IncidentId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,

        [Parameter(Mandatory)]
        [ValidateSet('New', 'InProgress', 'Resolved')]
        [string]$Status,

        [Parameter(Mandatory)]
        [ValidateSet(
            'TruePositive',
            'InformationalExpectedActivity',
            'FalsePositive'
        )]
        [string]$Classification,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    $report = [ordered]@{
        SchemaVersion  = '1.0'
        IncidentId     = $IncidentId
        Title          = $Title
        DeviceName     = $DeviceName
        Status         = $Status
        Classification = $Classification
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

    $json = $report | ConvertTo-Json -Depth 5

    $parent = Split-Path -Parent $OutputPath

    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory `
            -Path $parent `
            -Force `
            -ErrorAction Stop | Out-Null
    }

    $json | Set-Content `
        -LiteralPath $OutputPath `
        -Encoding utf8 `
        -ErrorAction Stop

    Get-Item -LiteralPath $OutputPath
}

function Test-SecOpsForgeGraphConnection {
    [CmdletBinding()]
    param()

    $command = Get-Command Get-MgContext -ErrorAction SilentlyContinue

    if (-not $command) {
        return [PSCustomObject]@{
            Connected    = $false
            AuthType     = $null
            HasReadScope = $false
            Status       = 'Graph authentication module is not available'
        }
    }

    try {
        $context = Get-MgContext -ErrorAction Stop

        if (-not $context -or -not $context.Account) {
            return [PSCustomObject]@{
                Connected    = $false
                AuthType     = $null
                HasReadScope = $false
                Status       = 'Not connected'
            }
        }

        $hasReadScope = @($context.Scopes) -contains 'User.Read'

        return [PSCustomObject]@{
            Connected    = $true
            AuthType     = [string]$context.AuthType
            HasReadScope = $hasReadScope
            Status       = 'Connected'
        }
    }
    catch {
        return [PSCustomObject]@{
            Connected    = $false
            AuthType     = $null
            HasReadScope = $false
            Status       = 'Connection check failed'
        }
    }
}

Export-ModuleMember -Function `
    Get-SecOpsForgeEnvironment, `
    New-SecOpsForgeIncidentReport, `
    Test-SecOpsForgeGraphConnection
