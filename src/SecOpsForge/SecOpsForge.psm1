
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

        [PSCustomObject]@{
            Connected    = $true
            AuthType     = [string]$context.AuthType
            HasReadScope = @($context.Scopes) -contains 'User.Read'
            Status       = 'Connected'
        }
    }
    catch {
        [PSCustomObject]@{
            Connected    = $false
            AuthType     = $null
            HasReadScope = $false
            Status       = 'Connection check failed'
        }
    }
}

function Get-SecOpsForgeIdentityInventory {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Graph authentication module is not available.'
    }

    $context = Get-MgContext -ErrorAction Stop

    if (-not $context -or -not $context.Account) {
        throw 'Microsoft Graph is not connected.'
    }

    if (@($context.Scopes) -notcontains 'User.Read.All') {
        throw 'Microsoft Graph permission User.Read.All is required.'
    }

    $users = @()
    $uri = 'https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled,userType,assignedLicenses&$top=100'

    do {
        $response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $uri `
            -ErrorAction Stop

        $users += @($response.value)
        $uri = $response.'@odata.nextLink'
    }
    while ($uri)

    $enabled = @($users | Where-Object {
        $_.accountEnabled -eq $true
    })

    $disabled = @($users | Where-Object {
        $_.accountEnabled -eq $false
    })

    $members = @($users | Where-Object {
        $_.userType -eq 'Member'
    })

    $guests = @($users | Where-Object {
        $_.userType -eq 'Guest'
    })

    $licensed = @($users | Where-Object {
        @($_.assignedLicenses).Count -gt 0
    })

    [PSCustomObject]@{
        SchemaVersion   = '1.0'
        TotalUsers      = $users.Count
        EnabledUsers    = $enabled.Count
        DisabledUsers   = $disabled.Count
        MemberUsers     = $members.Count
        GuestUsers      = $guests.Count
        LicensedUsers   = $licensed.Count
        UnlicensedUsers = $users.Count - $licensed.Count
        GeneratedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-SecOpsForgePrivilegedAccessInventory {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Graph authentication module is not available.'
    }

    $context = Get-MgContext -ErrorAction Stop

    if (-not $context -or -not $context.Account) {
        throw 'Microsoft Graph is not connected.'
    }

    if (@($context.Scopes) -notcontains 'RoleManagement.Read.Directory') {
        throw 'Microsoft Graph permission RoleManagement.Read.Directory is required.'
    }

    try {
        $assignments = @()
        $uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'

        do {
            $response = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $uri `
                -ErrorAction Stop

            if ($null -eq $response -or $null -eq $response.value) {
                throw 'Invalid role assignments response.'
            }

            $assignments += @($response.value)
            $uri = $response.'@odata.nextLink'
        }
        while ($uri)

        $roles = @()
        $uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'

        do {
            $response = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $uri `
                -ErrorAction Stop

            if ($null -eq $response -or $null -eq $response.value) {
                throw 'Invalid role definitions response.'
            }

            $roles += @($response.value)
            $uri = $response.'@odata.nextLink'
        }
        while ($uri)

        $globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

        $globalAdminRoleIds = @(
            $roles |
                Where-Object {
                    $_.templateId -eq $globalAdminTemplateId
                } |
                ForEach-Object { $_.id }
        )

        if ($globalAdminRoleIds.Count -eq 0) {
            throw 'Global Administrator role definition was not found.'
        }

        $globalAdminAssignments = @(
            $assignments | Where-Object {
                $_.roleDefinitionId -in $globalAdminRoleIds
            }
        )

        $otherAssignments = @(
            $assignments | Where-Object {
                $_.roleDefinitionId -notin $globalAdminRoleIds
            }
        )

        $uniquePrincipals = @(
            $assignments |
                ForEach-Object { $_.principalId } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )

        [PSCustomObject]@{
            SchemaVersion              = '1.0'
            TotalRoleAssignments       = $assignments.Count
            GlobalAdminAssignments     = $globalAdminAssignments.Count
            OtherRoleAssignments       = $otherAssignments.Count
            UniquePrivilegedPrincipals = $uniquePrincipals.Count
            GeneratedAtUtc             = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    catch {
        throw 'Privileged access inventory failed. No report was generated.'
    }
}

Export-ModuleMember -Function `
    Get-SecOpsForgeEnvironment, `
    New-SecOpsForgeIncidentReport, `
    Test-SecOpsForgeGraphConnection, `
    Get-SecOpsForgeIdentityInventory, `
    Get-SecOpsForgePrivilegedAccessInventory
