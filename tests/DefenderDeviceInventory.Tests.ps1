
BeforeAll {
    Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force
}

Describe 'Get-SecOpsForgeDefenderDeviceInventory' {

    BeforeEach {
        Mock Invoke-RestMethod {
            [PSCustomObject]@{
                value = @(
                    [PSCustomObject]@{
                        computerDnsName = 'w11-client'
                        onboardingStatus = 'Onboarded'
                        healthStatus = 'Active'
                        riskScore = 'None'
                        exposureLevel = 'Medium'
                        lastSeen = '2026-10-30T08:43:37Z'
                    }
                )
            }
        } -ModuleName SecOpsForge
    }

    It 'returns a structured device inventory' {
        $result = Get-SecOpsForgeDefenderDeviceInventory -AccessToken 'test-token'

        $result.TotalDevices | Should -Be 1
        $result.Devices[0].ComputerName | Should -Be 'w11-client'
        $result.Devices[0].OnboardingStatus | Should -Be 'Onboarded'
        $result.Devices[0].HealthStatus | Should -Be 'Active'
        $result.Devices[0].RiskScore | Should -Be 'None'
        $result.Devices[0].ExposureLevel | Should -Be 'Medium'
    }

    It 'returns an empty inventory when no devices exist' {
        Mock Invoke-RestMethod {
            [PSCustomObject]@{ value = @() }
        } -ModuleName SecOpsForge

        $result = Get-SecOpsForgeDefenderDeviceInventory -AccessToken 'test-token'

        $result.TotalDevices | Should -Be 0
        @($result.Devices).Count | Should -Be 0
    }

    It 'throws when the Defender API fails' {
        Mock Invoke-RestMethod {
            throw '403 Forbidden'
        } -ModuleName SecOpsForge

        {
            Get-SecOpsForgeDefenderDeviceInventory -AccessToken 'test-token'
        } | Should -Throw '*Defender device inventory failed*'
    }

    It 'rejects an empty access token' {
        {
            Get-SecOpsForgeDefenderDeviceInventory -AccessToken ''
        } | Should -Throw
    }

    It 'does not expose the access token in its result' {
        $result = Get-SecOpsForgeDefenderDeviceInventory -AccessToken 'test-token'

        ($result | ConvertTo-Json -Depth 5) |
            Should -Not -Match 'test-token'
    }
}
