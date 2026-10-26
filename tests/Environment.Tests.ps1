Import-Module "$PSScriptRoot/../src/SecOpsForge/SecOpsForge.psm1" -Force

Describe "SecOpsForge Environment" {

    It "Returns four tools" {
        $result = @(Get-SecOpsForgeEnvironment)
        $result.Count | Should -Be 4
    }

    It "Returns expected tool names" {
        $result = Get-SecOpsForgeEnvironment
        ($result.Tool -join ",") | Should -Be "git,gh,Pester,PowerShell 7+"
    }

    It "Returns boolean installation status" {
        $result = Get-SecOpsForgeEnvironment

        foreach ($item in $result) {
            ($item.Installed -is [bool]) | Should -Be $true
        }
    }
}

