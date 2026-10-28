# Architecture

## Purpose
SecOpsForge is a defensive Microsoft security operations research lab and PowerShell reporting project. It combines a Microsoft 365 Business Premium lab tenant, Entra ID, Intune, Defender for Business, a Windows 11 Hyper-V lab endpoint, PowerShell 7, Pester, and GitHub Actions.

## Data flow

```text
Microsoft 365 lab tenant
  |-- Entra identity and privileged access
  |-- Intune device and policy inventory
  `-- Defender incident inventory
            |
      Read-only Microsoft Graph inventory commands
            |
      Security review orchestration
            |
      Private JSON: security-posture.json + security-assessment.json
            |
      Offline HTML renderer
            |
      Private security-report.html
```

The PowerShell module is at `src/SecOpsForge/SecOpsForge.psm1`. The review orchestrator is `scripts/Invoke-SecOpsForgeSecurityReview.ps1`; the HTML renderer is `scripts/New-SecOpsForgeHtmlReport.ps1`. The renderer accepts `PosturePath`, `AssessmentPath`, and `OutputPath`.

## Trust boundaries
The Microsoft tenant is a lab source. Inventory is read-only. Raw tenant-derived output stays in `$HOME/SecOpsForge-Private-Reports` outside the repository. HTML is intended for offline viewing; it must not require external scripts, fonts, or images. The SVG icon loader validates local assets before embedding them as data URIs.

## Limitations
This is not a production SOC platform or a comprehensive security audit. Reported findings and inventory counts depend on available permissions, data completeness, and the specific implemented checks. A zero-finding result does not establish that an environment is secure.
