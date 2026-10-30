
# Lab Documentation

## Environment

- Microsoft 365 Business Premium EEA trial lab tenant (time-limited; service access depends on licensing).
- Microsoft Entra ID for identity and access controls.
- Microsoft Intune for managed endpoint and policy evaluation.
- Microsoft Defender for Business for endpoint protection and incident investigation.
- Windows 11 lab endpoint hosted on Hyper-V.
- PowerShell 7, Pester, and GitHub Actions for automation and validation.

## Validated Activities

The lab has included identity controls, Intune enrollment and compliance, Defender onboarding, and an authorized EICAR detection-to-investigation exercise.

The README documents the EICAR investigation workflow and its results.

Conditional Access policies were evaluated in report-only mode rather than assumed to be enforced.

## Read-only Security Review

SecOpsForge uses `Invoke-SecOpsForgeSecurityReview.ps1` to collect security inventory and generate private reports.

The review uses read-only Microsoft Graph integrations for:

- Microsoft Entra ID identity inventory.
- Privileged access inventory.
- Microsoft Intune device inventory.
- Microsoft Intune policy inventory.
- Microsoft Defender incident inventory.

The review produces:

- `security-posture.json`
- `security-assessment.json`

A previously validated five-area review returned zero security findings.

Zero findings must not be interpreted as proof that the tenant is secure. Assessment results depend on the available data, permissions, and implemented detection rules.

## Microsoft Defender Device Inventory

### Objective

Integrate read-only Microsoft Defender device inventory into the existing SecOpsForge security review and offline HTML dashboard.

### Implementation

- PowerShell function: `Get-SecOpsForgeDefenderDeviceInventory`
- API endpoint: `https://api.securitycenter.microsoft.com/api/machines`
- Authentication: Microsoft Entra ID using OAuth 2.0 client credentials.
- API permission: `WindowsDefenderATP Machine.Read.All` (Application).
- Access: Read-only.

The integration retrieves available device information, including:

- Computer name.
- Onboarding status.
- Health status.
- Risk score.
- Exposure level.
- Last-seen timestamp.

The security review supports an optional Defender access token.

When valid Defender API access is available, the review includes a sixth inventory area for Defender devices.

Without a Defender token, the original five-area reporting workflow remains supported.

### Lab Validation

The integration was validated against the Windows 11 lab endpoint `w11-client`.

Microsoft Defender returned:

| Property | Result |
|---|---|
| Onboarding status | Onboarded |
| Health status | Active |
| Risk score | None |
| Exposure level | Medium |

The reported exposure level does not independently confirm a vulnerability or security incident.

The integrated security review was also verified with live Defender device data.

Confirmed results:

- Security review completed successfully.
- Six inventory areas were collected.
- One Defender device was returned.
- Security Posture JSON export succeeded.
- Security Assessment JSON export succeeded.
- Offline HTML report generation succeeded.
- Defender device count appeared in the HTML report.
- Original five-area reporting remained functional.

### Security and Limitations

The integration uses a dedicated read-only Microsoft Entra application.

Access tokens are supplied at runtime. Client secrets and access tokens must not be stored in the Git repository or included in generated reports.

The integration does not modify Defender settings, isolate devices, or perform automated remediation.

Individual device names are not displayed in the offline HTML dashboard.

Defender device inventory is an informational snapshot and does not automatically generate security findings.

The Security Assessment currently evaluates four existing rules.

An onboarded device is not necessarily fully protected or free from vulnerabilities.

## Offline HTML Reporting

The HTML renderer `New-SecOpsForgeHtmlReport.ps1` reads the private Security Posture and Security Assessment JSON files.

It generates:

`security-report.html`

The report is stored outside the Git repository in:

`$HOME/SecOpsForge-Private-Reports`

The HTML report supports offline viewing and displays security inventory and assessment results.

Verified local SVG branding assets are embedded without requiring external resources.

The Defender device inventory is displayed as an additional reporting area when available.

## Automated Testing

SecOpsForge uses Pester for automated PowerShell validation.

The tests cover existing security inventory, reporting, validation, and integration functionality.

Defender device inventory has been tested for:

- Structured API responses.
- Empty responses.
- API failures.
- Access-token validation.
- Prevention of token exposure in returned results.

The project has also been tested for Defender inventory integration with Security Review and offline HTML reporting.

**Latest verified result (2026-10-30):**

- 102 Pester tests passed.
- 0 tests failed.
- GitHub Actions completed successfully.

Earlier test results of 94 and 101 passed represented previous development stages.

## Evidence Policy

Public documentation should contain sanitized procedures and verified technical outcomes.

The following information must remain private unless individually reviewed and anonymized:

- Tenant exports.
- Authentication credentials and access tokens.
- User and device identifiers.
- Sensitive investigation records.
- Private JSON and HTML security reports.
- Screenshots containing sensitive tenant information.

A configured security policy must not be assumed effective without validation.

SecOpsForge is a defensive educational research project and is not a production-certified security monitoring platform.
