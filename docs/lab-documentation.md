# Lab Documentation

## Environment
- Microsoft 365 Business Premium EEA trial lab tenant (time-limited; service access depends on licensing).
- Microsoft Entra ID for identity and access controls.
- Microsoft Intune for managed endpoint and policy evaluation.
- Microsoft Defender for Business for endpoint protection and incident investigation.
- Windows 11 lab endpoint hosted on Hyper-V.
- PowerShell 7, Pester, and GitHub Actions for automation and validation.

## Validated activities
The lab has included identity controls, Intune enrollment and compliance, Defender onboarding, and an authorized EICAR detection-to-investigation exercise. The README records the EICAR results and investigation sequence. Conditional Access policies were evaluated in report-only mode, rather than assumed to be enforced.

## Read-only security review
The project has successfully produced private `security-posture.json` and `security-assessment.json` files through `Invoke-SecOpsForgeSecurityReview.ps1`. A successful run reported five report sections and zero findings, which must not be interpreted as proof of a secure tenant.

## Offline reporting
The HTML renderer reads the two private JSON files and writes `security-report.html` in the private reports directory. Entra ID and Intune logos are embedded from verified local SVG files. No tenant-derived report or private icon asset is intended for public GitHub publication.

## Evidence policy
Record sanitized procedures and verification outcomes in public documentation. Keep screenshots, tenant exports, user/device names, identifiers, and investigation records private unless individually reviewed and anonymized. Do not infer that a configured policy is effective without validation.

## Microsoft Defender Endpoint Security Inventory

SecOpsForge includes a read-only integration with the Microsoft Defender for Endpoint API.

### Implementation

- PowerShell function: `Get-SecOpsForgeDefenderDeviceInventory`
- API endpoint: `https://api.securitycenter.microsoft.com/api/machines`
- Authentication: Microsoft Entra ID application using OAuth 2.0 client credentials
- API permission: `Machine.Read.All` (Application)
- Access: Read-only

The function retrieves device information, including computer name, onboarding status, health status, risk score, exposure level, and last-seen timestamp.

Access tokens are provided at runtime. Client secrets and access tokens must never be committed to GitHub or included in reports.

### Lab Validation

The integration was validated against a Windows 11 lab device (`w11-client`).

The Defender API returned:

- Onboarding status: Onboarded
- Health status: Active
- Risk score: None
- Exposure level: Medium

The exposure level is reported by Microsoft Defender and does not independently confirm a vulnerability.

### Automated Testing

Five Pester tests cover structured inventory results, empty responses, API failures, access-token validation, and prevention of token exposure in returned results.

Full project validation: 94 tests passed, 0 failed.

The integration does not modify Defender settings, isolate devices, or perform automated remediation.
