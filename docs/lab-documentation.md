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
