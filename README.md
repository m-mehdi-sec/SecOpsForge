# SecOpsForge

### Microsoft Security Operations Research Lab

[![PowerShell CI](https://github.com/m-mehdi-sec/SecOpsForge/actions/workflows/powershell-ci.yml/badge.svg)](https://github.com/m-mehdi-sec/SecOpsForge/actions/workflows/powershell-ci.yml)

**Identity Security | Endpoint Protection | SOC Investigations | PowerShell Automation**

SecOpsForge is a hands-on Microsoft security operations research lab focused on identity protection, endpoint security, threat detection, incident investigation, and security automation.

The project integrates Microsoft Entra ID, Microsoft Intune, Microsoft Defender for Business, Windows 11, PowerShell, and GitHub Actions in a controlled security testing environment.

SecOpsForge is developed as a technical cybersecurity portfolio project, combining practical security operations with reusable code, automated testing, and structured engineering workflows.

**Project Status:** Active Development

---

## Project Objectives

The primary objectives of SecOpsForge are to:

- Design and configure a Microsoft cloud-based security lab.
- Implement identity and access management security controls.
- Enroll, manage, and secure Windows endpoints using Microsoft Intune.
- Configure endpoint protection and detection capabilities.
- Investigate security alerts and incidents using Microsoft Defender.
- Develop reusable PowerShell security automation components.
- Validate functionality using automated Pester tests.
- Integrate continuous integration using GitHub Actions.
- Document technical findings, investigations, and security procedures.

The project emphasizes practical security engineering, defensive operations, and reproducible technical validation.

## Lab Architecture

SecOpsForge uses a Microsoft 365 Business Premium lab tenant integrated with an existing Hyper-V environment.

### Core Components

| Component | Role |
|---|---|
| Microsoft Entra ID | Identity management, authentication, authorization, and Conditional Access |
| Microsoft Intune | Endpoint enrollment, device compliance, and security configuration |
| Microsoft Defender for Business | Endpoint detection, protection, security alerts, and incident investigation |
| Windows 11 | Managed endpoint used for authorized security testing |
| Hyper-V | Virtualization platform hosting the lab endpoint |
| PowerShell 7 | Security operations scripting and automation |
| Pester 6 | Automated PowerShell testing |
| GitHub Actions | Continuous integration and automated validation |

### Security Architecture

```text
Microsoft 365 Security Lab
│
├── Microsoft Entra ID
│   ├── Administrative Identities
│   ├── Test Users and Groups
│   ├── Multi-Factor Authentication
│   ├── Conditional Access (Report-only)
│   └── Self-Service Password Reset
│
├── Microsoft Intune
│   ├── Windows Device Enrollment
│   ├── Device Compliance Policies
│   ├── Endpoint Security Policies
│   └── Defender Integration
│
├── Microsoft Defender for Business
│   ├── Endpoint Protection
│   ├── Endpoint Detection and Response
│   ├── Security Alerts
│   ├── Incident Investigation
│   └── Vulnerability Management
│
└── Hyper-V Lab Environment
    └── W11-CLIENT
        ├── Microsoft Entra Joined
        ├── Intune Enrolled
        ├── Device Compliant
        └── Defender Onboarded
```

The Windows 11 endpoint is managed through Microsoft Intune and onboarded to Microsoft Defender for Business.

Conditional Access policies are currently configured in report-only mode for evaluation and validation. Microsoft Entra Security Defaults remain enabled.

## Implemented Security Capabilities

### Identity and Access Security

The Microsoft Entra ID environment includes:

- Administrative and standard user account separation.
- Multi-factor authentication configuration.
- Conditional Access policy creation and evaluation.
- Emergency administrator account exclusion from selected Conditional Access policies.
- Self-service password reset configuration.
- Authentication method registration.
- Identity Secure Score assessment.
- Enterprise application consent configuration.

Conditional Access evaluation has been performed using report-only results and policy simulation.

### Endpoint Management and Compliance

Microsoft Intune has been configured to manage the Windows 11 lab endpoint.

Implemented capabilities include:

- Microsoft Entra device joining.
- Automatic device enrollment.
- Device compliance policy assignment.
- Endpoint security policy configuration.
- Microsoft Defender integration.
- Endpoint detection and response onboarding.
- Antivirus and firewall policy deployment.

The managed Windows 11 endpoint has been verified as compliant.

### Microsoft Defender Security Operations

Microsoft Defender for Business is used for endpoint protection and security investigation.

Practical activities include:

- Endpoint onboarding verification.
- Device security status assessment.
- Security recommendation analysis.
- Vulnerability exposure review.
- Antivirus detection validation.
- Security alert investigation.
- Incident classification and resolution.

## SOC Investigation: EICAR Detection Validation

An authorized EICAR antivirus validation was performed against the managed Windows 11 lab endpoint.

The objective was to verify that endpoint security controls could detect a known antivirus test file and surface the resulting activity through Microsoft Defender.

### Investigation Workflow

1. Initiate an authorized EICAR antivirus test.
2. Verify Microsoft Defender Antivirus detection.
3. Confirm that the test file is blocked or removed.
4. Review the resulting endpoint protection event.
5. Locate the security alert in Microsoft Defender.
6. Investigate the associated incident.
7. Classify the activity as expected security testing.
8. Resolve the incident and document the findings.

### Validation Results

| Validation | Result |
|---|---|
| EICAR test file detection | Confirmed |
| Antivirus prevention | Confirmed |
| Endpoint protection history | Verified |
| Central security alert | Generated |
| Security incident | Created |
| Incident investigation | Completed |
| Classification | Informational / Expected Activity |
| Incident resolution | Completed |

The investigation demonstrated a functioning detection-to-investigation workflow in the lab environment.

The test used the standard EICAR antivirus test file rather than real malware.

## PowerShell Security Automation

SecOpsForge includes a reusable PowerShell module located at:

`src/SecOpsForge/SecOpsForge.psm1`

The module provides the foundation for future security operations automation.

### Get-SecOpsForgeEnvironment

Checks the availability of essential development tools.

Currently validates:

- Git
- GitHub CLI
- Pester
- PowerShell 7 or later

Example:

```powershell
Import-Module ./src/SecOpsForge/SecOpsForge.psm1 -Force

Get-SecOpsForgeEnvironment
```

### New-SecOpsForgeIncidentReport

Creates a structured JSON incident report from explicitly supplied incident information.

Supported report fields include:

- Schema version
- Incident identifier
- Incident title
- Device name
- Incident status
- Incident classification
- UTC generation timestamp

Example:

```powershell
Import-Module ./src/SecOpsForge/SecOpsForge.psm1 -Force

New-SecOpsForgeIncidentReport `
    -IncidentId 1 `
    -Title "EICAR test file prevented" `
    -DeviceName "W11-CLIENT" `
    -Status "Resolved" `
    -Classification "InformationalExpectedActivity" `
    -OutputPath "./samples/incident-report.json"
```

The current function generates reports from provided parameters. Direct retrieval of security incidents through Microsoft APIs is not yet implemented.

### Incident Report Classification

Supported classification values:

- `TruePositive`
- `InformationalExpectedActivity`
- `FalsePositive`

Supported incident status values:

- `New`
- `InProgress`
- `Resolved`

The function validates input parameters and generates UTF-8 JSON output.

## Repository Structure

```text
SecOpsForge/
├── .github/
│   └── workflows/
│       └── powershell-ci.yml
├── config/
├── docs/
├── evidence/
├── samples/
│   └── eicar-incident.json
├── scripts/
├── src/
│   └── SecOpsForge/
│       └── SecOpsForge.psm1
├── tests/
│   ├── Environment.Tests.ps1
│   └── IncidentReport.Tests.ps1
└── README.md
```

The repository is organized to support modular automation, test coverage, security evidence, technical documentation, and future expansion.

Some directories are reserved for planned functionality.

## Automated Testing

SecOpsForge uses **Pester 6.2.0** to validate PowerShell functionality.

### Current Test Coverage

| Test | Purpose |
|---|---|
| Returns four tools | Validates environment tool enumeration |
| Returns expected tool names | Verifies expected development dependencies |
| Returns boolean installation status | Validates installation status types |
| Creates a valid JSON incident report | Verifies incident report generation |
| Rejects an invalid incident status | Validates parameter restrictions |

### Run Tests Locally

Requirements:

- PowerShell 7 or later
- Pester 6.2.0

```powershell
Import-Module Pester -RequiredVersion 6.2.0 -Force

Invoke-Pester -Path ./tests -Output Detailed
```

**Latest locally verified result:**

```text
Tests Passed: 5
Tests Failed: 0
```

Automated testing will be expanded as additional functionality is implemented.

## Continuous Integration

SecOpsForge uses GitHub Actions to execute automated PowerShell tests.

Workflow:

`.github/workflows/powershell-ci.yml`

The workflow runs on:

- Pushes to `main`
- Pull requests targeting `main`
- Manual workflow dispatch

### CI Execution

The pipeline:

1. Checks out the repository.
2. Installs Pester 6.2.0.
3. Executes the automated test suite using PowerShell.
4. Fails the workflow if tests fail or no tests are discovered.

The initial GitHub Actions workflow completed successfully.

[View GitHub Actions](https://github.com/m-mehdi-sec/SecOpsForge/actions)

## Development Roadmap

SecOpsForge follows an eight-phase development structure with four planned release milestones.

| Phase | Development Focus | Status |
|---|---|---|
| 1 | Project foundation and lab preparation | Implemented |
| 2 | Identity security and access controls | Implemented baseline |
| 3 | Intune device management and compliance | Implemented baseline |
| 4 | Defender endpoint protection and detection | Implemented baseline |
| 5 | SOC investigations and incident reporting | In progress |
| 6 | PowerShell security automation | In progress |
| 7 | Automated testing and CI | Initial implementation complete |
| 8 | Documentation, final validation, and release preparation | Planned |

### Planned GitHub Releases

| Release | Planned Scope |
|---|---|
| v0.1.0 | Foundation, initial automation, and validated lab capabilities |
| v0.2.0 | Expanded identity and endpoint security automation |
| v0.3.0 | SOC investigation and security reporting enhancements |
| v1.0.0 | Integrated, tested, and documented project release |

Release versions represent planned milestones. No release is considered complete until its implementation and validation criteria have been met.

## Security Principles

SecOpsForge follows defensive security engineering principles.

- All security testing must be authorized.
- Lab testing must remain within the intended environment.
- No production systems are targeted.
- No real malware is required for antivirus validation.
- Credentials, access tokens, and other secrets must not be committed.
- Sensitive tenant information must be sanitized before publication.
- Security controls must be evaluated before enforcement.
- Potentially disruptive response actions require explicit authorization.
- Automated functionality should be tested before operational use.
- Technical findings should be documented accurately and reproducibly.

## Technology Stack

| Category | Technologies |
|---|---|
| Identity and Access | Microsoft Entra ID, MFA, Conditional Access |
| Endpoint Management | Microsoft Intune |
| Endpoint Security | Microsoft Defender for Business |
| Operating System | Windows 11 |
| Virtualization | Hyper-V |
| Automation | PowerShell 7 |
| Data Format | JSON |
| Testing | Pester 6 |
| Version Control | Git, GitHub |
| Continuous Integration | GitHub Actions |

## Potential Future Improvements

The following capabilities are being considered for future development:

- Microsoft Graph API integration for authorized security data retrieval.
- Automated collection of Microsoft Defender incident information.
- Extended endpoint security posture assessment.
- Structured incident investigation reports.
- Reusable security operations scripts and runbooks.
- Additional input validation and error handling.
- Expanded automated test coverage.
- Improved CI validation and code quality checks.
- Secure configuration management.
- Additional defensive detection and investigation workflows.

Future capabilities will be implemented incrementally and validated before being described as completed functionality.

SecOpsForge is an independent cybersecurity learning and research project, not a production-certified SOC platform.

## Author

**Muhammad Mehdi**

IT Security Developer Student

Focused on cybersecurity, SOC operations, Blue Team security, threat detection, incident response, and security automation.

[![GitHub](https://img.shields.io/badge/GitHub-24292F?style=flat-square&logo=github&logoColor=white)](https://github.com/m-mehdi-sec)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/muhammadmehdi-sec/)

---

SecOpsForge is an independent cybersecurity learning, research, and portfolio project. It is not affiliated with Microsoft and is not intended to replace production security operations platforms.

