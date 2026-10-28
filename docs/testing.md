# Testing and Verification

## Local test suite
Run from the repository root in PowerShell 7:

```powershell
Import-Module Pester -RequiredVersion 6.2.0 -Force
Invoke-Pester -Path ./tests -Output Normal
```

Latest locally reported result on 2026-10-28: **89 passed, 0 failed**. The suite ran from 14 test files. This result predates staging and CI execution for the new dashboard files.

## Coverage areas
Environment prerequisites; Graph connection; identity and privileged-access inventories; Intune device and policy inventories; Defender incident inventory; security posture and assessment; structured incident reporting; review orchestration; offline HTML output; dashboard presentation; and SVG brand security.

## Dashboard validation
The report was generated using existing private JSON files and visually checked in a browser. Entra ID and Intune logos rendered. Automated SVG tests cover allowed local gradient references and rejection of unsafe constructs. These tests do not replace a security review of any future third-party SVG asset.

## CI
The existing GitHub Actions workflow `.github/workflows/powershell-ci.yml` runs Pester on pushes, pull requests, and manual dispatches as described in the README. **Do not claim that CI has validated newly added tests until a new workflow run completes successfully.**

## Release gate
1. Run the full local Pester suite.
2. Generate and inspect a private HTML report.
3. Review staged file names and contents for secrets or tenant data.
4. Commit only reviewed source, tests, and documentation.
5. Confirm GitHub Actions passes.
6. Create a versioned release only after its agreed scope and validation criteria are met.
