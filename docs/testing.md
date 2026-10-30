# Testing and Verification

## Local test suite
Run from the repository root in PowerShell 7:

```powershell
Import-Module Pester -RequiredVersion 6.2.0 -Force
Invoke-Pester -Path ./tests -Output Normal
```

Latest locally verified result on 2026-10-30: **102 passed, 0 failed**. The suite ran from 16 test files. GitHub Actions also completed successfully after the Defender integration and README updates.

## Coverage areas
Environment prerequisites; Graph connection; identity and privileged-access inventories; Intune device and policy inventories; Defender incident and device inventories; Defender HTML integration; security posture and assessment; structured incident reporting; review orchestration; offline HTML output; dashboard presentation; and SVG brand security.

## Dashboard validation
The offline HTML report was validated using private JSON files and live Microsoft Defender inventory data. Both five-area and six-area reporting were tested. The six-area report displayed one Defender device without exposing its name in the HTML output. Entra ID and Intune logos rendered. Automated SVG tests cover allowed local gradient references and rejection of unsafe constructs. These tests do not replace a security review of any future third-party SVG asset.

## CI
The existing GitHub Actions workflow `.github/workflows/powershell-ci.yml` runs Pester on pushes, pull requests, and manual dispatches as described in the README. GitHub Actions completed successfully after the Defender integration and subsequent README update (commit `0fd2270`).

## Release gate
1. Run the full local Pester suite.
2. Generate and inspect a private HTML report.
3. Review staged file names and contents for secrets or tenant data.
4. Commit only reviewed source, tests, and documentation.
5. Confirm GitHub Actions passes.
6. Create a versioned release only after its agreed scope and validation criteria are met.
