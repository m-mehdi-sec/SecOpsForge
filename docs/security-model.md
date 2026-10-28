# Security Model

## Operating principles
- Run only in an authorized Microsoft 365 lab tenant.
- Keep Graph inventory and security review read-only; do not turn reporting scripts into enforcement tools.
- Store tenant-derived JSON, HTML reports, tokens, and backups outside the Git repository.
- Never publish tenant identifiers, account information, device identifiers, raw incident details, credentials, or access tokens.
- Review every staged file before committing; `.gitignore` is defense in depth, not a substitute for inspection.

## HTML output
The renderer HTML-encodes untrusted data fields and uses a restrictive Content Security Policy. Brand SVGs are read from a private local directory, parsed with prohibited DTDs, and restricted to allowed shapes and local paint references. Remote URLs, scriptable SVG constructs, and event handlers are rejected. The renderer should not silently weaken these controls to accept new assets.

## Data quality
Missing or unsupported metrics must not be presented as zero. Assessment findings are conditional on the available inventory and checks; distinguish missing evidence from verified absence of risk.

## Before publication
Run Pester; inspect `git status`, `git diff --cached`, and staged filenames; scan staged content for sensitive values; verify that no private reports or raw evidence are included. Keep security-sensitive report files under `$HOME/SecOpsForge-Private-Reports`.
