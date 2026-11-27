# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes land on the latest 1.x release. Upgrade before reporting an issue that only reproduces on an older release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/pycorscage/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected pycorscage version or commit.
- The Python version and operating system.
- A minimal proof of concept or input that demonstrates the problem.
- The expected behavior and the observed behavior.
- A short assessment of impact and any preconditions.

Do not include real credentials, tokens, cookies, private keys, customer data or personal data in a report. Redact secrets before attaching logs.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix or documented mitigation within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

## Scope

In scope:

- Origin canonicalization or matching bypasses.
- Credentialed wildcard or null-origin activation.
- Preflight method, header, or Private Network Access validation bypasses.
- Cache-poisoning failures involving missing or incorrect `Vary`.
- Downstream middleware override of policy-controlled response headers.
- CLI file-opening or terminal-output safety failures.

Out of scope:

- Application authentication and authorization logic.
- CSRF protections unrelated to CORS response headers.
- DNS rebinding and reverse-proxy trust configuration.
- Denial of service requiring already unrealistic memory or CPU use outside documented caps.
- Issues in frameworks or servers that integrate this library.
