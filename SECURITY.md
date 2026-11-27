# Security policy

## Supported versions

The 1.0.x series is the initial supported series. Security fixes are applied
to the latest release line first.

## Reporting a vulnerability

Do not open a public issue for a live exploit path, credential, private origin
list, or other sensitive detail. Use GitHub Security Advisories for
`draarivpatel-ui/pycorscage` when the repository is public. Include:

- the affected version and commit if known
- a minimal reproduction or proof of concept
- the security impact and whether credentials, Private Network Access, or a
  shared cache are involved
- any mitigation you have already applied

If the advisory interface is unavailable, open a minimal public issue that asks
for a private contact path and do not include exploit details.

## Scope

In scope:

- origin canonicalization or matching bypasses
- credentialed wildcard or null-origin activation
- preflight method, header, or Private Network Access validation bypasses
- cache-poisoning failures involving missing or incorrect `Vary`
- downstream middleware override of policy-controlled response headers
- CLI file-opening or terminal-output safety failures

Out of scope:

- application authentication and authorization logic
- CSRF protections unrelated to CORS response headers
- DNS rebinding and reverse-proxy trust configuration
- denial of service requiring already unrealistic memory or CPU use outside
  documented caps
- issues in frameworks or servers that integrate this library

## Response expectations

Reports are triaged as soon as practical. Please do not disclose publicly
until a fix or coordinated disclosure date has been agreed.
