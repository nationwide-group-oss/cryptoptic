# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

The cryptoptic team takes security issues seriously. We appreciate your efforts to responsibly disclose your findings.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Private Vulnerability Reporting**: Use the [Security Advisories](../../security/advisories/new) feature on this repository to privately report a vulnerability.
2. **Email**: Send a detailed report to **ProductSecurity@nationwide.co.uk**

### What to Include

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue or a proof of concept.
- Any relevant logs, screenshots, or configuration details.
- The version(s) of cryptoptic affected.

### What to Expect

- **Acknowledgement** within 48 hours of your report.
- An initial **assessment and timeline** within 5 business days.
- We will work with you to understand and validate the issue.
- A fix will be developed and a coordinated disclosure timeline agreed upon.
- Credit will be given to reporters in the release notes, unless anonymity is requested.

## Disclosure Policy

- We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
- We request that you give us a reasonable amount of time to address the issue before public disclosure.
- We will publish security advisories for confirmed vulnerabilities via GitHub Security Advisories.

## Security Best Practices for Users

- Always use the latest release of cryptoptic.
- Review CodeQL query results carefully before acting on findings.
- Keep your CodeQL CLI and GitHub Actions runners up to date.
- Follow the principle of least privilege when configuring GitHub tokens and workflow permissions.
