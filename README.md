<p align="left">
   <picture>
      <source media="(prefers-color-scheme: dark)" srcset="assets/Nationwide%20Logo%20Lockup%20Reversed.svg">
      <source media="(prefers-color-scheme: light)" srcset="assets/Nationwide%20Logo%20Lockup%20Colour.svg">
      <img src="assets/Nationwide%20Logo%20Lockup%20Colour.svg" alt="Nationwide Building Society" width="420">
   </picture>
</p>

# cryptoptic

**Find the cryptography hiding in your code before quantum computers find it for you.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Code of Conduct](https://img.shields.io/badge/Code%20of%20Conduct-Contributor%20Covenant%202.1-purple.svg)](CODE_OF_CONDUCT.md)

cryptoptic uses [CodeQL](https://codeql.github.com/) and GitHub Actions to scan a repository or an entire GitHub organisation and produce an inventory of every cryptographic function in use, the library it comes from, and where it is called.

---

## Why this exists

The anticipated arrival of cryptographically relevant quantum computing means that many algorithms in widespread use today will no longer keep data secure. "Harvest now, decrypt later" makes this a present-day risk, not a future one.

Before an organisation can migrate to post-quantum algorithms, it needs to understand where cryptography is used across its codebase. cryptoptic helps create that Cryptographic Bill of Materials (CBOM), so vulnerable algorithms can be replaced with quantum-safe alternatives or managed transparently.

cryptoptic was built and is used internally at Nationwide Building Society. It is released here for the wider community.

## What it does

- Scans a **single repository**, or **every repository in an organisation**.
- Identifies **cryptographic function calls**, the **library** each comes from, and the **file and location** of each usage.
- Runs within **GitHub Actions**, with no third-party service required and no code leaving GitHub.
- Outputs results as **SARIF**, which can be viewed in the Actions run and consumed by downstream tooling.

## Supported languages

| Language   | Status      | `TARGET_LANG` value |
| ---------- | ----------- | ------------------- |
| Python     | Supported   | `python`            |
| JavaScript | Supported   | `javascript`        |
| .NET       | Supported   | `csharp`            |
| Java       | Planned     |                   |

## Getting started

### Prerequisites

- A GitHub account with access to the repository or organisation you want to scan.
- GitHub Actions enabled on the repository running the scan.

### Running a scan

1. **Clone this repository** and open it in an editor of your choice.

2. **Edit `.github/workflows/org-codeql-sarif-run.yml`** and set the required workflow values.

### Workflow settings

   | Setting       | Description                                                                                              |
   | ------------- | -------------------------------------------------------------------------------------------------------- |
   | `ORG`         | The organisation to scan. For a personal repository, use your GitHub username.                            |
   | `REPO`        | The repository to scan. **Leave as an empty string to scan every repository in the organisation.**        |
   | `TARGET_LANG` | The language to scan see [Supported languages](#supported-languages) for valid values.                  |

3. **Commit and push** your changes.

4. **Go to the Actions tab** in GitHub and select **CodeQL org run (crypto inventory)** from the left-hand sidebar.

5. Click **Run workflow**, choose the branch you want to run against, and click the green **Run workflow** button.

### Viewing results

The generated files are published as artifacts on the workflow run:

- **Organisation-wide scans** → under **CodeQL org run**.
- **Single-repository scans** → under **Security Scanning Workflow**.

## Development

To work on cryptoptic itself, you will need:

- **Python 3**
- Either the **[CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli)** or the **[CodeQL extension for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql)**

## Roadmap

- Java support.
- Expanded query coverage for the currently supported languages.

## Contributing

Contributions are welcome, including code, queries, documentation, tests and bug reports. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating; it applies to every project space.

- Open a [GitHub Issue](../../issues) for bugs and feature requests.
- Discuss significant changes in an Issue or Discussion **before** implementation; these need sign-off from at least two maintainers.
- Submit your work as a pull request. By contributing, you agree that your contribution is licensed under the Apache License 2.0.
- Contributors must sign off commits using the Developer Certificate of Origin process described in [CONTRIBUTING.md](CONTRIBUTING.md). Contributions that do not include a valid DCO sign-off may not be accepted.
- Maintainers may decline contributions at their discretion, including where they raise legal, security, quality, sanctions, export control or project governance concerns.

See [GOVERNANCE.md](GOVERNANCE.md) for how decisions get made and [MAINTAINERS.md](MAINTAINERS.md) for who to talk to.

## Security

**Please do not report security vulnerabilities through public GitHub issues.** See [SECURITY.md](SECURITY.md) for how to report privately and what to expect after you do.

## Licence

This project is licensed under the Apache License, Version 2.0. A copy of the licence should be included in the repository in a file named LICENCE or LICENSE. Users should review the licence terms before using, modifying or distributing the project.

Where the project is redistributed, the Apache License 2.0 requires preservation of applicable copyright, patent, trade mark and attribution notices, inclusion of a copy of the licence, notices for modified files where applicable, and appropriate handling of any NOTICE file included with the project.

## Notice

If the repository includes a NOTICE file, users and redistributors must preserve the attribution notices contained in that file in accordance with the Apache License 2.0. The NOTICE file should be kept accurate and should reflect the notices applicable to the contents of the distribution.

## Trade Marks and Branding

The Apache License 2.0 does not grant permission to use Nationwide's names, logos, trade marks or branding. Any use of Nationwide branding or project-specific branding must comply with the project's separate trade mark policy.

## No Warranty / No Liability

As described in the Apache License 2.0, the project is provided on an "AS IS" basis, without warranties or conditions of any kind. Users are responsible for determining whether the project is appropriate for their use and for validating any outputs before relying on them.

## Repository documents

- [LICENSE](LICENSE) full Apache License 2.0 text.
- [NOTICE](NOTICE) attribution and other notices applicable to the distribution.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) community standards for participation.
- [CONTRIBUTING.md](CONTRIBUTING.md) contribution process and contributor sign-off requirements.
- [SECURITY.md](SECURITY.md) vulnerability reporting process.
- [TRADEMARK.md](TRADEMARK.md) rules for use of Nationwide and project branding.
- [GOVERNANCE.md](GOVERNANCE.md) project governance and maintainer decision-making model.
- [MAINTAINERS.md](MAINTAINERS.md) current project maintainers.