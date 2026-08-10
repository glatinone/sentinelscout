# Security Policy

## Scope

SentinelScout aggregates data from multiple third-party threat intelligence
sources (VirusTotal, AlienVault OTX, Shodan, NVD CVE feeds, and GitHub
Security Advisories) and holds API credentials for several of these
services. Because of this, the following are all explicitly **in scope**
for security reports:

- Vulnerabilities in application code (e.g. injection flaws, unsafe
  deserialization, path traversal, SSRF via source queries).
- Credential-handling issues, including but not limited to:
  - API keys (VirusTotal, AlienVault OTX, Shodan, NVD, GitHub, or any
    AI/LLM provider key) being logged, printed, cached, or otherwise
    exposed in plaintext.
  - API keys or secrets being written to disk outside of the user's own
    `.env`/config file, or persisted in a way the user did not request.
  - Secrets leaking into error messages, stack traces, debug output, or
    telemetry.
  - Insecure defaults for storing or transmitting configured API keys.
  - Any code path that could exfiltrate a configured API key to a
    destination other than the intended upstream API.
- Supply-chain issues (e.g. malicious or compromised dependencies,
  unsafe use of dependency-provided code).
- Any issue that could cause SentinelScout to return falsified or
  tampered threat-intelligence results to a user without indication.

Denial-of-service reports against third-party services caused solely by
normal API usage/rate limits are generally **not** considered a
SentinelScout vulnerability, but excessive or unbounded retry/backoff
behavior that could get a user's key banned or rate-limited unexpectedly
is in scope.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security reports.

Report vulnerabilities privately using **GitHub Security Advisories**:

1. Go to the repository's **Security** tab.
2. Select **"Report a vulnerability"** to open a new draft security
   advisory.
3. Include as much detail as possible:
   - A description of the issue and its potential impact.
   - Steps to reproduce, including a minimal proof of concept if
     possible.
   - Whether the issue involves credential exposure (e.g. which
     source/API key is affected) and, if so, whether you believe any
     key material was exposed to third parties as a result.
   - The affected version/commit.

Do not include real, active API keys or other live credentials in your
report. If a live credential was inadvertently exposed as part of the
issue you're reporting, note that fact but redact the actual value, and
mention that it should be rotated.

## Response Targets

- **Acknowledgment:** within 72 hours of a report being submitted via
  GitHub Security Advisories.
- **Triage and initial assessment:** as soon as practical after
  acknowledgment, including confirmation of scope/severity.
- **Resolution and/or coordinated disclosure:** within 90 days of the
  initial report. If a fix requires more time (for example, coordination
  with an upstream dependency or third-party API provider), we will
  communicate an updated timeline through the same advisory thread.

## Disclosure

We follow coordinated disclosure. Once a fix is available (or the 90-day
target is reached, whichever comes first), we will work with the
reporter on public disclosure timing via the GitHub Security Advisory,
which can then be published with credit to the reporter if desired.

## Supported Versions

This project does not yet maintain multiple long-term-supported release
branches. Security fixes are applied to the latest released version and
the default branch.
