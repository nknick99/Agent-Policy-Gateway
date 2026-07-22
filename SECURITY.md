# Security Policy

Agent Policy Gateway is a security tool, so we take issues in it seriously.
Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability
reporting](https://github.com/nknick99/Agent-Policy-Gateway/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal policy + request is ideal),
- affected version/commit, and
- any suggested remediation.

**What to expect:** acknowledgement within a few days, an assessment and severity
rating, a fix or mitigation for confirmed issues, and credit in the release notes
if you'd like it. Please give a reasonable window to remediate before any public
disclosure; we'll coordinate timing with you.

## Supported versions

The project is pre-1.0 (`0.x`). Security fixes land on the latest `main` and the
most recent release. Pin a version and watch releases for updates.

## Scope

**In scope** — vulnerabilities in this repository's code, for example:

- **enforcement bypass** — a request that should be denied is allowed (policy
  bypass, egress/SSRF bypass, SQL parsing evasion, per-agent scope escape);
- **authentication/authorization flaws** — token/JWT handling, argon2 usage,
  constant-time comparison, default-credential exposure;
- **audit integrity** — ways to suppress, forge, or corrupt audit records;
- **information disclosure** — secrets leaking via logs, errors, or responses.

**Out of scope** — see the [threat model](docs/threat-model.md) for the full
statement of assumptions and non-goals. In particular:

- issues that require the documented assumptions to already be violated (e.g. an
  agent that can reach the target *without* going through the gateway, or write
  access to the policy file / secret env vars);
- missing controls that are explicitly non-goals per
  [ADR-002](docs/adr/002-deterministic-policy-scope.md) (content DLP,
  prompt-injection *detection*, model assurance);
- vulnerabilities in third-party dependencies (report upstream; we'll bump);
- missing transport security when TLS termination in front of the gateway is
  assumed (assumption A2 in the threat model).

## Good-faith research

We support good-faith security research and will not pursue action against
researchers who act in good faith, avoid privacy violations and service
disruption, and give us a chance to remediate before public disclosure.
