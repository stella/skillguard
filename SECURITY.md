# Security Policy

SkillGuard scans untrusted skill content. Treat scanner bugs as security issues
when they allow a malicious skill to bypass deterministic checks, crash the
scanner, access host secrets, or trigger code execution.

## Reporting

Please report security issues privately through GitHub security advisories:

https://github.com/stella/skillguard/security/advisories/new

Do not include private skill contents, secrets, tokens, or production logs in
public issues.

## Supported Versions

Until the first stable release, only the current `main` branch is supported.

## Scanner Guarantees

SkillGuard aims to:

- avoid executing candidate skill files;
- avoid network access by default;
- avoid following symlinks;
- cap scan resources;
- produce deterministic reports.

SkillGuard does not guarantee that a scanned skill is safe to install.
