<p align="center">
  <img src=".github/assets/banner.png" alt="SkillGuard" width="100%" />
</p>

# SkillGuard

SkillGuard is a local-first security scanner and policy gate for Agent Skills.
It is designed to run before a third-party skill is installed.

SkillGuard is not a certification system. It is a deterministic lint and policy
engine for catching high-risk skill behavior before installation.

Status: alpha. The scanner is useful as a local install gate and CI signal, but
it does not prove that a skill is safe.

## Goals

- Scan skill directories without executing skill code.
- Work offline by default.
- Produce stable JSON and SARIF reports for installers and CI.
- Keep the scanner generic while allowing products to enforce stricter policy.
- Stay Bun-first at the CLI and portable TypeScript in the core.

## Quick Start

```sh
bunx @stll/skillguard scan ./skill --preset strict --policy strict
```

Scan a local directory, zip file, Git URL, or direct URL. Remote inputs require
explicit network opt-in:

```sh
bunx @stll/skillguard scan https://github.com/org/skill --allow-network
```

Try the repository fixtures from a clone:

```sh
bun install
bun --filter @stll/skillguard skillguard scan ./fixtures/malicious
```

JSON output:

```sh
bunx @stll/skillguard scan ./skill \
  --preset strict \
  --policy strict \
  --format json
```

Markdown output:

```sh
bunx @stll/skillguard scan ./skill \
  --format markdown \
  --output skillguard-report.md
```

SARIF output:

```sh
bunx @stll/skillguard scan ./skill --format sarif --output skillguard.sarif
```

## Presets

`--preset` controls scan breadth. `--policy` controls which severities fail the
install gate. Keep these knobs separate: a broad scan can still use an advisory
policy, and a quick scan can still fail on medium findings.

| Preset | Purpose |
| --- | --- |
| `quick` | High-confidence local checks for install gating. |
| `standard` | Default. Adds dependency hygiene, dangerous code, taint-flow, and output-handling checks. |
| `strict` | Adds lower-confidence behavioral checks: excessive agency, memory poisoning, tool misuse, trigger abuse, and MCP/tool metadata poisoning. |
| `paranoid` | Adds malware/offensive-tool indicators, generic network-use findings, offline dependency advisory fallback, and OSV lookup when `--allow-network` is set. |

Examples:

```sh
skillguard scan ./skill --preset quick --policy standard
skillguard scan ./skill.zip --preset strict --policy strict
skillguard scan https://github.com/org/skill --preset paranoid --allow-network
```

## Semantic Review

Semantic review is optional and off by default. It sends a bounded, redacted
review packet for the candidate skill to an OpenAI-compatible model provider and
turns the response into normal SkillGuard findings under
`skillguard.semantic-review`.

It requires explicit network opt-in:

```sh
skillguard scan ./skill \
  --preset paranoid \
  --policy strict \
  --allow-network \
  --semantic \
  --semantic-provider openai
```

Configuration:

- `OPENAI_API_KEY` or `SKILLGUARD_SEMANTIC_API_KEY`
- `SKILLGUARD_SEMANTIC_MODEL` or `--semantic-model`
- `OPENAI_BASE_URL`, `SKILLGUARD_SEMANTIC_BASE_URL`, or
  `--semantic-base-url` for OpenAI-compatible endpoints

Do not run semantic review on broad workspace roots containing unrelated user
documents or secrets. Scan only the third-party skill package being evaluated.

## Packages

- `@stll/skillguard-core`: traversal, report types, policy evaluation, rule runtime.
- `@stll/skillguard-rules`: built-in deterministic rules.
- `@stll/skillguard-sarif`: SARIF 2.1.0 report conversion.
- `@stll/skillguard`: Bun-first CLI and TanStack Intent skill.

The `@stll/skillguard` package also ships a TanStack Intent skill at
`skills/security-scan/SKILL.md`, so agents that discover package-provided skills
can invoke SkillGuard before installing third-party skills.

## Public Rule Catalog

`@stll/skillguard-rules` exports `RULE_CATALOG`, a documented catalog of 64 stable
pattern IDs across the built-in rule set. Findings include these IDs in
`finding.metadata.pattern` when a specific pattern matched, so installers and CI
can suppress, explain, or route findings without depending only on prose.

## Security Defaults

- No skill code execution.
- No network calls unless `--allow-network` is set.
- No symlink following.
- File count, file size, total byte, and depth limits.
- Text scanning only; binary files are fingerprinted and skipped.
- Package install scripts are flagged.
- Remote Git/URL inputs require `--allow-network`.
- Local zip extraction blocks zip-slip paths.

## Current Analyzer Coverage

SkillGuard is inspired by NVIDIA's Python-based
[SkillSpector](https://github.com/NVIDIA/SkillSpector), but it is not a
line-for-line port. It implements the same install-gate classes where they make
sense for a Bun-first scanner:

- prompt injection and hidden instructions;
- system prompt leakage;
- harmful content;
- data exfiltration and secret access;
- privilege escalation;
- supply-chain risk, package lifecycle scripts, dependency hygiene, npm/PyPI
  lockfile discovery, offline advisory fallback, and optional OSV;
- dangerous Python/JavaScript/TypeScript/shell execution constructs;
- source-to-sink taint-flow heuristics, including structured intra-file
  assignment tracking for Python and JavaScript/TypeScript;
- output handling;
- excessive agency;
- memory poisoning;
- rogue-agent persistence and self-modification;
- trigger abuse;
- MCP least-privilege and tool metadata poisoning;
- malware/offensive-tool indicators.

The intentionally deferred piece is native YARA rule execution. Provider-backed
semantic analysis exists, but it is explicit opt-in because it sends candidate
skill content to a model provider.

## AST Analysis

AST means "abstract syntax tree": the scanner parses source into a syntax tree
and inspects the structure of the code without running it. That catches behavior
that plain text matching can miss, for example `exec(requests.get(...))`,
`subprocess.run(...)`, `eval(await fetch(...))`, or aliased
`child_process.exec(...)` calls even if spacing or formatting changes.

SkillGuard uses TypeScript-native parsers for Python and JavaScript/TypeScript
analysis, so the Bun-first package does not require language runtimes to be
installed and does not execute candidate skill code.

## Fixtures

The `fixtures/` corpus includes benign, malicious, and evasive skills used by
the regression tests. The benign fixture is expected to stay quiet for high-risk
findings; malicious and evasive fixtures cover install hooks, secret/file
exfiltration, Python and JavaScript/TypeScript taint flow, encoded execution,
and hidden Unicode.

## CI

See [docs/github-action.md](docs/github-action.md) for strict-gate and SARIF
upload examples.

See [docs/release.md](docs/release.md) for the npm publish order and release
verification checklist.

## Development

```sh
bun install
bun run lint:ws
bun run typecheck
bun run lint
bun run format:check
bun run test
bun run knip
bun run build
bun --filter @stll/skillguard intent:validate
bun run pack:verify
```
