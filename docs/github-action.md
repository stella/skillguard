# GitHub Actions

SkillGuard can run in CI as an install gate for third-party skills or as a SARIF
producer for GitHub code scanning.

## Strict Gate

```yaml
name: SkillGuard

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: oven-sh/setup-bun@v2
        with:
          bun-version: 1.3.14
      - run: >
          bunx @stll/skillguard scan ./skills
          --preset strict
          --policy strict
```

## SARIF Upload

```yaml
name: SkillGuard SARIF

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: oven-sh/setup-bun@v2
        with:
          bun-version: 1.3.14
      - run: >
          bunx @stll/skillguard scan ./skills
          --preset paranoid
          --policy advisory
          --format sarif
          --output skillguard.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: skillguard.sarif
```

Remote Git, URL, zip downloads, and live OSV lookups require `--allow-network`.
Keep that flag off for deterministic offline CI unless the workflow explicitly
needs network-backed dependency vulnerability checks.

## Semantic Review Gate

Semantic review is optional because it sends candidate skill content to a model
provider. Use it only for scan targets that contain the third-party skill being
evaluated, not a broad workspace root.

```yaml
name: SkillGuard Semantic Review

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: oven-sh/setup-bun@v2
        with:
          bun-version: 1.3.14
      - run: >
          bunx @stll/skillguard scan ./skills
          --preset paranoid
          --policy strict
          --allow-network
          --semantic
          --semantic-provider openai
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```
