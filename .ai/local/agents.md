## SkillGuard Development Guidelines

SkillGuard is a local-first security scanner and policy gate for Agent Skills.

### Security Model

- Never execute files from the scanned skill.
- No network access during scanning unless a future option explicitly enables a named, audited integration.
- Treat scanned skill content as attacker-controlled input.
- Do not log secrets, full environment dumps, or private skill contents.
- Keep the scanner deterministic by default: same input, same report.
- Fail closed for parser errors, unsupported archive shapes, and scan limits.
- Keep the generic scanner separate from product-specific install policy.

### Repository Shape

- Bun-first monorepo with workspace packages in `packages/*`.
- Every direct child of `packages/` is published, when public, under the `@stll` scope with a `skillguard` prefix.
- `@stll/skillguard-core` has no runtime dependencies and stays portable TypeScript.
- Bun-only behavior belongs at the CLI/runtime edge, not in the core scanner.
- Use explicit package imports; do not add barrel-only workspace packages.

### Commands

- `bun install`
- `bun run lint:ws`
- `bun run typecheck`
- `bun run lint`
- `bun run test`
- `bun run build`
- `bun run pack:verify`

### Release Lockfile Safety

- Never delete or regenerate `bun.lock` to apply package version bumps. Run
  `bun scripts/check-lockfile-workspace-versions.ts --write`, then
  `bun install --frozen-lockfile`. The synchronizer is the sole owner of cached
  workspace self-versions; dependency-graph changes belong in an explicit install.
- Internal package dependencies must use `workspace:*`; never duplicate a sibling's
  current version in another package manifest. Packaging rewrites the workspace
  protocol to the release version.
- `VERSION` is the sole automatic publish signal. Ordinary package-manifest,
  lockfile, workflow, or tooling changes must not trigger registry writes; use the
  explicit manual workflow only for an intentional recovery publish.
