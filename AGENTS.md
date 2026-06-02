# SkillGuard Development Guidelines

SkillGuard is a local-first security scanner and policy gate for Agent Skills.

## Security Model

- Never execute files from the scanned skill.
- No network access during scanning unless a future option explicitly enables a
  named, audited integration.
- Treat scanned skill content as attacker-controlled input.
- Do not log secrets, full environment dumps, or private skill contents.
- Keep the scanner deterministic by default: same input, same report.
- Fail closed for parser errors, unsupported archive shapes, and scan limits.
- Keep the generic scanner separate from product-specific install policy.

## Repository Shape

- Bun-first monorepo with workspace packages in `packages/*`.
- Every direct child of `packages/` is published, when public, under the `@stll`
  scope with a `skillguard` prefix.
- `@stll/skillguard-core` has no runtime dependencies and stays portable
  TypeScript.
- Bun-only behavior belongs at the CLI/runtime edge, not in the core scanner.
- Use explicit package imports; do not add barrel-only workspace packages.

## TypeScript

- No enums: use `as const` objects and union types.
- Model state with discriminated unions.
- Avoid `any`; use `unknown` plus type guards at untrusted boundaries.
- Prefer exhaustive `switch` checks for internal discriminated unions.
- Do not cast around type errors. Trace the mismatch to the source and narrow it.
- Use `.at(0)` when absence is possible.
- Use named option objects for helpers with 3+ arguments.

## Dependencies

- Keep runtime dependencies minimal and pinned.
- Prefer standard library APIs for parsing and filesystem traversal.
- Add a dependency only when it materially improves security, correctness, or
  maintainability.

## Testing

- Test scanner invariants and malicious fixtures, not only happy paths.
- Add regression fixtures for every high-confidence detection rule.
- Tests must not require network access.

## Commands

- `bun install`
- `bun run lint:ws`
- `bun run typecheck`
- `bun run lint`
- `bun run test`
- `bun run build`
- `bun run pack:verify`
