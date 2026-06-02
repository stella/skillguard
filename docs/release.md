# Release Checklist

SkillGuard publishes four npm packages:

1. `@stll/skillguard-core`
2. `@stll/skillguard-sarif`
3. `@stll/skillguard-rules`
4. `@stll/skillguard`

Run the local release gate before publishing:

```sh
bun install --frozen-lockfile
bun run lint:ws
bun run typecheck
bun run lint
bun run format:check
bun run test
bun run knip
bun --filter @stll/skillguard intent:validate
bun run pack:verify
```

Publish from a clean, tagged commit on `main`:

```sh
npm publish packages/core --access public
npm publish packages/sarif --access public
npm publish packages/rules --access public
npm publish packages/cli --access public
```

After publishing, verify the user-facing command from a clean directory:

```sh
bunx @stll/skillguard scan ./skill --preset strict --policy strict
```
