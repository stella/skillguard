# Releasing SkillGuard

SkillGuard publishes four independently versioned npm packages:

1. `@stll/skillguard-core`
2. `@stll/skillguard-sarif`
3. `@stll/skillguard-rules`
4. `@stll/skillguard`

Add a Changeset to every pull request that changes a published package:

```sh
bun run changeset
```

Choose the affected packages and semantic version bumps. Use an empty Changeset
when a published-package change intentionally needs no release. CI enforces this
release intent.

After the change lands on `main`, the shared release workflow opens or updates
one Version Packages pull request. Merging that pull request updates package
versions, internal dependency ranges, changelogs, and the lockfile. The stable
`.github/workflows/publish.yml` caller then builds one tarball per package and
delegates the privileged npm/GitHub release transaction to the versioned
`stella/.github` contract.

Package releases use immutable `<name>@<version>` tags. The central transaction
publishes internal dependencies before dependants, verifies npm integrity, and
is safe to resume after a partial failure.

## Local release gate

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

A manual `Publish` workflow run with `publish` unchecked performs the build and
pack dry run without registry or GitHub release writes.

Before the first publish, configure npm trusted publishing for each package to
authorize `stella/skillguard` and `.github/workflows/publish.yml`.
