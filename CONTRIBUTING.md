# Contributing

Keep changes small, typed, and backed by fixtures.

Before opening a pull request, run:

```sh
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

Rules should prefer high-signal detections over broad guesses. If a rule is
heuristic, document why it is useful and add fixtures for true positives and
acceptable false positives.

Type checking uses Bun in each workspace. The rule parser uses oxc-parser and declarations are built with the oxc generator, so no workspace package needs a TypeScript compiler. The root does not declare one either. Editors keep their bundled TypeScript language service because Bun has no language server.
