# Contributing

Keep changes small, typed, and backed by fixtures.

Before opening a pull request, run:

```sh
bun run lint:ws
bun run typecheck
bun run check:typecheck-parity
bun run lint
bun fmt --check
bun run test
bun run knip
bun run build
bun --filter @stll/skillguard intent:validate
bun run pack:verify
```

Rules should prefer high-signal detections over broad guesses. If a rule is
heuristic, document why it is useful and add fixtures for true positives and
acceptable false positives.

Type checking uses Bun in each workspace. Editors retain the TypeScript language service because Bun has no language server. Keep TypeScript 6 for the rule parser, lint plugin compiler API, and declaration generation, and native TypeScript 7 for diagnostic parity.
