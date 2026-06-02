# SkillGuard

Local-first security scanner and policy gate for third-party Agent Skills.

```sh
bunx @stll/skillguard scan ./skill --preset strict --policy strict
```

SkillGuard scans candidate skill packages without executing them. Network access
is disabled unless `--allow-network` is set. Optional semantic review is
available with `--semantic`, but it sends a bounded, redacted review packet to
the configured model provider and must be explicitly enabled.

Repository and documentation:

https://github.com/stella/skillguard
