---
name: security-scan
description: Run SkillGuard before installing third-party Agent Skills, with optional semantic review only when the user explicitly allows network/model use.
---

# SkillGuard Security Scan

Use this skill before installing or enabling a third-party Agent Skill.

## Default Static Scan

Run a deterministic local scan first:

```sh
skillguard scan <skill-path> --preset strict --policy strict
```

Do not install the skill if the scan fails unless the user explicitly accepts
the risk after reviewing the findings.

## Semantic Review

Run semantic review only when the user explicitly approves sending the candidate
skill content to a model provider:

```sh
skillguard scan <skill-path> \
  --preset paranoid \
  --policy strict \
  --allow-network \
  --semantic \
  --semantic-provider openai
```

Semantic review requires provider credentials, normally `OPENAI_API_KEY`. For
OpenAI-compatible local endpoints, use:

```sh
skillguard scan <skill-path> \
  --preset paranoid \
  --policy strict \
  --allow-network \
  --semantic \
  --semantic-provider openai-compatible \
  --semantic-base-url http://localhost:11434/v1
```

Never include unrelated user documents, chat history, workspace secrets, or
credentials in the scan target.
