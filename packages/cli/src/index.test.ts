import { expect, test } from "bun:test";

import { parseCliArgs } from "./index";

test("parses scan command options", () => {
  const parsed = parseCliArgs([
    "scan",
    "./fixture",
    "--format",
    "markdown",
    "--policy=strict",
    "--preset",
    "paranoid",
    "--allow-network",
    "--semantic",
    "--semantic-provider=openai-compatible",
    "--semantic-model",
    "gpt-5.4-mini",
    "--semantic-base-url",
    "http://localhost:11434/v1",
    "--fail-on",
    "medium",
  ]);

  expect(parsed.type).toBe("command");

  if (parsed.type !== "command") {
    return;
  }

  expect(parsed.command.targetPath).toBe("./fixture");
  expect(parsed.command.format).toBe("markdown");
  expect(parsed.command.policy).toBe("strict");
  expect(parsed.command.preset).toBe("paranoid");
  expect(parsed.command.allowNetwork).toBe(true);
  expect(parsed.command.semantic).toBe(true);
  expect(parsed.command.semanticProvider).toBe("openai-compatible");
  expect(parsed.command.semanticModel).toBe("gpt-5.4-mini");
  expect(parsed.command.semanticBaseUrl).toBe("http://localhost:11434/v1");
  expect(parsed.command.failOn).toBe("medium");
});

test("semantic review requires network opt-in", () => {
  expect(() => parseCliArgs(["scan", "./fixture", "--semantic"])).toThrow(
    "--semantic requires --allow-network.",
  );
});
