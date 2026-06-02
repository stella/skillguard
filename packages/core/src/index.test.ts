import { expect, test } from "bun:test";
import { mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import {
  FindingCategory,
  Severity,
  createFinding,
  evaluatePolicy,
  scanPath,
  type Rule,
} from "./index";

test("scanPath scans text files without including file contents in report files", async () => {
  const directory = await mkdtemp(nodePath.join(tmpdir(), "skillguard-core-"));
  await writeFile(nodePath.join(directory, "SKILL.md"), "# Test skill\n");

  const report = await scanPath(directory);
  const scannedFile = report.files.find((file) => file.path === "SKILL.md");

  expect(scannedFile?.type).toBe("text");
  expect("content" in (scannedFile ?? {})).toBe(false);
});

test("scanPath does not follow symlinks", async () => {
  const directory = await mkdtemp(nodePath.join(tmpdir(), "skillguard-core-"));
  await writeFile(nodePath.join(directory, "secret.txt"), "secret\n");
  await symlink(
    nodePath.join(directory, "secret.txt"),
    nodePath.join(directory, "secret-link.txt"),
  );

  const report = await scanPath(directory);

  expect(report.files.some((file) => file.type === "symlink")).toBe(true);
  expect(
    report.findings.some((finding) => finding.title === "Symlink skipped"),
  ).toBe(true);
});

test("evaluatePolicy fails on configured severity threshold", async () => {
  const directory = await mkdtemp(nodePath.join(tmpdir(), "skillguard-core-"));
  await writeFile(nodePath.join(directory, "SKILL.md"), "# Test skill\n");

  const rule: Rule = {
    id: "skillguard.test",
    title: "Test rule",
    category: FindingCategory.ScanIntegrity,
    confidence: 1,
    description: "Test rule",
    defaultSeverity: Severity.High,
    run: () => [
      createFinding(rule, {
        message: "Test finding",
        location: {
          path: "SKILL.md",
        },
      }),
    ],
  };
  const report = await scanPath(directory, { rules: [rule] });
  const evaluation = evaluatePolicy(report, { failOn: Severity.High });

  expect(evaluation.status).toBe("fail");
  expect(evaluation.blockingFindings).toHaveLength(1);
});
