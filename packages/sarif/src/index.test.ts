import type { ScanReport } from "@stll/skillguard-core";
import { expect, test } from "bun:test";

import { toSarif } from "./index";

test("converts findings to SARIF results", () => {
  const report: ScanReport = {
    schemaVersion: "skillguard.report.v1",
    target: {
      path: "/tmp/skill",
    },
    summary: {
      files: {
        scanned: 1,
        skipped: 0,
        total: 1,
      },
      bytes: {
        scanned: 12,
      },
      findings: {
        critical: 0,
        high: 1,
        info: 0,
        low: 0,
        medium: 0,
      },
      risk: {
        level: "medium",
        recommendation: "Require manual review before trusting this skill.",
        score: 18,
      },
      maxSeverity: "high",
    },
    files: [],
    findings: [
      {
        ruleId: "skillguard.test",
        title: "Test finding",
        severity: "high",
        message: "Test message",
        location: {
          path: "SKILL.md",
          line: 3,
          column: 5,
        },
      },
    ],
  };

  const sarif = toSarif(report);
  const result = sarif.runs.at(0)?.results.at(0);

  expect(result?.level).toBe("error");
  expect(result?.ruleId).toBe("skillguard.test");
});
