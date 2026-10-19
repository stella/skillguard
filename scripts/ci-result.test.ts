import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const loadWorkflow = (path: string) =>
  Bun.YAML.parse(readFileSync(new URL(path, import.meta.url), "utf8"));

const ciWorkflow = loadWorkflow("../.github/workflows/ci.yml");
const claWorkflow = loadWorkflow("../.github/workflows/cla.yml");

test("the aggregate result depends on every CI validation job", () => {
  const aggregate = ciWorkflow.jobs["ci-result"];
  const validationJobs = Object.keys(ciWorkflow.jobs)
    .filter((job) => job !== "ci-result")
    .toSorted();

  expect(aggregate.needs.toSorted()).toEqual(validationJobs);
  expect(aggregate.if).toBe("always()");
});

test("CI and CLA workflows handle merge queue checks", () => {
  expect(ciWorkflow.on.merge_group.types).toEqual(["checks_requested"]);
  expect(claWorkflow.on.merge_group.types).toEqual(["checks_requested"]);
});

test("CI runs the aggregate policy test directly", () => {
  const runs = Object.values(ciWorkflow.jobs)
    .flatMap((job) => job.steps ?? [])
    .map((step) => step.run)
    .filter(Boolean);

  expect(runs).toContain("bun test ./scripts/ci-result.test.ts");
});
