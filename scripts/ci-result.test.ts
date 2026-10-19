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

test("the aggregate gate passes only when every selected job succeeded", () => {
  const script = ciWorkflow.jobs["ci-result"].steps[0].run;
  const gate = (event: string, verify: string, changeset: string) =>
    Bun.spawnSync(["bash", "-e", "-c", script], {
      env: {
        PATH: process.env.PATH,
        EVENT_NAME: event,
        VERIFY_RESULT: verify,
        CHANGESET_RESULT: changeset,
      },
    }).exitCode;

  expect(gate("pull_request", "success", "success")).toBe(0);
  expect(gate("merge_group", "success", "skipped")).toBe(0);
  expect(gate("pull_request", "success", "skipped")).not.toBe(0);
  for (const verify of ["failure", "cancelled", "skipped"]) {
    expect(gate("pull_request", verify, "success")).not.toBe(0);
    expect(gate("merge_group", verify, "skipped")).not.toBe(0);
  }
  expect(gate("merge_group", "success", "failure")).not.toBe(0);
});

test("CI and CLA workflows handle merge queue checks", () => {
  expect(ciWorkflow.on.merge_group.types).toEqual(["checks_requested"]);
  expect(claWorkflow.on.merge_group.types).toEqual(["checks_requested"]);
});

test("CI runs the aggregate policy test with the workspace script tests", () => {
  const runs = Object.values(ciWorkflow.jobs)
    .flatMap((job) => job.steps ?? [])
    .map((step) => step.run)
    .filter(Boolean);
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );

  expect(runs).toContain("bun run lint:ws");
  expect(packageJson.scripts["lint:ws"]).toContain("scripts/ci-result.test.ts");
});
