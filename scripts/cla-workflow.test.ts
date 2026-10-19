import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const workflow = Bun.YAML.parse(
  readFileSync(
    new URL("../.github/workflows/cla.yml", import.meta.url),
    "utf8",
  ),
);

const bots = [
  "dependabot[bot]",
  "renovate[bot]",
  "github-actions[bot]",
  "stella-provenance-updater[bot]",
];

test("CLA covers every pull request and only signing or recheck comments", () => {
  expect(workflow.on.pull_request_target.types).toEqual([
    "opened",
    "synchronize",
    "reopened",
    "closed",
  ]);
  expect(workflow.on.issue_comment.types).toEqual(["created"]);
  expect(workflow.jobs.cla.if.trim().replace(/\s+/gu, " ")).toBe(
    "( github.event_name == 'pull_request_target' ) || ( github.event_name == 'issue_comment' && github.event.issue.pull_request && ( github.event.comment.body == 'recheck' || github.event.comment.body == 'I have read the CLA Document and I hereby sign the CLA' ) )",
  );
});

test("the SHA-pinned shared CLA workflow owns bot exemptions", () => {
  const allowlist = workflow.jobs.cla.with.allowlist.split(",");
  for (const bot of bots) expect(allowlist).toContain(bot);
  expect(workflow.jobs.cla.uses).toMatch(
    /^stella\/\.github\/\.github\/workflows\/cla\.yml@[a-f0-9]{40}$/u,
  );
  expect(workflow.jobs.cla.secrets.CLA_APP_PRIVATE_KEY).toBe(
    "${{ secrets.CLA_APP_PRIVATE_KEY }}",
  );
});
