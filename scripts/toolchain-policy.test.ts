import { describe, expect, test } from "bun:test";

import rootPackage from "../package.json";

const packagePaths = rootPackage.workspaces.flatMap((pattern) =>
  [...new Bun.Glob(`${pattern}/package.json`).scanSync()].toSorted(
    (left, right) => left.localeCompare(right),
  ),
);
const manifestPaths = ["package.json", ...packagePaths];
const bunTypecheck = "bun check --no-pretty --all --project=tsconfig.json";
const dependencyFields = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;

describe("TypeScript toolchain policy", () => {
  test("uses Bun for every workspace typecheck", async () => {
    for (const path of packagePaths) {
      const packageJson = await Bun.file(path).json();
      expect(packageJson.scripts.typecheck).toBe(bunTypecheck);
    }
  });

  test("declares no TypeScript compiler in any manifest", async () => {
    for (const path of manifestPaths) {
      const packageJson = await Bun.file(path).json();
      for (const field of dependencyFields) {
        const names = Object.keys(packageJson[field] ?? {});
        expect({ path, field, names }).toEqual({
          path,
          field,
          names: names.filter(
            (name) => name !== "typescript" && !name.startsWith("@typescript/"),
          ),
        });
      }
    }
  });

  test("builds declarations without a TypeScript compiler", async () => {
    for (const path of packagePaths) {
      const packageJson = await Bun.file(path).json();
      expect(packageJson.scripts.build).toContain("--dts.generator oxc");
    }
  });

  test("delegates seeded failure and clean recovery to the shared probe", async () => {
    const workflow = await Bun.file(
      new URL("../.github/workflows/ci.yml", import.meta.url),
    ).text();
    const proof = workflow
      .split("      - name: Verify typecheck rejects a seeded error\n")
      .at(1)
      ?.split("      - run: bun test scripts/tooling-adoption.test.ts\n")
      .at(0);
    expect(proof?.trim()).toBe(
      "run: bunx --no-install stll-typecheck-probe --project packages/core/tsconfig.json --seed-dir packages/core/src -- bun run typecheck",
    );
    expect(workflow).not.toContain("typecheck-proof.ts");
    expect(workflow).not.toContain("typecheck-proof.log");
    expect(workflow).not.toContain("typecheck-parity");
  });
});
