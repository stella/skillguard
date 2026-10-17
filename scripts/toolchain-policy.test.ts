import { describe, expect, test } from "bun:test";

import rootPackage from "../package.json";
import rulesPackage from "../packages/rules/package.json";

const packagePaths = rootPackage.workspaces.flatMap((pattern) =>
  [...new Bun.Glob(`${pattern}/package.json`).scanSync()].toSorted(
    (left, right) => left.localeCompare(right),
  ),
);
const bunTypecheck = "bun check --no-pretty --all --project=tsconfig.json";

describe("TypeScript toolchain policy", () => {
  test("uses Bun for every workspace typecheck and retains the parity compiler", async () => {
    expect(rootPackage.devDependencies["@typescript/native"]).toBe(
      "npm:typescript@7.0.2",
    );
    for (const path of packagePaths) {
      const packageJson = await Bun.file(path).json();
      expect(packageJson.scripts.typecheck).toBe(bunTypecheck);
    }
  });

  test("parity covers every workspace typecheck project", () => {
    expect(rootPackage.scripts["check:typecheck-parity"]).toBe(
      [
        "stll-typecheck-parity",
        ...packagePaths.map(
          (path) =>
            `--project ${path.replace(/package\.json$/, "tsconfig.json")}`,
        ),
      ].join(" "),
    );
  });

  test("keeps classic TypeScript 6 scoped to compiler-API consumers", () => {
    expect(rootPackage.devDependencies.typescript).toBe("6.0.3");
    expect(rulesPackage.dependencies.typescript).toBe("6.0.3");
  });

  test("delegates seeded failure and clean recovery to the shared probe", async () => {
    const workflow = await Bun.file(
      new URL("../.github/workflows/ci.yml", import.meta.url),
    ).text();
    const proof = workflow
      .split("      - name: Verify typecheck rejects a seeded error\n")
      .at(1)
      ?.split("      - name: Detect toolchain changes\n")
      .at(0);
    expect(proof?.trim()).toBe(
      "run: bunx --no-install stll-typecheck-probe --project packages/core/tsconfig.json --seed-dir packages/core/src -- bun run typecheck",
    );
    expect(workflow).not.toContain("typecheck-proof.ts");
    expect(workflow).not.toContain("typecheck-proof.log");
  });
});
