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
});
