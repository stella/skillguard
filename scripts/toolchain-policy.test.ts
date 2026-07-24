import { describe, expect, test } from "bun:test";

import rootPackage from "../package.json";
import cliPackage from "../packages/cli/package.json";
import corePackage from "../packages/core/package.json";
import rulesPackage from "../packages/rules/package.json";
import sarifPackage from "../packages/sarif/package.json";

const packages = [cliPackage, corePackage, rulesPackage, sarifPackage];
const nativeTypecheck =
  "bun ../../scripts/tsc-native.ts --noEmit -p tsconfig.json";

describe("TypeScript toolchain policy", () => {
  test("pins native TypeScript 7 for every typecheck", () => {
    expect(rootPackage.devDependencies["@typescript/native"]).toBe(
      "npm:typescript@7.0.2",
    );
    for (const packageJson of packages) {
      expect(packageJson.scripts.typecheck).toBe(nativeTypecheck);
    }
  });

  test("keeps classic TypeScript 6 scoped to compiler-API consumers", () => {
    expect(rootPackage.devDependencies.typescript).toBe("6.0.3");
    expect(rulesPackage.dependencies.typescript).toBe("6.0.3");
  });
});
