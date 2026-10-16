import { library } from "@stll/oxlint-config";
import {
  portableSafetyPluginSpecifiers,
  portableSafetyRules,
} from "@stll/oxlint-plugin";
import { describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import config from "../oxlint.config";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (path: string) => readFileSync(join(root, path), "utf8");

// Each fixture exercises the actual syntax and options of its declared rule.
const sonarFixtures = {
  "code-eval":
    'import vm from "node:vm";\n\nexport const inspect = (input) => vm.runInNewContext(input);',
  "confidential-information-logging":
    'import { Signale } from "signale";\n\nexport const logger = new Signale();',
  "no-hardcoded-secrets":
    'export const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";',
  "no-identical-conditions":
    "export const inspect = (input) => { if (input === 1) return 2; else if (input === 1) return 3; return 4; };",
  "no-identical-functions":
    "export const first = (value) => {\nconst result = value + 1;\nconst doubled = result * 2;\nreturn doubled + 3;\n};\nexport const second = (value) => {\nconst result = value + 1;\nconst doubled = result * 2;\nreturn doubled + 3;\n};",
  "no-inverted-boolean-check":
    "export const inspect = (left, right) => !(left === right);",
  "no-unthrown-error":
    'export const inspect = () => { new Error("problem"); };',
  "slow-regex": "export const inspect = (input) => /a+$/u.test(input);",
  "stateful-regex":
    'const pattern = /match/g; export const first = pattern.test("first"); export const second = pattern.test("second");',
};

describe("shared tooling adoption", () => {
  test("adds the complete portable pack without weakening shared defaults", () => {
    const central = library({
      jsPlugins: [...portableSafetyPluginSpecifiers],
      rules: { ...portableSafetyRules },
    });
    for (const [name, disposition] of Object.entries(central.rules ?? {})) {
      expect(config.rules?.[name]).toEqual(disposition);
    }
    expect(config.overrides).toHaveLength(central.overrides?.length ?? 0);
    for (const [index, override] of (central.overrides ?? []).entries()) {
      expect(config.overrides?.at(index)).toMatchObject(override);
    }
    const retained = Object.keys(config.rules ?? {})
      .filter((name) => name.startsWith("sonarjs/"))
      .map((name) => name.slice("sonarjs/".length))
      .toSorted();
    expect(retained).toEqual(Object.keys(sonarFixtures).toSorted());
  });

  test("measures shared coverage against every retained Sonar check", () => {
    const directory = mkdtempSync(join(root, ".tooling-coverage-"));
    const lint = (name: string, candidate: ReturnType<typeof library>) => {
      const path = join(directory, `${name}.json`);
      writeFileSync(
        path,
        JSON.stringify({
          ...candidate,
          // These JS syntax fixtures do not need a TypeScript project.
          options: { ...candidate.options, typeAware: false },
        }),
      );
      const result = spawnSync(
        "bun",
        [
          "--bun",
          "oxlint",
          "-c",
          path,
          "--format",
          "json",
          ...Object.keys(sonarFixtures).map((rule) =>
            join(directory, `${rule}.js`),
          ),
        ],
        { cwd: root, encoding: "utf8" },
      );
      expect(result.status).toBe(1);
      const output = JSON.parse(result.stdout);
      expect(output.diagnostics).toBeArray();
      return output.diagnostics;
    };
    try {
      for (const [name, source] of Object.entries(sonarFixtures)) {
        writeFileSync(join(directory, `${name}.js`), source);
      }
      const central = lint(
        "central",
        library({
          jsPlugins: [...portableSafetyPluginSpecifiers],
          rules: { ...portableSafetyRules },
        }),
      );
      const retained = lint("retained", config);
      for (const name of Object.keys(sonarFixtures)) {
        expect(
          retained.some(
            (diagnostic: { code: string; filename: string }) =>
              diagnostic.filename.endsWith(`/${name}.js`) &&
              diagnostic.code.includes(name),
          ),
        ).toBe(true);
      }
      const sharedMatches = Object.keys(sonarFixtures).filter((name) =>
        central.some((diagnostic: { filename: string }) =>
          diagnostic.filename.endsWith(`/${name}.js`),
        ),
      );
      expect(sharedMatches).toEqual([
        "no-identical-conditions",
        "no-unthrown-error",
      ]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("cloud generation is reproducible and third-party quarantine stays enabled", () => {
    const paths = [".agents/cloud-setup.sh", ".claude/settings.json"];
    const before = paths.map(read);
    execFileSync("bunx", ["--no-install", "stll-cloud-setup"], { cwd: root });
    expect(paths.map(read)).toEqual(before);
    const bunfig = Bun.TOML.parse(read("bunfig.toml"));
    expect(bunfig.install.minimumReleaseAge).toBe(432_000);
    expect(bunfig.install.minimumReleaseAgeExcludes.toSorted()).toEqual([
      "@stll/oxlint-config",
      "@stll/oxlint-plugin",
      "@stll/typescript-config",
    ]);
    for (const workflow of ["quarantine-policy", "quarantine-prune"]) {
      expect(read(`.github/workflows/${workflow}.yml`)).toContain(
        `uses: stella/.github/.github/workflows/${workflow}.yml@`,
      );
    }
  });

  test("parity uses the shared detector and complete Git history", () => {
    const workflow = read(".github/workflows/ci.yml")
      .split("  verify:\n")
      .at(1);
    expect(workflow).toContain("fetch-depth: 0");
    expect(workflow).toContain('stll-toolchain-changed --since "$BASE_REF"');
    expect(workflow).toContain("github.event.pull_request.base.sha");
    expect(workflow).toContain("github.event.before");
    expect(workflow).toContain("unavailable-toolchain-base");
    expect(workflow).toContain("if: steps.toolchain.outputs.changed == 'true'");
  });
});
