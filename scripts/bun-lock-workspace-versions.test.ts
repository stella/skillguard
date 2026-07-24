import { describe, expect, test } from "bun:test";
import { readdir } from "node:fs/promises";
import { join } from "node:path";

import packageJson from "../package.json";
import { syncWorkspaceVersions } from "./lib/bun-lock-workspace-versions";

const ROOT = join(import.meta.dirname, "..");
const readJson = async (path: string): Promise<Record<string, unknown>> =>
  JSON.parse(await Bun.file(path).text());
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const fixture = `{
  "lockfileVersion": 1,
  "workspaces": {
    "packages/core": {
      "name": "@stll/core",
      "version": "1.0.0",
      "dependencies": { "version": "do-not-touch" },
    },
    "packages/escaped\\u002dname": { "version": "2.0.0" },
  },
  "packages": [{ "version": "also-do-not-touch" }],
}\n`;

describe("bun.lock workspace self-version synchronization", () => {
  test("changes only the exact workspace version string spans", () => {
    const result = syncWorkspaceVersions(
      fixture,
      new Map([
        ["packages/core", "1.1.0"],
        ["packages/escaped-name", "2.1.0"],
      ]),
    );

    expect(result.mismatches).toHaveLength(2);
    expect(result.text).toBe(
      fixture
        .replace('"version": "1.0.0"', '"version": "1.1.0"')
        .replace('"version": "2.0.0"', '"version": "2.1.0"'),
    );
    expect(result.text).toContain('"version": "do-not-touch"');
    expect(result.text).toContain('"version": "also-do-not-touch"');
  });

  test("version-up/version-down is byte-identical", () => {
    const up = syncWorkspaceVersions(
      fixture,
      new Map([["packages/core", "1.1.0"]]),
    ).text;
    const down = syncWorkspaceVersions(
      up,
      new Map([["packages/core", "1.0.0"]]),
    ).text;

    expect(down).toBe(fixture);
  });

  test("refuses to invent missing workspace structure", () => {
    const result = syncWorkspaceVersions(
      fixture,
      new Map([["packages/missing", "1.0.0"]]),
    );

    expect(result.text).toBe(fixture);
    expect(result.mismatches).toEqual([
      { workspace: "packages/missing", expected: "1.0.0", actual: null },
    ]);
  });

  test("release versioning cannot delete or regenerate bun.lock", () => {
    const command = packageJson.scripts["changeset:version"];

    expect(command).not.toMatch(/\brm\b/);
    expect(command).toContain("check-lockfile-workspace-versions.ts --write");
    expect(command).toEndWith("bun install --frozen-lockfile");
  });

  test("workspace dependencies cannot duplicate sibling versions", async () => {
    const packageDirs = (
      await readdir(join(ROOT, "packages"), { withFileTypes: true })
    )
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
    const manifests = await Promise.all(
      packageDirs.map((directory) =>
        readJson(join(ROOT, "packages", directory, "package.json")),
      ),
    );
    const workspaceNames = new Set(
      manifests.flatMap((manifest) =>
        typeof manifest.name === "string" ? [manifest.name] : [],
      ),
    );

    for (const manifest of manifests) {
      for (const sectionName of [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
      ]) {
        const section = manifest[sectionName];
        if (!isRecord(section)) continue;
        for (const [dependency, specifier] of Object.entries(section)) {
          if (!workspaceNames.has(dependency)) continue;
          expect(specifier).toBe("workspace:*");
        }
      }
    }
  });

  test("release packaging must rewrite workspace protocol dependencies", async () => {
    const publishWorkflow = await Bun.file(
      join(ROOT, ".github/workflows/publish.yml"),
    ).text();
    const packVerifier = await Bun.file(
      join(ROOT, "scripts/verify-pack.sh"),
    ).text();

    expect(publishWorkflow).toContain("bun pm pack");
    expect(packVerifier).toContain("bun pm pack");
    expect(publishWorkflow).not.toMatch(/\bnpm pack\b/);
    expect(packVerifier).not.toMatch(/\bnpm pack\b/);
  });
});
