import { expect, test } from "bun:test";
import JSZip from "jszip";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import { InputResolutionError, resolveInput } from "./input";

test("resolves a local directory without cleanup side effects", async () => {
  const directory = await createTempDirectory();
  const resolved = await resolveInput(directory, { allowNetwork: false });

  expect(resolved.scanPath).toBe(directory);
  expect(resolved.type).toBe("directory");
  await resolved.cleanup();
});

test("extracts a local zip safely", async () => {
  const directory = await createTempDirectory();
  const zip = new JSZip();
  zip.file("skill/SKILL.md", "# Test\n");
  const zipPath = nodePath.join(directory, "skill.zip");
  await writeFile(zipPath, await zip.generateAsync({ type: "nodebuffer" }));

  const resolved = await resolveInput(zipPath, { allowNetwork: false });

  expect(resolved.type).toBe("zip");
  expect(resolved.scanPath.endsWith("skill")).toBe(true);
  await resolved.cleanup();
});

test("rejects zip entries that escape the extraction root", async () => {
  const directory = await createTempDirectory();
  const zip = new JSZip();
  zip.file("../escape.txt", "escaped");
  const zipPath = nodePath.join(directory, "malicious.zip");
  await writeFile(zipPath, await zip.generateAsync({ type: "nodebuffer" }));

  let thrown: unknown;

  try {
    await resolveInput(zipPath, { allowNetwork: false });
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(InputResolutionError);
});

test("requires network opt-in for remote inputs", async () => {
  let thrown: unknown;

  try {
    await resolveInput("https://github.com/example/skill", {
      allowNetwork: false,
    });
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(InputResolutionError);
});

const createTempDirectory = (): Promise<string> =>
  mkdtemp(nodePath.join(tmpdir(), "skillguard-input-"));
