import JSZip from "jszip";
import { spawn } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";

const InputSourceType = {
  Directory: "directory",
  File: "file",
  Git: "git",
  Url: "url",
  Zip: "zip",
} as const;

type InputSourceType = (typeof InputSourceType)[keyof typeof InputSourceType];

export type ResolveInputOptions = {
  allowNetwork: boolean;
};

export type ResolvedInput = {
  cleanup: () => Promise<void>;
  original: string;
  scanPath: string;
  type: InputSourceType;
};

export class InputResolutionError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "InputResolutionError";
  }
}

export const resolveInput = async (
  input: string,
  options: ResolveInputOptions,
): Promise<ResolvedInput> => {
  const trimmed = input.trim();

  if (trimmed === "") {
    throw new InputResolutionError("Input path cannot be empty.");
  }

  if (isGitUrl(trimmed)) {
    assertNetworkAllowed(options, "Git URL scanning");
    return cloneGitInput(trimmed);
  }

  if (isHttpUrl(trimmed)) {
    assertNetworkAllowed(options, "URL scanning");
    return downloadUrlInput(trimmed);
  }

  const absolutePath = nodePath.resolve(trimmed);

  let pathStat;
  try {
    pathStat = await stat(absolutePath);
  } catch {
    throw new InputResolutionError(`Input does not exist: ${trimmed}`);
  }

  if (pathStat.isDirectory()) {
    return {
      original: trimmed,
      scanPath: absolutePath,
      type: InputSourceType.Directory,
      cleanup: noopCleanup,
    };
  }

  if (!pathStat.isFile()) {
    throw new InputResolutionError(
      `Input is not a file or directory: ${trimmed}`,
    );
  }

  if (absolutePath.endsWith(".zip")) {
    return extractZipInput({
      bytes: await readFile(absolutePath),
      original: trimmed,
      type: InputSourceType.Zip,
    });
  }

  return wrapSingleFile(absolutePath, trimmed, InputSourceType.File);
};

type ZipInputOptions = {
  bytes: Buffer;
  original: string;
  type: "url" | "zip";
};

const extractZipInput = async ({
  bytes,
  original,
  type,
}: ZipInputOptions): Promise<ResolvedInput> => {
  const tempDir = await createTempDir();
  const extractDir = nodePath.join(tempDir, "extracted");
  await mkdir(extractDir, { recursive: true });

  let zip;
  try {
    zip = await JSZip.loadAsync(bytes);
  } catch {
    await rm(tempDir, { recursive: true, force: true });
    throw new InputResolutionError(`Invalid zip input: ${original}`);
  }

  try {
    const entries = Object.values(zip.files);

    for (const entry of entries) {
      if (entry.dir) {
        continue;
      }

      const targetPath = safeJoin(
        extractDir,
        entry.unsafeOriginalName ?? entry.name,
      );
      await mkdir(nodePath.dirname(targetPath), { recursive: true });
      const content = await entry.async("nodebuffer");
      await writeFile(targetPath, content);
    }
  } catch (error) {
    await rm(tempDir, { recursive: true, force: true });
    throw error;
  }

  return {
    original,
    scanPath: await unwrapSingleRootDirectory(extractDir),
    type,
    cleanup: async () => {
      await rm(tempDir, { recursive: true, force: true });
    },
  };
};

const wrapSingleFile = async (
  absolutePath: string,
  original: string,
  type: InputSourceType,
): Promise<ResolvedInput> => {
  const tempDir = await createTempDir();
  const targetPath = nodePath.join(tempDir, nodePath.basename(absolutePath));
  await cp(absolutePath, targetPath);

  return {
    original,
    scanPath: tempDir,
    type,
    cleanup: async () => {
      await rm(tempDir, { recursive: true, force: true });
    },
  };
};

const downloadUrlInput = async (url: string): Promise<ResolvedInput> => {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(30_000),
  });

  if (!response.ok) {
    throw new InputResolutionError(
      `Failed to download ${url}: ${response.status}`,
    );
  }

  const bytes = Buffer.from(await response.arrayBuffer());
  const contentType = response.headers.get("content-type") ?? "";

  if (url.endsWith(".zip") || contentType.includes("zip")) {
    return extractZipInput({
      bytes,
      original: url,
      type: InputSourceType.Url,
    });
  }

  const tempDir = await createTempDir();
  const fileName = nodePath.basename(new URL(url).pathname) || "SKILL.md";
  await writeFile(nodePath.join(tempDir, fileName), bytes);

  return {
    original: url,
    scanPath: tempDir,
    type: InputSourceType.Url,
    cleanup: async () => {
      await rm(tempDir, { recursive: true, force: true });
    },
  };
};

const cloneGitInput = async (url: string): Promise<ResolvedInput> => {
  const tempDir = await createTempDir();
  const cloneDir = nodePath.join(tempDir, "repo");

  try {
    await runCommand("git", ["clone", "--depth", "1", url, cloneDir], 60_000);
  } catch (error) {
    await rm(tempDir, { recursive: true, force: true });
    const message = error instanceof Error ? error.message : String(error);
    throw new InputResolutionError(`Failed to clone ${url}: ${message}`);
  }

  return {
    original: url,
    scanPath: cloneDir,
    type: InputSourceType.Git,
    cleanup: async () => {
      await rm(tempDir, { recursive: true, force: true });
    },
  };
};

const runCommand = (
  command: string,
  args: readonly string[],
  timeoutMs: number,
): Promise<void> =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      shell: false,
      stdio: ["ignore", "ignore", "pipe"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${command} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const chunks: Buffer[] = [];

    child.stderr.on("data", (chunk: unknown) => {
      if (Buffer.isBuffer(chunk)) {
        chunks.push(chunk);
      }
    });

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timer);

      if (code === 0) {
        resolve();
        return;
      }

      const stderr = Buffer.concat(chunks).toString("utf-8").trim();
      reject(
        new Error(stderr === "" ? `${command} exited with ${code}` : stderr),
      );
    });
  });

const unwrapSingleRootDirectory = async (
  directory: string,
): Promise<string> => {
  const entries = await Array.fromAsync(
    new Bun.Glob("*").scan({
      cwd: directory,
      dot: true,
      onlyFiles: false,
    }),
  );

  if (entries.length !== 1) {
    return directory;
  }

  const onlyEntry = entries.at(0);

  if (onlyEntry === undefined) {
    return directory;
  }

  const candidate = nodePath.join(directory, onlyEntry);
  const candidateStat = await stat(candidate);

  if (candidateStat.isDirectory()) {
    return candidate;
  }

  return directory;
};

const safeJoin = (root: string, unsafePath: string): string => {
  const targetPath = nodePath.resolve(root, unsafePath);
  const relative = nodePath.relative(root, targetPath);

  if (relative.startsWith("..") || nodePath.isAbsolute(relative)) {
    throw new InputResolutionError(
      `Zip entry escapes extraction root: ${unsafePath}`,
    );
  }

  return targetPath;
};

const createTempDir = () => mkdtemp(nodePath.join(tmpdir(), "skillguard-"));

const isHttpUrl = (value: string): boolean =>
  value.startsWith("https://") || value.startsWith("http://");

const isGitUrl = (value: string): boolean => {
  if (value.startsWith("git@") || value.endsWith(".git")) {
    return true;
  }

  if (!isHttpUrl(value)) {
    return false;
  }

  const parsed = new URL(value);

  if (value.includes("/raw/") || value.includes("/blob/")) {
    return false;
  }

  return ["bitbucket.org", "github.com", "gitlab.com"].includes(
    parsed.hostname,
  );
};

const assertNetworkAllowed = (
  options: ResolveInputOptions,
  feature: string,
): void => {
  if (options.allowNetwork) {
    return;
  }

  throw new InputResolutionError(
    `${feature} requires --allow-network because it contacts a remote host.`,
  );
};

const noopCleanup = (): Promise<void> => Promise.resolve();
