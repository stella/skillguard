#!/usr/bin/env bun
import {
  PolicyName,
  ScanStatus,
  Severity,
  evaluatePolicy,
  scanPath,
  type Finding,
  type PolicyName as PolicyNameValue,
  type ScanReport,
  type Severity as SeverityValue,
} from "@stll/skillguard-core";
import {
  ScanPreset,
  SemanticProviderName,
  createRuleSet,
  createSemanticReviewRule,
  type ScanPreset as ScanPresetValue,
  type SemanticProviderName as SemanticProviderNameValue,
} from "@stll/skillguard-rules";
import { toSarif } from "@stll/skillguard-sarif";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";

import { resolveInput, type ResolvedInput } from "./input";

type PackageManifest = {
  version: string;
};

const isPackageManifest = (value: unknown): value is PackageManifest =>
  typeof value === "object" &&
  value !== null &&
  "version" in value &&
  typeof value.version === "string";

const readPackageVersion = (): string => {
  const packageJsonUrl = new URL("../package.json", import.meta.url);
  const packageJson: unknown = JSON.parse(readFileSync(packageJsonUrl, "utf8"));

  if (!isPackageManifest(packageJson)) {
    throw new Error("Package manifest is missing a string version.");
  }

  return packageJson.version;
};

const VERSION = readPackageVersion();

const OutputFormat = {
  Json: "json",
  Markdown: "markdown",
  Sarif: "sarif",
  Text: "text",
} as const;

type OutputFormat = (typeof OutputFormat)[keyof typeof OutputFormat];

type ScanCommand = {
  type: "scan";
  allowNetwork: boolean;
  failOn?: SeverityValue;
  format: OutputFormat;
  outputPath?: string;
  policy: PolicyNameValue;
  preset: ScanPresetValue;
  semantic: boolean;
  semanticBaseUrl?: string;
  semanticModel?: string;
  semanticProvider: SemanticProviderNameValue;
  targetPath: string;
};

type CliParseResult =
  | {
      type: "command";
      command: ScanCommand;
    }
  | {
      type: "help";
    }
  | {
      type: "version";
    };

class CliError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CliError";
  }
}

const main = (argv: readonly string[]): number | Promise<number> => {
  const parsed = parseCliArgs(argv);

  switch (parsed.type) {
    case "help":
      process.stdout.write(getHelpText());
      return 0;
    case "version":
      process.stdout.write(`${VERSION}\n`);
      return 0;
    case "command":
      return runScan(parsed.command);
  }

  return assertNever(parsed);
};

const runScan = async (command: ScanCommand): Promise<number> => {
  const resolvedInput = await resolveInput(command.targetPath, {
    allowNetwork: command.allowNetwork,
  });

  try {
    const rules = [
      ...createRuleSet({
        allowNetwork: command.allowNetwork,
        preset: command.preset,
      }),
    ];

    if (command.semantic) {
      rules.push(
        createSemanticReviewRule({
          ...(command.semanticBaseUrl === undefined
            ? {}
            : { baseUrl: command.semanticBaseUrl }),
          ...(command.semanticModel === undefined
            ? {}
            : { model: command.semanticModel }),
          providerName: command.semanticProvider,
        }),
      );
    }

    const report = await scanPath(resolvedInput.scanPath, {
      preset: command.preset,
      rules,
    });
    const evaluation = evaluatePolicy(report, {
      policy: command.policy,
      ...(command.failOn === undefined ? {} : { failOn: command.failOn }),
    });
    const output = formatOutput(
      command.format,
      report,
      evaluation,
      resolvedInput,
    );

    if (command.outputPath === undefined) {
      process.stdout.write(output);
    } else {
      await writeFile(command.outputPath, output);
    }

    if (evaluation.status === ScanStatus.Fail) {
      return 1;
    }

    return 0;
  } finally {
    await resolvedInput.cleanup();
  }
};

type FormatOutputEvaluation = ReturnType<typeof evaluatePolicy>;

const formatOutput = (
  format: OutputFormat,
  report: ScanReport,
  evaluation: FormatOutputEvaluation,
  input: ResolvedInput,
): string => {
  switch (format) {
    case "json":
      return `${JSON.stringify({ input: toInputReport(input), report, evaluation }, null, 2)}\n`;
    case "markdown":
      return formatMarkdownReport(report, evaluation, input);
    case "sarif":
      return `${JSON.stringify(toSarif(report), null, 2)}\n`;
    case "text":
      return formatTextReport(report, evaluation, input);
  }

  return assertNever(format);
};

const formatTextReport = (
  report: ScanReport,
  evaluation: FormatOutputEvaluation,
  input: ResolvedInput,
): string => {
  const lines: string[] = [];

  lines.push(`SkillGuard scan: ${evaluation.status}`);
  lines.push(`Input: ${input.original} (${input.type})`);
  lines.push(`Target: ${report.target.path}`);
  lines.push(`Preset: ${report.target.preset ?? "standard"}`);
  lines.push(
    `Risk: ${report.summary.risk.level} (${report.summary.risk.score}/100)`,
  );
  lines.push(
    `Files: ${report.summary.files.scanned} scanned, ${report.summary.files.skipped} skipped`,
  );
  lines.push(
    `Findings: critical ${report.summary.findings.critical}, high ${report.summary.findings.high}, medium ${report.summary.findings.medium}, low ${report.summary.findings.low}, info ${report.summary.findings.info}`,
  );
  lines.push(`Policy: fail on ${evaluation.failOn}`);

  if (report.findings.length === 0) {
    lines.push("");
    lines.push("No findings.");
    return `${lines.join("\n")}\n`;
  }

  lines.push("");

  for (const finding of report.findings) {
    lines.push(formatFinding(finding));
  }

  return `${lines.join("\n")}\n`;
};

const formatMarkdownReport = (
  report: ScanReport,
  evaluation: FormatOutputEvaluation,
  input: ResolvedInput,
): string => {
  const lines: string[] = [
    "# SkillGuard Report",
    "",
    `- Status: **${evaluation.status}**`,
    `- Input: \`${input.original}\` (${input.type})`,
    `- Target: \`${report.target.path}\``,
    `- Preset: \`${report.target.preset ?? "standard"}\``,
    `- Policy: fail on \`${evaluation.failOn}\``,
    `- Risk: **${report.summary.risk.level}** (${report.summary.risk.score}/100)`,
    `- Recommendation: ${report.summary.risk.recommendation}`,
    `- Files: ${report.summary.files.scanned} scanned, ${report.summary.files.skipped} skipped`,
    "",
    "## Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No findings.");
    return `${lines.join("\n")}\n`;
  }

  lines.push("| Severity | Rule | Location | Message |");
  lines.push("| --- | --- | --- | --- |");

  for (const finding of report.findings) {
    lines.push(
      `| ${finding.severity} | \`${finding.ruleId}\` | ${markdownEscape(formatLocation(finding) || "-")} | ${markdownEscape(finding.message)} |`,
    );
  }

  return `${lines.join("\n")}\n`;
};

const formatFinding = (finding: Finding): string => {
  const location = formatLocation(finding);

  if (location === "") {
    return `[${finding.severity.toUpperCase()}] ${finding.ruleId}: ${finding.message}`;
  }

  return `[${finding.severity.toUpperCase()}] ${finding.ruleId} ${location}: ${finding.message}`;
};

const formatLocation = (finding: Finding): string => {
  if (finding.location === undefined) {
    return "";
  }

  const parts = [finding.location.path];

  if (finding.location.line !== undefined) {
    parts.push(String(finding.location.line));
  }

  if (finding.location.column !== undefined) {
    parts.push(String(finding.location.column));
  }

  return parts.join(":");
};

export const parseCliArgs = (argv: readonly string[]): CliParseResult => {
  const commandName = argv.at(0);

  if (
    commandName === undefined ||
    commandName === "-h" ||
    commandName === "--help"
  ) {
    return { type: "help" };
  }

  if (commandName === "-v" || commandName === "--version") {
    return { type: "version" };
  }

  if (commandName !== "scan") {
    throw new CliError(`Unknown command: ${commandName}`);
  }

  return {
    type: "command",
    command: parseScanCommand(argv.slice(1)),
  };
};

const parseScanCommand = (argv: readonly string[]): ScanCommand => {
  let allowNetwork = false;
  let failOn: SeverityValue | undefined;
  let format: OutputFormat = OutputFormat.Text;
  let outputPath: string | undefined;
  let policy: PolicyNameValue = PolicyName.Standard;
  let preset: ScanPresetValue = ScanPreset.Standard;
  let semantic = false;
  let semanticBaseUrl: string | undefined;
  let semanticModel: string | undefined;
  let semanticProvider: SemanticProviderNameValue = SemanticProviderName.OpenAi;
  let targetPath: string | undefined;

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];

    if (arg === undefined) {
      continue;
    }

    if (arg === "--format") {
      index += 1;
      format = parseOutputFormat(readOptionValue(argv, index, arg));
      continue;
    }

    if (arg.startsWith("--format=")) {
      format = parseOutputFormat(readInlineOptionValue(arg, "--format="));
      continue;
    }

    if (arg === "--output" || arg === "-o") {
      index += 1;
      outputPath = readOptionValue(argv, index, arg);
      continue;
    }

    if (arg.startsWith("--output=")) {
      outputPath = readInlineOptionValue(arg, "--output=");
      continue;
    }

    if (arg === "--allow-network") {
      allowNetwork = true;
      continue;
    }

    if (arg === "--semantic") {
      semantic = true;
      continue;
    }

    if (arg === "--semantic-provider") {
      index += 1;
      semanticProvider = parseSemanticProvider(
        readOptionValue(argv, index, arg),
      );
      continue;
    }

    if (arg.startsWith("--semantic-provider=")) {
      semanticProvider = parseSemanticProvider(
        readInlineOptionValue(arg, "--semantic-provider="),
      );
      continue;
    }

    if (arg === "--semantic-model") {
      index += 1;
      semanticModel = readOptionValue(argv, index, arg);
      continue;
    }

    if (arg.startsWith("--semantic-model=")) {
      semanticModel = readInlineOptionValue(arg, "--semantic-model=");
      continue;
    }

    if (arg === "--semantic-base-url") {
      index += 1;
      semanticBaseUrl = readOptionValue(argv, index, arg);
      continue;
    }

    if (arg.startsWith("--semantic-base-url=")) {
      semanticBaseUrl = readInlineOptionValue(arg, "--semantic-base-url=");
      continue;
    }

    if (arg === "--policy") {
      index += 1;
      policy = parsePolicyName(readOptionValue(argv, index, arg));
      continue;
    }

    if (arg.startsWith("--policy=")) {
      policy = parsePolicyName(readInlineOptionValue(arg, "--policy="));
      continue;
    }

    if (arg === "--preset") {
      index += 1;
      preset = parseScanPreset(readOptionValue(argv, index, arg));
      continue;
    }

    if (arg.startsWith("--preset=")) {
      preset = parseScanPreset(readInlineOptionValue(arg, "--preset="));
      continue;
    }

    if (arg === "--fail-on") {
      index += 1;
      failOn = parseSeverity(readOptionValue(argv, index, arg));
      continue;
    }

    if (arg.startsWith("--fail-on=")) {
      failOn = parseSeverity(readInlineOptionValue(arg, "--fail-on="));
      continue;
    }

    if (arg.startsWith("-")) {
      throw new CliError(`Unknown option: ${arg}`);
    }

    if (targetPath !== undefined) {
      throw new CliError(`Unexpected extra path: ${arg}`);
    }

    targetPath = arg;
  }

  if (targetPath === undefined) {
    throw new CliError("Missing scan target path.");
  }

  if (semantic && !allowNetwork) {
    throw new CliError("--semantic requires --allow-network.");
  }

  return {
    type: "scan",
    allowNetwork,
    format,
    policy,
    preset,
    semantic,
    semanticProvider,
    targetPath,
    ...(failOn === undefined ? {} : { failOn }),
    ...(outputPath === undefined ? {} : { outputPath }),
    ...(semanticBaseUrl === undefined ? {} : { semanticBaseUrl }),
    ...(semanticModel === undefined ? {} : { semanticModel }),
  };
};

const readOptionValue = (
  argv: readonly string[],
  index: number,
  optionName: string,
): string => {
  const value = argv.at(index);

  if (value === undefined || value.startsWith("-")) {
    throw new CliError(`Missing value for ${optionName}.`);
  }

  return value;
};

const readInlineOptionValue = (arg: string, prefix: string): string => {
  const value = arg.slice(prefix.length);

  if (value === "") {
    throw new CliError(`Missing value for ${prefix.slice(0, -1)}.`);
  }

  return value;
};

const parseOutputFormat = (value: string): OutputFormat => {
  switch (value) {
    case "json":
      return OutputFormat.Json;
    case "markdown":
    case "md":
      return OutputFormat.Markdown;
    case "sarif":
      return OutputFormat.Sarif;
    case "text":
      return OutputFormat.Text;
    default:
      throw new CliError(`Unsupported format: ${value}`);
  }
};

const parseScanPreset = (value: string): ScanPresetValue => {
  switch (value) {
    case "paranoid":
      return ScanPreset.Paranoid;
    case "quick":
      return ScanPreset.Quick;
    case "standard":
      return ScanPreset.Standard;
    case "strict":
      return ScanPreset.Strict;
    default:
      throw new CliError(`Unsupported preset: ${value}`);
  }
};

const parseSemanticProvider = (value: string): SemanticProviderNameValue => {
  switch (value) {
    case "openai":
      return SemanticProviderName.OpenAi;
    case "openai-compatible":
      return SemanticProviderName.OpenAiCompatible;
    default:
      throw new CliError(`Unsupported semantic provider: ${value}`);
  }
};

const parsePolicyName = (value: string): PolicyNameValue => {
  switch (value) {
    case "advisory":
      return PolicyName.Advisory;
    case "standard":
      return PolicyName.Standard;
    case "strict":
      return PolicyName.Strict;
    default:
      throw new CliError(`Unsupported policy: ${value}`);
  }
};

const parseSeverity = (value: string): SeverityValue => {
  switch (value) {
    case "critical":
      return Severity.Critical;
    case "high":
      return Severity.High;
    case "info":
      return Severity.Info;
    case "low":
      return Severity.Low;
    case "medium":
      return Severity.Medium;
    default:
      throw new CliError(`Unsupported severity: ${value}`);
  }
};

const getHelpText = (): string => `SkillGuard ${VERSION}

Usage:
  skillguard scan <path> [options]

Options:
  --format <text|json|markdown|sarif>
                               Output format. Default: text
  --output, -o <path>          Write report to a file
  --preset <name>              quick, standard, strict, or paranoid. Default: standard
  --policy <name>              advisory, standard, or strict. Default: standard
  --fail-on <severity>         Override policy threshold
  --allow-network              Allow remote inputs and network-enabled analyzers
  --semantic                   Run explicit opt-in semantic review. Requires --allow-network
  --semantic-provider <name>   openai or openai-compatible. Default: openai
  --semantic-model <model>     Override semantic review model
  --semantic-base-url <url>    Override OpenAI-compatible base URL
  --help                       Show help
  --version                    Show version
`;

const toInputReport = (input: ResolvedInput) => ({
  original: input.original,
  resolvedPath: input.scanPath,
  type: input.type,
});

const markdownEscape = (value: string): string =>
  value.replaceAll("|", "\\|").replaceAll("\n", " ");

const assertNever = (value: never): never => {
  throw new CliError(`Unhandled value: ${String(value)}`);
};

if (import.meta.main) {
  try {
    const exitCode = await main(process.argv.slice(2));
    process.exitCode = exitCode;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`error: ${message}\n`);
    process.exitCode = 1;
  }
}
