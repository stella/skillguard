import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import nodePath from "node:path";

export const Severity = {
  Critical: "critical",
  High: "high",
  Info: "info",
  Low: "low",
  Medium: "medium",
} as const;

export type Severity = (typeof Severity)[keyof typeof Severity];

export const PolicyName = {
  Advisory: "advisory",
  Standard: "standard",
  Strict: "strict",
} as const;

export type PolicyName = (typeof PolicyName)[keyof typeof PolicyName];

export const ScanStatus = {
  Fail: "fail",
  Pass: "pass",
} as const;

export type ScanStatus = (typeof ScanStatus)[keyof typeof ScanStatus];

export const FindingCategory = {
  DataExfiltration: "data-exfiltration",
  DangerousCode: "dangerous-code",
  DependencyVulnerability: "dependency-vulnerability",
  ExcessiveAgency: "excessive-agency",
  HarmfulContent: "harmful-content",
  HiddenContent: "hidden-content",
  InputResolution: "input-resolution",
  MalwareIndicator: "malware-indicator",
  McpLeastPrivilege: "mcp-least-privilege",
  McpToolPoisoning: "mcp-tool-poisoning",
  MemoryPoisoning: "memory-poisoning",
  OutputHandling: "output-handling",
  PrivilegeEscalation: "privilege-escalation",
  PromptInjection: "prompt-injection",
  RogueAgent: "rogue-agent",
  ScanIntegrity: "scan-integrity",
  SupplyChain: "supply-chain",
  SystemPromptLeakage: "system-prompt-leakage",
  ToolMisuse: "tool-misuse",
  TriggerAbuse: "trigger-abuse",
} as const;

export type FindingCategory =
  (typeof FindingCategory)[keyof typeof FindingCategory];

export const RiskLevel = {
  Critical: "critical",
  High: "high",
  Low: "low",
  Medium: "medium",
  None: "none",
} as const;

export type RiskLevel = (typeof RiskLevel)[keyof typeof RiskLevel];

export type JsonScalar = boolean | null | number | string;

export type FindingLocation = {
  path: string;
  line?: number;
  column?: number;
};

export type Finding = {
  ruleId: string;
  title: string;
  severity: Severity;
  message: string;
  category?: FindingCategory;
  confidence?: number;
  location?: FindingLocation;
  metadata?: Record<string, JsonScalar>;
  remediation?: string;
};

export type TextScanFile = {
  type: "text";
  absolutePath: string;
  path: string;
  size: number;
  sha256: string;
  content: string;
};

export type JsonScanFile = {
  type: "json";
  absolutePath: string;
  path: string;
  size: number;
  sha256: string;
  content: string;
  json: unknown;
};

export type BinaryScanFile = {
  type: "binary";
  absolutePath: string;
  path: string;
  size: number;
  sha256: string;
};

export type SkippedScanFile = {
  type: "skipped";
  absolutePath: string;
  path: string;
  reason: ScanSkipReason;
  size?: number;
  message?: string;
};

export type SymlinkScanFile = {
  type: "symlink";
  absolutePath: string;
  path: string;
  target?: string;
};

export type ScanFile =
  | BinaryScanFile
  | JsonScanFile
  | SkippedScanFile
  | SymlinkScanFile
  | TextScanFile;

export type ReportFile = {
  type: ScanFile["type"];
  path: string;
  reason?: ScanSkipReason;
  sha256?: string;
  size?: number;
};

export type ScanSkipReason =
  | "binary"
  | "depth-limit"
  | "file-count-limit"
  | "ignored"
  | "read-error"
  | "too-large";

export type SeverityCounts = Record<Severity, number>;

export type ScanSummary = {
  files: {
    scanned: number;
    skipped: number;
    total: number;
  };
  bytes: {
    scanned: number;
  };
  findings: SeverityCounts;
  maxSeverity?: Severity;
  risk: RiskSummary;
};

export type RiskSummary = {
  level: RiskLevel;
  recommendation: string;
  score: number;
};

export type ScanReport = {
  schemaVersion: "skillguard.report.v1";
  target: {
    path: string;
    preset?: string;
  };
  summary: ScanSummary;
  files: readonly ReportFile[];
  findings: readonly Finding[];
};

export type ScanLimits = {
  maxDepth: number;
  maxFileBytes: number;
  maxFiles: number;
  maxTotalBytes: number;
};

export type ScanOptions = {
  ignore?: readonly string[];
  limits?: Partial<ScanLimits>;
  preset?: string;
  rules?: readonly Rule[];
};

export type RuleContext = {
  files: readonly ScanFile[];
  findings: readonly Finding[];
  rootPath: string;
};

export type Rule = {
  id: string;
  title: string;
  category: FindingCategory;
  confidence: number;
  description: string;
  defaultSeverity: Severity;
  remediation?: string;
  run: (
    context: RuleContext,
  ) => Promise<readonly Finding[]> | readonly Finding[];
};

export type FindingInput = {
  message: string;
  category?: FindingCategory;
  confidence?: number;
  location?: FindingLocation;
  metadata?: Record<string, JsonScalar>;
  remediation?: string;
  severity?: Severity;
  title?: string;
};

export type PolicyEvaluation = {
  status: ScanStatus;
  failOn: Severity;
  blockingFindings: readonly Finding[];
};

export type PolicyOptions = {
  failOn?: Severity;
  policy?: PolicyName;
};

export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxDepth: 16,
  maxFileBytes: 1_000_000,
  maxFiles: 2000,
  maxTotalBytes: 20_000_000,
};

const DEFAULT_IGNORES = new Set([
  ".cache",
  ".git",
  ".turbo",
  "coverage",
  "dist",
  "node_modules",
]);

const POLICY_FAIL_ON: Record<PolicyName, Severity> = {
  advisory: Severity.Critical,
  standard: Severity.High,
  strict: Severity.Medium,
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  info: 0,
  low: 1,
  medium: 2,
};

const TEXT_FILE_EXTENSIONS = new Set([
  ".bash",
  ".cjs",
  ".css",
  ".env",
  ".fish",
  ".js",
  ".json",
  ".jsx",
  ".lock",
  ".md",
  ".mjs",
  ".ps1",
  ".py",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".yaml",
  ".yml",
  ".zsh",
]);

const ROOT_TEXT_FILENAMES = new Set([
  "AGENTS.md",
  "CLAUDE.md",
  "LICENSE",
  "README",
  "README.md",
  "SECURITY.md",
  "SKILL.md",
]);

type CollectState = {
  didHitFileLimit: boolean;
  files: ScanFile[];
  findings: Finding[];
  ignore: Set<string>;
  limits: ScanLimits;
  rootPath: string;
  scannedBytes: number;
};

type CollectPathOptions = {
  absolutePath: string;
  depth: number;
  state: CollectState;
};

export const createFinding = (
  rule: Pick<
    Rule,
    | "category"
    | "confidence"
    | "defaultSeverity"
    | "id"
    | "remediation"
    | "title"
  >,
  input: FindingInput,
): Finding => {
  const remediation = input.remediation ?? rule.remediation;

  return {
    ruleId: rule.id,
    title: input.title ?? rule.title,
    severity: input.severity ?? rule.defaultSeverity,
    message: input.message,
    category: input.category ?? rule.category,
    confidence: input.confidence ?? rule.confidence,
    ...(input.location === undefined ? {} : { location: input.location }),
    ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
    ...(remediation === undefined ? {} : { remediation }),
  };
};

export const isTextLikeFile = (
  file: ScanFile,
): file is JsonScanFile | TextScanFile =>
  file.type === "json" || file.type === "text";

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const severityAtLeast = (
  severity: Severity,
  threshold: Severity,
): boolean => SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];

export const compareSeverity = (left: Severity, right: Severity): number =>
  SEVERITY_RANK[right] - SEVERITY_RANK[left];

export const evaluatePolicy = (
  report: ScanReport,
  options: PolicyOptions = {},
): PolicyEvaluation => {
  const failOn = options.failOn ?? POLICY_FAIL_ON[options.policy ?? "standard"];
  const blockingFindings: Finding[] = [];

  for (const finding of report.findings) {
    if (!severityAtLeast(finding.severity, failOn)) {
      continue;
    }

    blockingFindings.push(finding);
  }

  return {
    status: blockingFindings.length === 0 ? ScanStatus.Pass : ScanStatus.Fail,
    failOn,
    blockingFindings,
  };
};

export const scanPath = async (
  targetPath: string,
  options: ScanOptions = {},
): Promise<ScanReport> => {
  const rootPath = nodePath.resolve(targetPath);
  const limits = { ...DEFAULT_SCAN_LIMITS, ...options.limits };
  const ignore = new Set([...DEFAULT_IGNORES, ...(options.ignore ?? [])]);
  const state: CollectState = {
    didHitFileLimit: false,
    files: [],
    findings: [],
    ignore,
    limits,
    rootPath,
    scannedBytes: 0,
  };

  await collectPath({ absolutePath: rootPath, depth: 0, state });

  const findings = [...state.findings];

  for (const rule of options.rules ?? []) {
    const ruleFindings = await rule.run({
      files: state.files,
      findings,
      rootPath,
    });
    findings.push(...ruleFindings);
  }

  findings.sort(compareFindings);

  return {
    schemaVersion: "skillguard.report.v1",
    target: {
      path: rootPath,
      ...(options.preset === undefined ? {} : { preset: options.preset }),
    },
    summary: summarize(state.files, findings, state.scannedBytes),
    files: state.files.map(toReportFile).toSorted(compareReportFiles),
    findings,
  };
};

export const addFindingsToReport = (
  report: ScanReport,
  additionalFindings: readonly Finding[],
): ScanReport => {
  if (additionalFindings.length === 0) {
    return report;
  }

  const findings = [...report.findings, ...additionalFindings].toSorted(
    compareFindings,
  );

  return {
    ...report,
    findings,
    summary: summarize(report.files, findings, report.summary.bytes.scanned),
  };
};

const collectPath = async ({
  absolutePath,
  depth,
  state,
}: CollectPathOptions): Promise<void> => {
  const relativePath = toRelativePath(state.rootPath, absolutePath);

  if (depth > state.limits.maxDepth) {
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "depth-limit",
    });
    pushSystemFinding(state, {
      message: `Skipped ${relativePath} because it exceeds the maximum scan depth.`,
      severity: Severity.High,
      title: "Scan depth limit reached",
      location: { path: relativePath },
      metadata: { maxDepth: state.limits.maxDepth },
    });
    return;
  }

  let stat;
  try {
    stat = await lstat(absolutePath);
  } catch (error) {
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "read-error",
      message: toErrorMessage(error),
    });
    pushSystemFinding(state, {
      message: `Could not inspect ${relativePath}: ${toErrorMessage(error)}`,
      severity: Severity.Medium,
      title: "Read error",
      location: { path: relativePath },
    });
    return;
  }

  if (stat.isSymbolicLink()) {
    await collectSymlink({ absolutePath, state });
    return;
  }

  if (stat.isDirectory()) {
    await collectDirectory({ absolutePath, depth, state });
    return;
  }

  if (!stat.isFile()) {
    return;
  }

  await collectFile({ absolutePath, size: stat.size, state });
};

type CollectDirectoryOptions = {
  absolutePath: string;
  depth: number;
  state: CollectState;
};

const collectDirectory = async ({
  absolutePath,
  depth,
  state,
}: CollectDirectoryOptions): Promise<void> => {
  const basename = nodePath.basename(absolutePath);

  if (basename !== "" && state.ignore.has(basename)) {
    pushSkipped(state, {
      absolutePath,
      path: toRelativePath(state.rootPath, absolutePath),
      reason: "ignored",
    });
    return;
  }

  let entries;
  try {
    entries = await readdir(absolutePath);
  } catch (error) {
    const relativePath = toRelativePath(state.rootPath, absolutePath);
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "read-error",
      message: toErrorMessage(error),
    });
    pushSystemFinding(state, {
      message: `Could not read ${relativePath}: ${toErrorMessage(error)}`,
      severity: Severity.Medium,
      title: "Read error",
      location: { path: relativePath },
    });
    return;
  }

  entries.sort();

  for (const entry of entries) {
    await collectPath({
      absolutePath: nodePath.join(absolutePath, entry),
      depth: depth + 1,
      state,
    });
  }
};

type CollectFileOptions = {
  absolutePath: string;
  size: number;
  state: CollectState;
};

const collectFile = async ({
  absolutePath,
  size,
  state,
}: CollectFileOptions): Promise<void> => {
  const relativePath = toRelativePath(state.rootPath, absolutePath);

  if (state.files.length >= state.limits.maxFiles) {
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "file-count-limit",
      size,
    });

    if (!state.didHitFileLimit) {
      state.didHitFileLimit = true;
      pushSystemFinding(state, {
        message:
          "The scan reached the maximum file count and skipped remaining files.",
        severity: Severity.High,
        title: "File count limit reached",
        metadata: { maxFiles: state.limits.maxFiles },
      });
    }

    return;
  }

  if (size > state.limits.maxFileBytes) {
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "too-large",
      size,
    });
    pushSystemFinding(state, {
      message: `Skipped ${relativePath} because it exceeds the maximum file size.`,
      severity: Severity.High,
      title: "File size limit reached",
      location: { path: relativePath },
      metadata: { maxFileBytes: state.limits.maxFileBytes, size },
    });
    return;
  }

  if (state.scannedBytes + size > state.limits.maxTotalBytes) {
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "too-large",
      size,
    });
    pushSystemFinding(state, {
      message: "The scan reached the maximum total byte count.",
      severity: Severity.High,
      title: "Total byte limit reached",
      location: { path: relativePath },
      metadata: { maxTotalBytes: state.limits.maxTotalBytes },
    });
    return;
  }

  let buffer;
  try {
    buffer = await readFile(absolutePath);
  } catch (error) {
    pushSkipped(state, {
      absolutePath,
      path: relativePath,
      reason: "read-error",
      size,
      message: toErrorMessage(error),
    });
    pushSystemFinding(state, {
      message: `Could not read ${relativePath}: ${toErrorMessage(error)}`,
      severity: Severity.Medium,
      title: "Read error",
      location: { path: relativePath },
    });
    return;
  }

  const sha256 = createHash("sha256").update(buffer).digest("hex");
  state.scannedBytes += buffer.byteLength;

  if (!isTextFile(relativePath, buffer)) {
    state.files.push({
      type: "binary",
      absolutePath,
      path: relativePath,
      size,
      sha256,
    });
    return;
  }

  const content = buffer.toString("utf-8");

  if (isJsonPath(relativePath)) {
    const parseResult = parseJson(content);

    if (parseResult.type === "success") {
      state.files.push({
        type: "json",
        absolutePath,
        path: relativePath,
        size,
        sha256,
        content,
        json: parseResult.value,
      });
      return;
    }

    pushSystemFinding(state, {
      message: `Could not parse JSON in ${relativePath}: ${parseResult.message}`,
      severity: Severity.Medium,
      title: "JSON parse error",
      location: { path: relativePath },
    });
  }

  state.files.push({
    type: "text",
    absolutePath,
    path: relativePath,
    size,
    sha256,
    content,
  });
};

type CollectSymlinkOptions = {
  absolutePath: string;
  state: CollectState;
};

const collectSymlink = async ({
  absolutePath,
  state,
}: CollectSymlinkOptions): Promise<void> => {
  const relativePath = toRelativePath(state.rootPath, absolutePath);
  let target: string | undefined;

  try {
    target = await readlink(absolutePath);
  } catch {
    target = undefined;
  }

  state.files.push({
    type: "symlink",
    absolutePath,
    path: relativePath,
    ...(target === undefined ? {} : { target }),
  });
  pushSystemFinding(state, {
    message: "Symlink was not followed during scan.",
    severity: Severity.Medium,
    title: "Symlink skipped",
    location: { path: relativePath },
  });
};

const pushSkipped = (
  state: CollectState,
  file: Omit<SkippedScanFile, "type">,
): void => {
  state.files.push({
    type: "skipped",
    ...file,
  });
};

type SystemFindingInput = {
  message: string;
  severity: Severity;
  title: string;
  location?: FindingLocation;
  metadata?: Record<string, JsonScalar>;
};

const pushSystemFinding = (
  state: CollectState,
  input: SystemFindingInput,
): void => {
  state.findings.push({
    ruleId: "skillguard.scan",
    title: input.title,
    severity: input.severity,
    message: input.message,
    category: FindingCategory.ScanIntegrity,
    confidence: 1,
    ...(input.location === undefined ? {} : { location: input.location }),
    ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
  });
};

type JsonParseResult =
  | {
      type: "failure";
      message: string;
    }
  | {
      type: "success";
      value: unknown;
    };

const parseJson = (content: string): JsonParseResult => {
  try {
    return {
      type: "success",
      value: JSON.parse(content),
    };
  } catch (error) {
    return {
      type: "failure",
      message: toErrorMessage(error),
    };
  }
};

const isJsonPath = (relativePath: string): boolean =>
  relativePath.endsWith(".json");

const isTextFile = (relativePath: string, buffer: Buffer): boolean => {
  if (buffer.includes(0)) {
    return false;
  }

  const extension = nodePath.extname(relativePath);

  if (TEXT_FILE_EXTENSIONS.has(extension)) {
    return true;
  }

  return ROOT_TEXT_FILENAMES.has(nodePath.basename(relativePath));
};

const toRelativePath = (rootPath: string, absolutePath: string): string => {
  const relativePath = nodePath.relative(rootPath, absolutePath);

  if (relativePath === "") {
    return ".";
  }

  return relativePath.split(nodePath.sep).join("/");
};

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
};

const summarize = (
  files: readonly { type: ScanFile["type"] }[],
  findings: readonly Finding[],
  scannedBytes: number,
): ScanSummary => {
  const severityCounts = createSeverityCounts();
  let maxSeverity: Severity | undefined;

  for (const finding of findings) {
    severityCounts[finding.severity] += 1;

    if (
      maxSeverity === undefined ||
      severityAtLeast(finding.severity, maxSeverity)
    ) {
      maxSeverity = finding.severity;
    }
  }

  const skipped = files.filter((file) => file.type === "skipped").length;

  return {
    files: {
      scanned: files.length - skipped,
      skipped,
      total: files.length,
    },
    bytes: {
      scanned: scannedBytes,
    },
    findings: severityCounts,
    risk: calculateRisk(severityCounts),
    ...(maxSeverity === undefined ? {} : { maxSeverity }),
  };
};

const calculateRisk = (findings: SeverityCounts): RiskSummary => {
  const score = Math.min(
    100,
    findings.critical * 35 +
      findings.high * 18 +
      findings.medium * 8 +
      findings.low * 2,
  );
  const level = toRiskLevel(score);

  return {
    score,
    level,
    recommendation: toRiskRecommendation(level),
  };
};

const toRiskLevel = (score: number): RiskLevel => {
  if (score >= 70) {
    return RiskLevel.Critical;
  }

  if (score >= 40) {
    return RiskLevel.High;
  }

  if (score >= 15) {
    return RiskLevel.Medium;
  }

  if (score > 0) {
    return RiskLevel.Low;
  }

  return RiskLevel.None;
};

const toRiskRecommendation = (level: RiskLevel): string => {
  switch (level) {
    case "critical":
      return "Do not install without source review and explicit owner approval.";
    case "high":
      return "Block by default; require security review before installation.";
    case "medium":
      return "Require manual review before trusting this skill.";
    case "low":
      return "Review findings, then install only if the behavior is expected.";
    case "none":
      return "No findings from enabled analyzers.";
  }

  return assertNever(level);
};

const createSeverityCounts = (): SeverityCounts => ({
  critical: 0,
  high: 0,
  info: 0,
  low: 0,
  medium: 0,
});

const toReportFile = (file: ScanFile): ReportFile => {
  switch (file.type) {
    case "binary":
    case "json":
    case "text":
      return {
        type: file.type,
        path: file.path,
        size: file.size,
        sha256: file.sha256,
      };
    case "skipped":
      return {
        type: file.type,
        path: file.path,
        reason: file.reason,
        ...(file.size === undefined ? {} : { size: file.size }),
      };
    case "symlink":
      return {
        type: file.type,
        path: file.path,
      };
  }

  return assertNever(file);
};

const assertNever = (value: never): never => {
  throw new Error(`Unhandled value: ${String(value)}`);
};

const compareFindings = (left: Finding, right: Finding): number => {
  const severity = compareSeverity(left.severity, right.severity);

  if (severity !== 0) {
    return severity;
  }

  const leftPath = left.location?.path ?? "";
  const rightPath = right.location?.path ?? "";
  const pathCompare = leftPath.localeCompare(rightPath);

  if (pathCompare !== 0) {
    return pathCompare;
  }

  return left.ruleId.localeCompare(right.ruleId);
};

const compareReportFiles = (left: ReportFile, right: ReportFile): number =>
  left.path.localeCompare(right.path);
