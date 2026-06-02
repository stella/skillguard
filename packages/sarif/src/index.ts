import type { Finding, ScanReport, Severity } from "@stll/skillguard-core";

export type SarifLog = {
  version: "2.1.0";
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  runs: readonly SarifRun[];
};

export type SarifRun = {
  tool: {
    driver: {
      name: "SkillGuard";
      informationUri: "https://github.com/stella/skillguard";
      rules: readonly SarifRule[];
    };
  };
  results: readonly SarifResult[];
};

export type SarifRule = {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
};

export type SarifResult = {
  ruleId: string;
  level: SarifLevel;
  message: {
    text: string;
  };
  locations?: readonly SarifLocation[];
  properties: {
    severity: Severity;
  };
};

export type SarifLevel = "error" | "none" | "note" | "warning";

export type SarifLocation = {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
    region?: {
      startColumn?: number;
      startLine?: number;
    };
  };
};

export const toSarif = (report: ScanReport): SarifLog => ({
  version: "2.1.0",
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [
    {
      tool: {
        driver: {
          name: "SkillGuard",
          informationUri: "https://github.com/stella/skillguard",
          rules: toSarifRules(report.findings),
        },
      },
      results: report.findings.map(toSarifResult),
    },
  ],
});

const toSarifRules = (findings: readonly Finding[]): readonly SarifRule[] => {
  const rules = new Map<string, SarifRule>();

  for (const finding of findings) {
    if (rules.has(finding.ruleId)) {
      continue;
    }

    rules.set(finding.ruleId, {
      id: finding.ruleId,
      name: finding.title,
      shortDescription: {
        text: finding.title,
      },
    });
  }

  return [...rules.values()].toSorted((left, right) =>
    left.id.localeCompare(right.id),
  );
};

const toSarifResult = (finding: Finding): SarifResult => ({
  ruleId: finding.ruleId,
  level: toSarifLevel(finding.severity),
  message: {
    text: finding.message,
  },
  properties: {
    severity: finding.severity,
  },
  ...(finding.location === undefined
    ? {}
    : { locations: [toSarifLocation(finding)] }),
});

const toSarifLocation = (finding: Finding): SarifLocation => {
  const location = finding.location;

  if (location === undefined) {
    return {
      physicalLocation: {
        artifactLocation: {
          uri: ".",
        },
      },
    };
  }

  const region =
    location.line === undefined && location.column === undefined
      ? undefined
      : {
          ...(location.line === undefined ? {} : { startLine: location.line }),
          ...(location.column === undefined
            ? {}
            : { startColumn: location.column }),
        };

  return {
    physicalLocation: {
      artifactLocation: {
        uri: location.path,
      },
      ...(region === undefined ? {} : { region }),
    },
  };
};

const toSarifLevel = (severity: Severity): SarifLevel => {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "info":
    case "low":
      return "note";
  }

  return "none";
};
