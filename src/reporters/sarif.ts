import { pathToFileURL } from 'node:url';
import type { Finding, Severity } from '../model/types.js';
import type { ScanMetadata } from './types.js';

const SARIF_SCHEMA_URI =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

// SARIF 2.1.0 only defines these four result levels.
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  properties: { category: string; owasp: string; severity: Severity };
}

interface SarifRegion {
  startLine: number;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: SarifRegion;
  };
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  properties: { severity: Severity; category: string; owasp: string; remediation: string };
}

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: [
    {
      tool: {
        driver: {
          name: 'chaperone';
          informationUri: string;
          version: string;
          rules: SarifRule[];
        };
      };
      results: SarifResult[];
    },
  ];
}

/**
 * Renders findings + scan metadata as SARIF 2.1.0, hand-built per
 * instruction.md §4 (no dependency needed) so results can be uploaded to
 * GitHub code scanning. `rules` only lists checks that actually produced a
 * finding in this run — reporters are pure functions of Finding[] and
 * every field a rule needs (title/category/owasp/severity) is already on
 * each Finding, so no separate check-registry input is required.
 */
export function formatSarifReport(findings: readonly Finding[], metadata: ScanMetadata): string {
  const sarif: SarifLog = {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'chaperone',
            informationUri: 'https://github.com/AlpayAltuntas/chaperone',
            version: metadata.toolVersion,
            rules: buildRules(findings),
          },
        },
        results: findings.map(toSarifResult),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function buildRules(findings: readonly Finding[]): SarifRule[] {
  const rules = new Map<string, SarifRule>();
  for (const finding of findings) {
    if (!rules.has(finding.checkId)) {
      rules.set(finding.checkId, {
        id: finding.checkId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.title },
        properties: {
          category: finding.category,
          owasp: finding.owasp,
          severity: finding.severity,
        },
      });
    }
  }
  return [...rules.values()];
}

function toSarifResult(finding: Finding): SarifResult {
  const result: SarifResult = {
    ruleId: finding.checkId,
    level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
    message: { text: finding.message },
    properties: {
      severity: finding.severity,
      category: finding.category,
      owasp: finding.owasp,
      remediation: finding.remediation,
    },
  };

  if (finding.location.filePath !== null) {
    result.locations = [
      {
        physicalLocation: {
          artifactLocation: { uri: pathToFileURL(finding.location.filePath).href },
          ...(finding.location.line !== null
            ? { region: { startLine: finding.location.line } }
            : {}),
        },
      },
    ];
  }

  return result;
}
