import { createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { findingFingerprint, relativeToTarget } from '../config/baseline.js';
import type { Finding, FindingLocation, Severity } from '../model/types.js';
import type { RuleDescription, ScanMetadata } from './types.js';

// Exported for reporters/index.ts's renderMultiTargetReport (Phase 20,
// improvement_plan.md 3.2) — a --all multi-target SARIF report merges
// several single-run documents into one multi-run one, and needs the
// same schema URI at the top level.
export const SARIF_SCHEMA_URI =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

const INFORMATION_URI = 'https://github.com/AlpayAltuntas/chaperone';
const CHECKS_DOC_URI = `${INFORMATION_URI}/blob/main/CHECKS.md`;
const SOURCE_ROOT_ID = 'SRCROOT';

// SARIF 2.1.0 only defines these four result levels.
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

// GitHub code scanning derives its Critical/High/Medium/Low label from a
// rule's `security-severity` (a 0.0-10.0 string): >= 9.0 critical,
// >= 7.0 high, >= 4.0 medium, else low (PROPOSED_FIXES.md 4.1).
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri: string;
  defaultConfiguration: { level: SarifLevel };
  properties: {
    category: string;
    owasp: string;
    severity: Severity;
    'security-severity': string;
    tags: string[];
  };
}

interface SarifPhysicalLocation {
  artifactLocation: { uri: string; uriBaseId?: string };
  region?: { startLine: number };
}

interface SarifLocation {
  id?: number;
  physicalLocation: SarifPhysicalLocation;
  message?: { text: string };
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  relatedLocations?: SarifLocation[];
  partialFingerprints: Record<string, string>;
  properties: { severity: Severity; category: string; owasp: string; remediation: string };
}

interface SarifRun {
  tool: {
    driver: {
      name: 'chaperone';
      informationUri: string;
      version: string;
      rules: SarifRule[];
    };
  };
  originalUriBaseIds: Record<string, { description: { text: string } }>;
  invocations: Array<{
    executionSuccessful: boolean;
    properties: { inspectedCount: number; skippedCount: number };
  }>;
  results: SarifResult[];
}

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: [SarifRun];
}

/**
 * Renders findings + scan metadata as SARIF 2.1.0, hand-built per
 * instruction.md §4 (no dependency needed) for GitHub code scanning.
 *
 * Shaped for code scanning (PROPOSED_FIXES.md 4.1): paths are relative to
 * `metadata.sourceRoot` (the git root) under the `SRCROOT` base, so they
 * map to repository files and don't leak the local home directory;
 * `partialFingerprints` carries the same stable fingerprint `--baseline`
 * uses, so an alert is tracked across runs; rules carry
 * `security-severity`, the check's full description, and help text; and
 * every check that ran gets a rule, so a fixed alert closes. A failed or
 * partial scan shows in `invocations`.
 */
export function formatSarifReport(findings: readonly Finding[], metadata: ScanMetadata): string {
  const sourceRoot = metadata.sourceRoot ?? metadata.target;
  const sarif: SarifLog = {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'chaperone',
            informationUri: INFORMATION_URI,
            version: metadata.toolVersion,
            rules: buildRules(findings, metadata.checks),
          },
        },
        // Declared without an absolute `uri` on purpose: the consumer
        // (code scanning) supplies the checkout root, and an absolute path
        // here would leak the scanning machine's directory layout.
        originalUriBaseIds: {
          [SOURCE_ROOT_ID]: {
            description: {
              text: 'The root of the git repository containing the scan target, or the scan target itself when it is not in a repository.',
            },
          },
        },
        invocations: [
          {
            executionSuccessful: metadata.targetRootResolved,
            properties: {
              inspectedCount: metadata.inspected.length,
              skippedCount: metadata.skipped.length,
            },
          },
        ],
        results: findings.map((finding) => toSarifResult(finding, sourceRoot)),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function buildRules(
  findings: readonly Finding[],
  checks: readonly RuleDescription[] | undefined,
): SarifRule[] {
  const rules = new Map<string, SarifRule>();
  for (const check of checks ?? []) {
    rules.set(check.id, ruleFromCheck(check));
  }
  // A finding from a check not in `checks` (a caller that only has
  // findings) still gets a rule, built from what the finding carries.
  for (const finding of findings) {
    if (!rules.has(finding.checkId)) {
      rules.set(
        finding.checkId,
        ruleFromCheck({
          id: finding.checkId,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          owasp: finding.owasp,
          detects: finding.title,
          heuristic: '',
          remediation: finding.remediation,
        }),
      );
    }
  }
  return [...rules.values()];
}

function ruleFromCheck(check: RuleDescription): SarifRule {
  const helpText = [
    check.detects,
    check.heuristic === '' ? null : `How it's detected: ${check.heuristic}`,
    `Remediation: ${check.remediation}`,
  ]
    .filter((part): part is string => part !== null)
    .join('\n\n');
  const helpMarkdown = [
    check.detects,
    check.heuristic === '' ? null : `**How it's detected:** ${check.heuristic}`,
    `**Remediation:** ${check.remediation}`,
  ]
    .filter((part): part is string => part !== null)
    .join('\n\n');
  return {
    id: check.id,
    name: check.title,
    shortDescription: { text: check.title },
    fullDescription: { text: check.detects },
    help: { text: helpText, markdown: helpMarkdown },
    helpUri: `${CHECKS_DOC_URI}#${checksDocAnchor(check)}`,
    defaultConfiguration: { level: SEVERITY_TO_SARIF_LEVEL[check.severity] },
    properties: {
      category: check.category,
      owasp: check.owasp,
      severity: check.severity,
      'security-severity': SECURITY_SEVERITY[check.severity],
      tags: ['security', check.category],
    },
  };
}

/** GitHub's heading anchor for `### <id> — <title>` in CHECKS.md. */
export function checksDocAnchor(check: Pick<RuleDescription, 'id' | 'title'>): string {
  return `${check.id} — ${check.title}`
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\- _]/gu, '')
    .replace(/ /g, '-');
}

function toSarifResult(finding: Finding, sourceRoot: string): SarifResult {
  const result: SarifResult = {
    ruleId: finding.checkId,
    level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
    message: { text: relativizePaths(finding.message, sourceRoot) },
    partialFingerprints: {
      'chaperoneFingerprint/v1': createHash('sha256')
        .update(findingFingerprint(finding, sourceRoot))
        .digest('hex'),
    },
    properties: {
      severity: finding.severity,
      category: finding.category,
      owasp: finding.owasp,
      remediation: finding.remediation,
    },
  };

  const primary = toPhysicalLocation(finding.location, sourceRoot);
  if (primary !== null) {
    result.locations = [{ physicalLocation: primary }];
  }

  const related = (finding.relatedLocations ?? [])
    .map((location, index): SarifLocation | null => {
      const physical = toPhysicalLocation(location, sourceRoot);
      return physical === null
        ? null
        : {
            id: index + 1,
            physicalLocation: physical,
            ...(location.detail !== null ? { message: { text: location.detail } } : {}),
          };
    })
    .filter((location): location is SarifLocation => location !== null);
  if (related.length > 0) {
    result.relatedLocations = related;
  }

  return result;
}

function toPhysicalLocation(
  location: FindingLocation,
  sourceRoot: string,
): SarifPhysicalLocation | null {
  if (location.filePath === null) {
    return null;
  }
  const relative = relativeToTarget(location.filePath, sourceRoot);
  const artifactLocation =
    relative !== null && !path.isAbsolute(relative)
      ? { uri: relative === '' ? '.' : encodeURI(relative), uriBaseId: SOURCE_ROOT_ID }
      : { uri: pathToFileURL(location.filePath).href };
  return {
    artifactLocation,
    ...(location.line !== null ? { region: { startLine: location.line } } : {}),
  };
}

/** Messages sometimes name a file; strip the local root so SARIF never carries it. */
function relativizePaths(text: string, sourceRoot: string): string {
  if (!path.isAbsolute(sourceRoot)) {
    return text;
  }
  return text
    .replaceAll(`${sourceRoot}${path.sep}`, '')
    .replaceAll(sourceRoot, `<${SOURCE_ROOT_ID}>`);
}
