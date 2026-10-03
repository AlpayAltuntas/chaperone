import path from 'node:path';
import type { CapabilityEvidence, FindingLocation, Skill } from '../../model/types.js';

const MAX_LISTED = 3;

export interface EvidenceLocation {
  location: FindingLocation;
  /** Spread into the finding: `relatedLocations` only when there are any. */
  related: { relatedLocations?: FindingLocation[] };
  /** e.g. " Seen at index.js:12 (child_process.execSync), lib/run.js:4 (execa)." — empty when there's no evidence. */
  seenAt: string;
}

/**
 * Points a skill finding at the code that triggered it (PROPOSED_FIXES.md
 * 4.2) instead of the skill's manifest. The first matching evidence item
 * is the location, the rest are related locations, and up to three are
 * listed in the message. `detail` stays the skill name so a finding's
 * identity doesn't change when its code moves within the skill. Without
 * evidence (an MCP server, or an older plugin-built model), it falls back
 * to the manifest.
 */
export function locateEvidence(
  skill: Skill,
  capability: CapabilityEvidence['capability'],
  filter: (item: CapabilityEvidence) => boolean = () => true,
): EvidenceLocation {
  const items = skill.capabilities.evidence.filter(
    (item) => item.capability === capability && filter(item),
  );
  const [first, ...rest] = items;
  if (first === undefined) {
    return {
      location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
      related: {},
      seenAt: '',
    };
  }
  const listed = items
    .slice(0, MAX_LISTED)
    .map((item) => `${describePosition(skill, item)} (${item.api})`)
    .join(', ');
  const more = items.length > MAX_LISTED ? `, and ${String(items.length - MAX_LISTED)} more` : '';
  return {
    location: { filePath: first.file, line: first.line, detail: skill.name },
    related:
      rest.length > 0
        ? {
            relatedLocations: rest.map((item) => ({
              filePath: item.file,
              line: item.line,
              detail: item.api,
            })),
          }
        : {},
    seenAt: ` Seen at ${listed}${more}.`,
  };
}

function describePosition(skill: Skill, item: CapabilityEvidence): string {
  const relative = path.relative(skill.dir, item.file) || path.basename(item.file);
  return item.line === null ? relative : `${relative}:${String(item.line)}`;
}
