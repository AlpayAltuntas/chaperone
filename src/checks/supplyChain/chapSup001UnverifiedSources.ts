import type { Check } from '../../engine/types.js';

const ID = 'CHAP-SUP-001';
const TITLE = 'Skill from an unverified source';
const OWASP = 'LLM05: Supply Chain';

/** Flags skills whose provenance isn't confirmed as pinned (an unpinned/unknown ref counts as unverified). */
export const chapSup001UnverifiedSources: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'supply-chain',
  owasp: OWASP,
  detects: 'Skills installed from an unpinned ref or with no verifiable provenance.',
  heuristic:
    'The skill\'s manifest doesn\'t confirm a pinned version/ref (`pinnedRef !== true` — covers both an explicitly unpinned version like `"latest"` and a manifest with no version/ref info at all).',
  remediation:
    'Pin the skill to an explicit version or commit, prefer reviewed sources, and verify the author.',
  run(model) {
    return model.skills
      .filter((skill) => skill.provenance.pinnedRef !== true)
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'supply-chain',
        owasp: OWASP,
        message: `Skill '${skill.name}' is not installed at a pinned version/commit (${skill.provenance.pinnedRef === false ? 'unpinned' : 'no version/ref info found'}).`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          'Pin the skill to an explicit version or commit, prefer reviewed sources, and verify the author.',
      }));
  },
};
