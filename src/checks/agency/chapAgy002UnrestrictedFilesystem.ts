import type { Check } from '../../engine/types.js';
import { locateEvidence } from '../shared/skillEvidence.js';

const ID = 'CHAP-AGY-002';
const TITLE = 'Unrestricted filesystem access';
const OWASP = 'LLM08: Excessive Agency';

/**
 * Flags skills that write/delete files with no evidence of scoping to a
 * fixed workspace directory (see `fileSystemScoped` in skillsScanner.ts) —
 * a static proxy for "no path scoping", not true taint tracking.
 */
export const chapAgy002UnrestrictedFilesystem: Check = {
  id: ID,
  title: TITLE,
  severity: 'high',
  category: 'agency',
  owasp: OWASP,
  detects: 'Skills that write/delete files with no scoping to a fixed workspace directory.',
  heuristic:
    "The skill writes files (`fs`/`fs/promises`/`fs-extra` writes, renames, copies, deletes, `mkdir`/`chmod`/`createWriteStream`, including `fs.promises.*`; or any call into `rimraf`/`del`) and at least one write's path isn't scoped. Scoping is decided per write call: a path is scoped when it is the skill's own directory (`__dirname`, `import.meta.dirname`/`url`, or a variable derived from them), a fixed literal path other than a filesystem root, a variable holding one of those, or `path.join`/`path.resolve` whose first argument is one of those. A caller-supplied path is unscoped, and one unscoped write anywhere in the skill is enough. Path traversal through a joined segment (`../`) isn't modeled. Python skills still use a file-level pattern (`os.path.dirname(__file__)`, a `WORKSPACE`/`SANDBOX`-named variable).",
  remediation:
    "Scope the skill's file access to a dedicated workspace directory and deny path traversal outside it.",
  run(model) {
    return model.skills
      .filter(
        (skill) => skill.capabilities.fileSystemAccess && !skill.capabilities.fileSystemScoped,
      )
      .map((skill) => {
        const { location, related, seenAt } = locateEvidence(
          skill,
          'fileSystemAccess',
          (item) => item.scoped !== true,
        );
        return {
          checkId: ID,
          title: TITLE,
          severity: 'high',
          category: 'agency',
          owasp: OWASP,
          message: `Skill '${skill.name}' writes/deletes files with no detected scoping to a fixed workspace directory — it can plausibly read/write anywhere the process can reach.${seenAt}`,
          location,
          ...related,
          remediation:
            "Scope the skill's file access to a dedicated workspace directory and deny path traversal outside it.",
        };
      });
  },
};
