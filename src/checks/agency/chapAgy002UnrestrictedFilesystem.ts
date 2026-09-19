import type { Check } from '../../engine/types.js';

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
    'The skill writes files (`fs.writeFile`/`unlink`/etc.) and its source shows no evidence of scoping — no `path.join(__dirname, ...)` (or `.resolve`) pattern and no constant named like `WORKSPACE`/`SANDBOX`/`SCOPED`. A static proxy for "no path scoping", not true taint tracking.',
  remediation:
    "Scope the skill's file access to a dedicated workspace directory and deny path traversal outside it.",
  run(model) {
    return model.skills
      .filter(
        (skill) => skill.capabilities.fileSystemAccess && !skill.capabilities.fileSystemScoped,
      )
      .map((skill) => ({
        checkId: ID,
        title: TITLE,
        severity: 'high',
        category: 'agency',
        owasp: OWASP,
        message: `Skill '${skill.name}' writes/deletes files with no detected scoping to a fixed workspace directory — it can plausibly read/write anywhere the process can reach.`,
        location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
        remediation:
          "Scope the skill's file access to a dedicated workspace directory and deny path traversal outside it.",
      }));
  },
};
