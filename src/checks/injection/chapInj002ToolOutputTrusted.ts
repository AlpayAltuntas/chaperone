import type { Check } from '../../engine/types.js';

const ID = 'CHAP-INJ-002';
const TITLE = 'Tool output treated as trusted';
const OWASP = 'LLM02: Insecure Output Handling';

/**
 * A skill that both ingests external/tool data (network or filesystem
 * access) AND can execute shell commands is a plausible shape for "a
 * tool's output can trigger another tool with no validation step".
 * improvement_plan.md 1.16's data-flow improvement: when
 * `astCapabilities.ts`'s bounded intra-file taint trace confirms a
 * network/fs result actually reaches the shell-exec call's argument
 * (not just "both capabilities present somewhere in the file"), that's
 * reported as a confirmed chain at `high` severity; otherwise this falls
 * back to the original `medium`-severity shape-match, since a real
 * cross-function/file data-flow trace is still out of scope (a genuine
 * static-analysis project of its own, not a quick patch — see
 * DECISIONS.md).
 */
export const chapInj002ToolOutputTrusted: Check = {
  id: ID,
  title: TITLE,
  severity: 'medium',
  category: 'injection',
  owasp: OWASP,
  detects:
    "A skill whose output could drive another tool with no validation step — either a confirmed data-flow chain (a network/filesystem result traced into a shell-exec call's argument) or, more weakly, just both capabilities being present in the same file.",
  heuristic:
    "A skill that can execute shell commands and also has network or filesystem-read capability. When a bounded intra-file taint trace confirms the network/fs result actually reaches the shell-exec call's argument, this is reported at `high` severity as a confirmed chain; otherwise it's the weaker `medium`-severity shape-match (both capabilities merely present, not traced) — Chaperone still has no cross-function/file data-flow analysis.",
  remediation:
    "Validate/escape a tool's output before it can drive another tool; never auto-execute model or tool output.",
  run(model) {
    return model.skills
      .filter(
        (skill) =>
          skill.capabilities.shellExec &&
          (skill.capabilities.networkAccess || skill.capabilities.fileSystemAccess),
      )
      .map((skill) => {
        const confirmed = skill.capabilities.dataFlowToShellExec;
        const severity = confirmed ? ('high' as const) : ('medium' as const);
        const message = confirmed
          ? `Skill '${skill.name}' traces a network/filesystem result directly into a shell-exec call's argument — a confirmed tool-output-to-shell-execution chain, not just a shape-match.`
          : `Skill '${skill.name}' both ingests external data (${skill.capabilities.networkAccess ? 'network' : 'filesystem'}) and can execute shell commands, with no detected validation step in between.`;

        return {
          checkId: ID,
          title: TITLE,
          severity,
          category: 'injection' as const,
          owasp: OWASP,
          message,
          location: { filePath: skill.manifestPath ?? skill.dir, line: null, detail: skill.name },
          remediation:
            "Validate/escape a tool's output before it can drive another tool; never auto-execute model or tool output.",
        };
      });
  },
};
