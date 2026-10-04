import type { AgentModel, ClaudeCodeSettingsFile } from '../../model/types.js';
import { isRecord } from '../../discovery/jsonUtils.js';

/** A permission rule from one settings file, with where it is. */
export interface PermissionRule {
  rule: string;
  /** `Bash` in `Bash(npm run:*)`. */
  tool: string;
  /** `npm run:*` in `Bash(npm run:*)`; null for a bare tool name. */
  specifier: string | null;
  file: ClaudeCodeSettingsFile;
  line: number | null;
}

/** Splits `Tool(specifier)` into its parts; a bare `Tool` has no specifier. */
export function parseRule(rule: string): { tool: string; specifier: string | null } {
  const match = /^([^()]+)\((.*)\)$/s.exec(rule.trim());
  return match?.[1] !== undefined && match[2] !== undefined
    ? { tool: match[1].trim(), specifier: match[2].trim() }
    : { tool: rule.trim(), specifier: null };
}

/** Every `permissions.<list>` rule across the model's Claude Code settings files. */
export function permissionRules(
  model: AgentModel,
  list: 'allow' | 'deny' | 'ask',
): PermissionRule[] {
  const rules: PermissionRule[] = [];
  for (const file of model.claudeCodeSettings) {
    const permissions = isRecord(file.data) ? file.data['permissions'] : undefined;
    const entries = isRecord(permissions) ? permissions[list] : undefined;
    if (!Array.isArray(entries)) {
      continue;
    }
    entries.forEach((entry, index) => {
      if (typeof entry === 'string') {
        rules.push({
          rule: entry,
          ...parseRule(entry),
          file,
          line: file.keyLines[`permissions.${list}[${String(index)}]`] ?? null,
        });
      }
    });
  }
  return rules;
}

/** A top-level (or `permissions.`-nested) value from a settings file. */
export function settingValue(file: ClaudeCodeSettingsFile, keyPath: readonly string[]): unknown {
  let node: unknown = file.data;
  for (const key of keyPath) {
    if (!isRecord(node)) {
      return undefined;
    }
    node = node[key];
  }
  return node;
}

/**
 * Every command a settings file will run on its own: hook commands,
 * `statusLine.command`, `fileSuggestion.command`, and `apiKeyHelper`.
 */
export function settingsCommands(
  file: ClaudeCodeSettingsFile,
): Array<{ keyPath: string; command: string; line: number | null }> {
  const found: Array<{ keyPath: string; command: string; line: number | null }> = [];
  const add = (keyPath: string, value: unknown): void => {
    if (typeof value === 'string' && value.trim() !== '') {
      found.push({ keyPath, command: value, line: file.keyLines[keyPath] ?? null });
    }
  };
  const hooks = settingValue(file, ['hooks']);
  if (isRecord(hooks)) {
    for (const [event, matchers] of Object.entries(hooks)) {
      if (!Array.isArray(matchers)) {
        continue;
      }
      matchers.forEach((matcher, i) => {
        const inner = isRecord(matcher) ? matcher['hooks'] : undefined;
        if (!Array.isArray(inner)) {
          return;
        }
        inner.forEach((hook, j) => {
          if (isRecord(hook)) {
            add(`hooks.${event}[${String(i)}].hooks[${String(j)}].command`, hook['command']);
          }
        });
      });
    }
  }
  add('statusLine.command', settingValue(file, ['statusLine', 'command']));
  add('fileSuggestion.command', settingValue(file, ['fileSuggestion', 'command']));
  add('apiKeyHelper', settingValue(file, ['apiKeyHelper']));
  return found;
}
