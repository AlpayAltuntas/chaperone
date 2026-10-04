import path from 'node:path';
import type { AgentModel } from '../model/types.js';
import type { FixAction, FixChange } from './types.js';

/**
 * An action appending `target` to the repository root's `.gitignore`
 * (anchored with a leading `/`, and a trailing `/` for a directory), or
 * null when the install isn't inside a git repository or the target is
 * outside it.
 */
export function gitignoreAction(
  model: AgentModel,
  target: string,
  isDirectory: boolean,
): { action: FixAction; change: FixChange } | null {
  const root = model.git.gitRootPath;
  if (!model.git.hasAncestorGitDir || root === null) {
    return null;
  }
  const relative = path.relative(root, target);
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    return null;
  }
  const line = `/${relative.split(path.sep).join('/')}${isDirectory ? '/' : ''}`;
  const filePath = path.join(root, '.gitignore');
  return {
    action: { kind: 'append-lines', filePath, lines: [line] },
    change: { keyPath: filePath, oldDisplayValue: '(not ignored)', newValue: `+ ${line}` },
  };
}
