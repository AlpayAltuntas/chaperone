import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { GitContext } from '../model/types.js';

// Bounds the ancestor walk so a pathological filesystem (or a symlink loop
// that somehow slips through) can't hang discovery.
const MAX_ANCESTOR_LEVELS = 40;

const EMPTY_GIT_CONTEXT: GitContext = {
  hasAncestorGitDir: false,
  gitDirPath: null,
  gitRootPath: null,
  gitignorePatterns: [],
  configPathRelativeToGitRoot: null,
};

/**
 * Walks upward from `fromPath` looking for an ancestor `.git` directory.
 * Per the read boundary in instruction.md §8, this is the only place
 * discovery reads outside the scan target: it may check directory
 * existence and read a root-level `.gitignore`, nothing else (no git
 * history, no other files). Matching `.gitignore` patterns against the
 * config path is check logic (pure, no I/O) and lives in CHAP-SEC-002.
 */
export function detectGitContext(fromPath: string): GitContext {
  let dir = isDirectory(fromPath) ? fromPath : path.dirname(fromPath);

  for (let i = 0; i < MAX_ANCESTOR_LEVELS; i++) {
    const gitDirPath = path.join(dir, '.git');
    if (existsSync(gitDirPath)) {
      return {
        hasAncestorGitDir: true,
        gitDirPath,
        gitRootPath: dir,
        gitignorePatterns: readGitignorePatterns(dir),
        configPathRelativeToGitRoot: path.relative(dir, fromPath),
      };
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }

  return EMPTY_GIT_CONTEXT;
}

function readGitignorePatterns(gitRoot: string): string[] {
  const gitignorePath = path.join(gitRoot, '.gitignore');
  if (!existsSync(gitignorePath)) {
    return [];
  }
  try {
    return readFileSync(gitignorePath, 'utf8')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
  } catch {
    return [];
  }
}

function isDirectory(candidate: string): boolean {
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}
