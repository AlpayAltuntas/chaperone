import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { GitContext, GitignoreFile } from '../model/types.js';

// Bounds the ancestor walk so a pathological filesystem (or a symlink loop
// that somehow slips through) can't hang discovery.
const MAX_ANCESTOR_LEVELS = 40;

const EMPTY_GIT_CONTEXT: GitContext = {
  hasAncestorGitDir: false,
  gitDirPath: null,
  gitRootPath: null,
  gitignoreFiles: [],
  configPathRelativeToGitRoot: null,
};

/**
 * Walks upward from `fromPath` looking for an ancestor `.git` directory,
 * then — once found — walks back down from the git root to `targetRoot`,
 * collecting every `.gitignore` along that chain (improvement_plan.md
 * 1.14: nested-.gitignore support, not just the root one). Per the read
 * boundary in instruction.md §8, this is the only place discovery reads
 * outside the scan target: it may check directory existence and read
 * `.gitignore` files, nothing else (no git history, no other files).
 * Scoping a nested file's patterns to its own directory and matching
 * them against a specific path is pure logic with no I/O, and lives in
 * `checks/shared/gitignoreMatch.ts`.
 *
 * Deliberately does not walk *past* `targetRoot` into its
 * subdirectories (e.g. a `.gitignore` inside `targetRoot/skills/some-
 * skill/` is out of scope) — every path CHAP-SEC-002/006/OBS-004 checks
 * lives at or directly under `targetRoot`, so this covers the realistic
 * cases without a per-checked-path walk.
 */
export function detectGitContext(fromPath: string, targetRoot: string): GitContext {
  let dir = isDirectory(fromPath) ? fromPath : path.dirname(fromPath);

  for (let i = 0; i < MAX_ANCESTOR_LEVELS; i++) {
    const gitDirPath = path.join(dir, '.git');
    if (existsSync(gitDirPath)) {
      return {
        hasAncestorGitDir: true,
        gitDirPath,
        gitRootPath: dir,
        gitignoreFiles: collectGitignoreFiles(dir, targetRoot),
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

function collectGitignoreFiles(gitRoot: string, targetRoot: string): GitignoreFile[] {
  const files: GitignoreFile[] = [];
  const relFromRoot = path.relative(gitRoot, targetRoot);
  // targetRoot should always be gitRoot itself or a descendant (gitRoot
  // was found by walking up from a path at/under targetRoot) — the
  // fallback to "root only" below is defensive, not expected in practice.
  const segments =
    relFromRoot === '' || relFromRoot.startsWith('..') ? [] : relFromRoot.split(path.sep);

  let currentDir = gitRoot;
  let currentRel = '';
  pushGitignoreIfPresent(files, currentDir, currentRel);
  for (const segment of segments) {
    currentDir = path.join(currentDir, segment);
    currentRel = currentRel === '' ? segment : `${currentRel}/${segment}`;
    pushGitignoreIfPresent(files, currentDir, currentRel);
  }
  return files;
}

function pushGitignoreIfPresent(
  files: GitignoreFile[],
  dir: string,
  dirRelativeToRoot: string,
): void {
  const gitignorePath = path.join(dir, '.gitignore');
  if (!existsSync(gitignorePath)) {
    return;
  }
  try {
    const patterns = readFileSync(gitignorePath, 'utf8')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
    files.push({ dirRelativeToRoot, patterns });
  } catch {
    // Defensive: an unreadable .gitignore just contributes no patterns,
    // same "never throw" posture the rest of discovery takes.
  }
}

function isDirectory(candidate: string): boolean {
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}
