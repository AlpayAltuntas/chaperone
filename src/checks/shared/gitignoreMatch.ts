import path from 'node:path';

/**
 * A deliberately small, documented subset of gitignore semantics — enough
 * for CHAP-SEC-002's "is the config file excluded by the repo's
 * .gitignore" question, not a full implementation. Supports `*`/`?`
 * wildcards, directory-only (`/` suffix) and root-anchored (`/` elsewhere
 * in the pattern) patterns, and `!` negation processed in order. Pure
 * logic over the lines discovery already read (see gitContext.ts) — no
 * I/O here.
 *
 * Known gaps vs real gitignore: no `**`, no nested (non-root) `.gitignore`
 * files.
 */
export function isGitignored(relativePath: string, patterns: readonly string[]): boolean {
  const normalized = relativePath.split(path.sep).join('/');
  const segments = normalized.split('/');

  let ignored = false;
  for (const raw of patterns) {
    const negate = raw.startsWith('!');
    const pattern = negate ? raw.slice(1) : raw;
    const dirOnly = pattern.endsWith('/');
    const cleanPattern = dirOnly ? pattern.slice(0, -1) : pattern;
    if (cleanPattern.length === 0) {
      continue;
    }

    const anchored = cleanPattern.includes('/');
    const regex = globToRegExp(cleanPattern);
    const matched = anchored
      ? regex.test(normalized)
      : segments.some((segment) => regex.test(segment));

    if (matched) {
      ignored = !negate;
    }
  }
  return ignored;
}

function globToRegExp(glob: string): RegExp {
  let pattern = '';
  for (const char of glob) {
    if (char === '*') {
      pattern += '[^/]*';
    } else if (char === '?') {
      pattern += '[^/]';
    } else {
      pattern += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${pattern}$`);
}
