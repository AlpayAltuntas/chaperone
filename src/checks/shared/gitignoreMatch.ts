import ignoreFactory from 'ignore';
import type { GitignoreFile } from '../../model/types.js';

/**
 * Real gitignore semantics (`**`, nested `.gitignore` files) via the
 * `ignore` npm package (de facto standard, zero dependencies of its
 * own) — improvement_plan.md 1.14 replaced the original hand-rolled
 * matcher here, which explicitly didn't support either.
 *
 * `ignore` matches one flat set of root-relative patterns; nested
 * `.gitignore` support is layered on top by *scoping* each nested
 * file's patterns to its own directory before feeding everything into
 * one matcher (a standard technique for this library, not something it
 * does automatically) — see `scopePattern` below.
 *
 * Known gap, not solved: `.git/info/exclude` and a user's global
 * `core.excludesFile` aren't read (improvement_plan.md 1.13) — see
 * DECISIONS.md for why that was deliberately left out.
 *
 * Pass `isDirectory: true` when checking a directory (e.g. the memory
 * store, CHAP-OBS-004) — the `ignore` package only matches a
 * directory-only pattern (`foo/`) against a query path that itself
 * carries a trailing slash; it has no other way to know the target is
 * a directory rather than a same-named file.
 */
export function isGitignored(
  relativePath: string,
  gitignoreFiles: readonly GitignoreFile[],
  isDirectory = false,
): boolean {
  if (gitignoreFiles.length === 0) {
    return false;
  }
  const matcher = ignoreFactory();
  for (const file of gitignoreFiles) {
    matcher.add(file.patterns.map((pattern) => scopePattern(pattern, file.dirRelativeToRoot)));
  }
  // The `ignore` package only matches a directory-only pattern (`foo/`)
  // against a query path that itself carries a trailing slash — it has
  // no other way to know the target is a directory.
  const queryPath = isDirectory && !relativePath.endsWith('/') ? `${relativePath}/` : relativePath;
  return matcher.ignores(queryPath);
}

/**
 * Rewrites one pattern line from a `.gitignore` at `dirPrefix` (relative
 * to the git root) into an equivalent root-relative pattern, so it can
 * be combined with every other level's patterns in one matcher.
 *
 * - A pattern already rooted within its own file (`/foo`, or containing
 *   a `/` other than a trailing one, e.g. `sub/foo`) anchors to exactly
 *   `dirPrefix/foo` (or `dirPrefix/sub/foo`).
 * - A bare single-segment pattern (`foo`) matches at *any* depth within
 *   its file's directory, not just directly inside it — `dirPrefix/**\/foo`
 *   expresses that, since gitignore's `**` between slashes matches zero
 *   or more directories (so it still covers `dirPrefix/foo` itself).
 *
 * A pattern from the root `.gitignore` (`dirPrefix === ''`) needs no
 * rewriting at all.
 */
function scopePattern(pattern: string, dirPrefix: string): string {
  if (dirPrefix === '') {
    return pattern;
  }

  const negate = pattern.startsWith('!');
  let body = negate ? pattern.slice(1) : pattern;

  const dirOnly = body.endsWith('/');
  if (dirOnly) {
    body = body.slice(0, -1);
  }
  if (body.length === 0) {
    return pattern;
  }

  const rooted = body.startsWith('/');
  const bare = rooted ? body.slice(1) : body;
  const hasInternalSlash = bare.includes('/');

  const scopedBody =
    rooted || hasInternalSlash ? `${dirPrefix}/${bare}` : `${dirPrefix}/**/${bare}`;

  return `${negate ? '!' : ''}${scopedBody}${dirOnly ? '/' : ''}`;
}
