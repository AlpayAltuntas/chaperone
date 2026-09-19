import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { isGitignored } from '../../../src/checks/shared/gitignoreMatch.js';
import type { GitignoreFile } from '../../../src/model/types.js';

// improvement_plan.md 5.2 — property-based/fuzz testing of the
// hand-rolled-integration `.gitignore` matcher (real gitignore
// semantics via the `ignore` package, improvement_plan.md 1.14, but the
// nested-file pattern-scoping logic — scopePattern — is this project's
// own code and exactly the kind of small, pure, input-shape-sensitive
// function 5.2 calls out).

const gitignoreFileArbitrary: fc.Arbitrary<GitignoreFile> = fc.record({
  dirRelativeToRoot: fc.constantFrom('', 'skills', 'skills/sub', 'a/b/c'),
  patterns: fc.array(fc.string({ maxLength: 30 }), { maxLength: 10 }),
});

describe('isGitignored — fuzz', () => {
  it('never throws for arbitrary paths, patterns, and directory flags', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 50 }),
        fc.array(gitignoreFileArbitrary, { maxLength: 5 }),
        fc.boolean(),
        (relativePath, gitignoreFiles, isDirectory) => {
          expect(() => isGitignored(relativePath, gitignoreFiles, isDirectory)).not.toThrow();
        },
      ),
    );
  });

  it('is pure — the same inputs always produce the same result, called repeatedly', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 50 }),
        fc.array(gitignoreFileArbitrary, { maxLength: 5 }),
        fc.boolean(),
        (relativePath, gitignoreFiles, isDirectory) => {
          const first = isGitignored(relativePath, gitignoreFiles, isDirectory);
          const second = isGitignored(relativePath, gitignoreFiles, isDirectory);
          expect(second).toBe(first);
        },
      ),
    );
  });

  it('is always false when there are no gitignore files at all, for any path', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 50 }), fc.boolean(), (relativePath, isDirectory) => {
        expect(isGitignored(relativePath, [], isDirectory)).toBe(false);
      }),
    );
  });

  // A "recall" property: a plain alphanumeric filename listed verbatim
  // in the root .gitignore is always ignored — regardless of what other
  // noise patterns/files are also present, and regardless of whether
  // it's queried as a file or a directory (a bare pattern with no
  // trailing slash matches both).
  const plainNameArbitrary = fc
    .string({
      minLength: 1,
      maxLength: 12,
      unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'.split('')),
    })
    .filter((s) => s.length > 0);

  it('a bare filename listed verbatim in the root .gitignore is always ignored', () => {
    fc.assert(
      fc.property(plainNameArbitrary, fc.boolean(), (name, isDirectory) => {
        const gitignoreFiles: GitignoreFile[] = [{ dirRelativeToRoot: '', patterns: [name] }];
        expect(isGitignored(name, gitignoreFiles, isDirectory)).toBe(true);
      }),
    );
  });

  // The precision counterpart: two DIFFERENT plain names — one listed,
  // one not — the unlisted one is never ignored by the other's pattern.
  it('a bare filename NOT listed in any .gitignore, and not equal to the listed one, is never ignored', () => {
    fc.assert(
      fc.property(
        plainNameArbitrary,
        plainNameArbitrary,
        fc.boolean(),
        (listedName, queriedName, isDirectory) => {
          fc.pre(listedName !== queriedName);
          const gitignoreFiles: GitignoreFile[] = [
            { dirRelativeToRoot: '', patterns: [listedName] },
          ];
          expect(isGitignored(queriedName, gitignoreFiles, isDirectory)).toBe(false);
        },
      ),
    );
  });

  // Nested-file scoping: a bare pattern declared in a NESTED
  // .gitignore only ever matches within that directory's own subtree,
  // never at the root — the exact behavior scopePattern exists to
  // implement (improvement_plan.md 1.14).
  it("a nested .gitignore's bare pattern matches within its own directory but not an unrelated root-level file of the same name", () => {
    fc.assert(
      fc.property(plainNameArbitrary, fc.boolean(), (name, isDirectory) => {
        const gitignoreFiles: GitignoreFile[] = [
          { dirRelativeToRoot: 'skills/sub', patterns: [name] },
        ];
        expect(isGitignored(`skills/sub/${name}`, gitignoreFiles, isDirectory)).toBe(true);
        expect(isGitignored(name, gitignoreFiles, isDirectory)).toBe(false);
      }),
    );
  });
});
