/**
 * Classic dynamic-programming Levenshtein (edit) distance between two
 * strings — the number of single-character insertions, deletions, or
 * substitutions to turn `a` into `b`. Used by CHAP-SUP-006 to flag a
 * dependency name that's suspiciously close to a well-known package
 * (`reqeust` vs `request`), a real, common typosquatting technique.
 */
export function levenshteinDistance(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  if (a.length === 0) {
    return b.length;
  }
  if (b.length === 0) {
    return a.length;
  }

  let previousRow = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 0; i < a.length; i++) {
    const currentRow = [i + 1];
    for (let j = 0; j < b.length; j++) {
      const deletionCost = (previousRow[j + 1] ?? 0) + 1;
      const insertionCost = (currentRow[j] ?? 0) + 1;
      const substitutionCost = (previousRow[j] ?? 0) + (a[i] === b[j] ? 0 : 1);
      currentRow.push(Math.min(deletionCost, insertionCost, substitutionCost));
    }
    previousRow = currentRow;
  }

  return previousRow[b.length] ?? 0;
}
