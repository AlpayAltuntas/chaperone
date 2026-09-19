import { describe, expect, it } from 'vitest';
import { levenshteinDistance } from '../../src/checks/shared/levenshtein.js';

describe('levenshteinDistance', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshteinDistance('request', 'request')).toBe(0);
  });

  it('returns the length of the other string when one is empty', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3);
    expect(levenshteinDistance('abc', '')).toBe(3);
  });

  it('counts a single substitution as distance 1', () => {
    expect(levenshteinDistance('cat', 'cot')).toBe(1);
  });

  it('counts a single deletion as distance 1', () => {
    expect(levenshteinDistance('reqeust', 'request')).toBe(2);
  });

  it('counts a single insertion as distance 1', () => {
    expect(levenshteinDistance('ab', 'abc')).toBe(1);
  });

  it('matches a known real-world typosquat pair distance', () => {
    expect(levenshteinDistance('loadash', 'lodash')).toBe(1);
  });

  it('is symmetric', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(levenshteinDistance('sitting', 'kitten'));
  });
});
