import { describe, expect, it } from 'vitest';
import { splitWordSegments } from '../../src/discovery/wordSegments.js';

// Extracted (improvement_plan.md 1.1/10) from configParser.ts's original
// private keySegments helper — same algorithm, now shared with
// astCapabilities.ts too. These lock in the exact segmentation behavior
// independent of either caller.
describe('splitWordSegments', () => {
  it('splits camelCase', () => {
    expect(splitWordSegments('deleteFile')).toEqual(['delete', 'file']);
    expect(splitWordSegments('apiKey')).toEqual(['api', 'key']);
  });

  it('splits snake_case', () => {
    expect(splitWordSegments('private_key')).toEqual(['private', 'key']);
  });

  it('splits kebab-case', () => {
    expect(splitWordSegments('api-key')).toEqual(['api', 'key']);
  });

  it('splits SCREAMING_SNAKE_CASE', () => {
    expect(splitWordSegments('API_KEY')).toEqual(['api', 'key']);
  });

  it('handles a single lowercase word', () => {
    expect(splitWordSegments('delete')).toEqual(['delete']);
  });

  it('does not split a run of consecutive capitals as multiple boundaries the way a naive per-letter split would', () => {
    // Only a lower->upper transition is a boundary, so "URL" stays one
    // segment rather than being torn into single letters.
    expect(splitWordSegments('fetchURL')).toEqual(['fetch', 'url']);
  });

  it('filters out empty segments from leading/trailing/double separators', () => {
    expect(splitWordSegments('__private__key__')).toEqual(['private', 'key']);
  });

  it('returns an empty array for an empty string', () => {
    expect(splitWordSegments('')).toEqual([]);
  });
});
