import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  extractBaseVersion,
  isVersionInRange,
} from '../../../src/checks/shared/semver.js';

describe('extractBaseVersion', () => {
  it('extracts the version from a bare specifier', () => {
    expect(extractBaseVersion('4.17.15')).toBe('4.17.15');
  });

  it('strips common range operators', () => {
    expect(extractBaseVersion('^4.17.15')).toBe('4.17.15');
    expect(extractBaseVersion('~1.2.5')).toBe('1.2.5');
    expect(extractBaseVersion('>=4.0.0')).toBe('4.0.0');
  });

  it('takes the first version token in a multi-clause range', () => {
    expect(extractBaseVersion('>=1.0.0 <2.0.0')).toBe('1.0.0');
  });

  it('returns null for a specifier with no X.Y.Z-shaped token', () => {
    expect(extractBaseVersion('latest')).toBeNull();
    expect(extractBaseVersion('*')).toBeNull();
    expect(extractBaseVersion('github:user/repo')).toBeNull();
    expect(extractBaseVersion('workspace:*')).toBeNull();
  });
});

describe('compareVersions', () => {
  it('compares numerically, not lexicographically', () => {
    expect(compareVersions('4.9.0', '4.17.0')).toBeLessThan(0);
    expect(compareVersions('4.17.0', '4.9.0')).toBeGreaterThan(0);
  });

  it('returns 0 for equal versions', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });

  it('treats a missing part as 0', () => {
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
    expect(compareVersions('0', '0.0.1')).toBeLessThan(0);
  });
});

describe('isVersionInRange', () => {
  it('is true at the introduced boundary (inclusive)', () => {
    expect(isVersionInRange('3.7.0', '3.7.0', '4.17.19')).toBe(true);
  });

  it('is false at the fixed boundary (exclusive)', () => {
    expect(isVersionInRange('4.17.19', '3.7.0', '4.17.19')).toBe(false);
  });

  it('is true strictly between the bounds', () => {
    expect(isVersionInRange('4.17.15', '3.7.0', '4.17.19')).toBe(true);
  });

  it('is false below introduced or at/above fixed', () => {
    expect(isVersionInRange('3.6.9', '3.7.0', '4.17.19')).toBe(false);
    expect(isVersionInRange('4.18.0', '3.7.0', '4.17.19')).toBe(false);
  });

  it('handles "0" as a valid lower bound (OSV convention for "always vulnerable up to fixed")', () => {
    expect(isVersionInRange('0.0.1', '0', '1.2.6')).toBe(true);
    expect(isVersionInRange('1.2.6', '0', '1.2.6')).toBe(false);
  });
});
