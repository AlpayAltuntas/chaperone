import { describe, expect, it } from 'vitest';
import { computeScore, severityMeetsThreshold } from '../../src/engine/severity.js';
import type { Finding } from '../../src/model/types.js';

// A distinct check per finding unless one is given: scoring v2 discounts
// repeats of the same check (PROPOSED_FIXES.md 4.3).
let nextCheck = 0;
function makeFinding(
  severity: Finding['severity'],
  checkId = `TEST-${String(nextCheck++)}`,
): Finding {
  return {
    checkId,
    title: 'test',
    severity,
    category: 'secrets',
    owasp: 'LLM06',
    message: 'test',
    location: { filePath: null, line: null, detail: null },
    remediation: 'test',
  };
}

describe('severityMeetsThreshold', () => {
  it('treats a severity as meeting an equal threshold', () => {
    expect(severityMeetsThreshold('high', 'high')).toBe(true);
  });

  it('treats a more severe finding as meeting a lower threshold', () => {
    expect(severityMeetsThreshold('critical', 'high')).toBe(true);
  });

  it('treats a less severe finding as NOT meeting a higher threshold', () => {
    expect(severityMeetsThreshold('medium', 'high')).toBe(false);
  });
});

describe('computeScore', () => {
  it('scores a clean scan (no findings) as a perfect A', () => {
    expect(computeScore([])).toEqual({ score: 100, band: 'A' });
  });

  it('subtracts weighted points per finding by severity', () => {
    const { score } = computeScore([makeFinding('critical'), makeFinding('high')]);
    expect(score).toBe(100 - 25 - 15);
  });

  it('floors the score at 0 rather than going negative', () => {
    const findings = Array.from({ length: 10 }, () => makeFinding('critical'));
    expect(computeScore(findings)).toEqual({ score: 0, band: 'F' });
  });

  it('never lets info-severity findings affect the score', () => {
    const findings = Array.from({ length: 5 }, () => makeFinding('info'));
    expect(computeScore(findings)).toEqual({ score: 100, band: 'A' });
  });

  it('bands exactly at the A/B boundary (deduction 10 -> score 90 -> A)', () => {
    expect(computeScore([makeFinding('medium'), makeFinding('low')]).band).toBe('A');
  });

  it('bands just below the A/B boundary (deduction 13 -> score 87 -> B)', () => {
    expect(computeScore([makeFinding('medium'), makeFinding('low'), makeFinding('low')]).band).toBe(
      'B',
    );
  });

  it('bands exactly at the B/C boundary (1 critical -> deduction 25 -> score 75 -> B)', () => {
    expect(computeScore([makeFinding('critical')]).band).toBe('B');
  });

  it('bands exactly at the C/D boundary (1 critical + 1 high -> deduction 40 -> score 60 -> C)', () => {
    expect(computeScore([makeFinding('critical'), makeFinding('high')]).band).toBe('C');
  });

  it('bands into D (1 critical + 1 high + 1 medium -> deduction 47 -> score 53 -> D)', () => {
    expect(
      computeScore([makeFinding('critical'), makeFinding('high'), makeFinding('medium')]).band,
    ).toBe('D');
  });

  it('bands into F once the deduction is large enough (score < 40)', () => {
    const findings = [
      makeFinding('critical'),
      makeFinding('critical'),
      makeFinding('high'),
      makeFinding('high'),
    ];
    expect(computeScore(findings).band).toBe('F');
  });
});

describe('computeScore — scoring v2: repeats of one check diminish', () => {
  it('halves each further finding of the same check', () => {
    // 15 + 7.5 = 22.5 -> 77.5 -> 78
    expect(computeScore([makeFinding('high', 'X'), makeFinding('high', 'X')]).score).toBe(78);
  });

  it('caps one check at twice its largest weight', () => {
    const tenSkills = Array.from({ length: 10 }, () => makeFinding('high', 'CHAP-SUP-002'));
    expect(computeScore(tenSkills).score).toBe(100 - 30);
  });

  it('uses the largest weight first within a check', () => {
    // 25 + 15/2 + 7/4 = 34.25 -> 65.75 -> 66
    const mixed = [
      makeFinding('medium', 'Y'),
      makeFinding('critical', 'Y'),
      makeFinding('high', 'Y'),
    ];
    expect(computeScore(mixed).score).toBe(66);
  });
});
