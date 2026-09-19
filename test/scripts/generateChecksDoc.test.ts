import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../../src/checks/index.js';
import { generateChecksDoc } from '../../scripts/generateChecksDoc.js';

describe('generateChecksDoc', () => {
  it('matches the committed CHECKS.md byte-for-byte (regression twin of `npm run docs:checks:check`)', async () => {
    const generated = await generateChecksDoc();
    const committed = readFileSync(path.join('CHECKS.md'), 'utf8');

    expect(generated).toBe(committed);
  });

  it('includes every check id and title from the registry', async () => {
    const generated = await generateChecksDoc();

    for (const check of ALL_CHECKS) {
      expect(generated).toContain(`### ${check.id} — ${check.title}`);
      expect(generated).toContain(check.detects);
      expect(generated).toContain(check.remediation);
    }
  });

  it('formats a multi-mapping OWASP value with an em dash per mapping, not just the first', async () => {
    const generated = await generateChecksDoc();

    // CHAP-INJ-003's OWASP const is 'LLM01: Prompt Injection / LLM08:
    // Excessive Agency' — both colons must become em dashes, not just
    // the first one a naive single-replace would catch.
    expect(generated).toContain('LLM01 — Prompt Injection / LLM08 — Excessive Agency');
  });

  it('shows the severityNote override instead of the plain severity for CHAP-SUP-003', async () => {
    const generated = await generateChecksDoc();
    const severityNote = ALL_CHECKS.find((c) => c.id === 'CHAP-SUP-003')?.severityNote;
    if (severityNote === undefined) {
      throw new Error('CHAP-SUP-003 is expected to have a severityNote');
    }

    expect(generated).toContain(`- **Severity:** ${severityNote}`);
  });

  it('groups checks under the correct category heading, sorted by id', async () => {
    const generated = await generateChecksDoc();

    const categoryIndex = generated.indexOf('## Category A — Secrets & credential hygiene');
    const sec001Index = generated.indexOf('### CHAP-SEC-001');
    const nextCategoryIndex = generated.indexOf('## Category B — Excessive agency & permissions');

    expect(categoryIndex).toBeGreaterThanOrEqual(0);
    expect(sec001Index).toBeGreaterThan(categoryIndex);
    expect(sec001Index).toBeLessThan(nextCategoryIndex);
  });

  it('produces prettier-stable output (idempotent re-formatting)', async () => {
    const generated = await generateChecksDoc();
    const generatedAgain = await generateChecksDoc();

    expect(generated).toBe(generatedAgain);
  });

  it('handles an empty check list without throwing', async () => {
    const result = await generateChecksDoc([]);

    expect(typeof result).toBe('string');
    expect(result).toContain('# Chaperone check catalog');
  });
});
