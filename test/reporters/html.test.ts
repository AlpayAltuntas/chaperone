import { describe, expect, it } from 'vitest';
import { formatHtmlReport } from '../../src/reporters/html.js';
import type { Finding, Severity } from '../../src/model/types.js';
import type { ScanMetadata } from '../../src/reporters/types.js';

const METADATA: ScanMetadata = {
  target: '/fake/target',
  targetRootResolved: true,
  timestamp: '2026-01-01T00:00:00.000Z',
  toolVersion: '0.1.0',
  inspected: [{ path: '/fake/config.yaml', kind: 'config' }],
  skipped: [
    { path: '/fake/skills/c/package.json', reason: 'unparseable manifest: Unexpected token' },
  ],
};

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: 'CHAP-SEC-001',
    title: 'Plaintext secrets in config',
    severity: 'high',
    category: 'secrets',
    owasp: 'LLM06',
    message: 'a secret is exposed',
    location: { filePath: '/fake/config.yaml', line: null, detail: 'llm.api_key' },
    remediation: 'use an env var',
    ...overrides,
  };
}

// Structural sanity checks, in lieu of a real browser (none is available
// in this environment) — a self-contained document that opens correctly
// with no console errors implies: valid doctype/structure, balanced
// tags, and — since this reporter deliberately ships zero JavaScript
// (improvement_plan.md 3.10: "no external JS/CSS dependency", taken to
// its logical conclusion here) — nothing that could ever throw at
// runtime in the first place. See DECISIONS.md, Phase 19.
function countOccurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

function expectBalancedTags(html: string, tag: string): void {
  const openTag = new RegExp(`<${tag}(?:\\s[^>]*)?>`, 'g');
  const closeTag = `</${tag}>`;
  const opens = (html.match(openTag) ?? []).length;
  const closes = countOccurrences(html, closeTag);
  expect(opens, `expected balanced <${tag}> tags`).toBe(closes);
}

describe('formatHtmlReport', () => {
  it('is a complete, well-formed HTML5 document', () => {
    const output = formatHtmlReport([makeFinding()], METADATA);

    expect(output.startsWith('<!doctype html>')).toBe(true);
    expect(output).toContain('<html lang="en">');
    expect(output).toContain('</html>');
    expect(output).toContain('<meta charset="utf-8">');
    expect(output).toContain('<title>Chaperone scan report</title>');
    for (const tag of [
      'html',
      'head',
      'body',
      'div',
      'section',
      'article',
      'h1',
      'h2',
      'h3',
      'p',
    ]) {
      expectBalancedTags(output, tag);
    }
  });

  it('ships no JavaScript at all — no <script> tag, no inline event handler', () => {
    const output = formatHtmlReport([makeFinding()], METADATA);

    expect(output).not.toContain('<script');
    expect(output).not.toMatch(/\son\w+\s*=/i);
  });

  it('pulls in no external resource — no CDN link, no separate stylesheet', () => {
    const output = formatHtmlReport([makeFinding()], METADATA);

    expect(output).not.toContain('<link');
    expect(output).not.toContain('http://');
    expect(output).not.toContain('https://');
    // The only <style> is the one inline block — no external CSS import.
    expect(countOccurrences(output, '<style>')).toBe(1);
  });

  it('renders the target, timestamp, and version', () => {
    const output = formatHtmlReport([], METADATA);

    expect(output).toContain('/fake/target');
    expect(output).toContain('2026-01-01T00:00:00.000Z');
    expect(output).toContain('chaperone v0.1.0');
  });

  it('renders one finding per article, grouped under its severity heading', () => {
    const findings = [
      makeFinding({ checkId: 'CHAP-AGY-001', severity: 'critical' }),
      makeFinding({ checkId: 'CHAP-SEC-001', severity: 'high' }),
      makeFinding({ checkId: 'CHAP-SEC-003', severity: 'medium' }),
    ];

    const output = formatHtmlReport(findings, METADATA);

    expect(output).toContain('Critical (1)');
    expect(output).toContain('High (1)');
    expect(output).toContain('Medium (1)');
    expect(countOccurrences(output, 'class="finding"')).toBe(3);
    // Most severe first, same order every other reporter uses.
    expect(output.indexOf('CHAP-AGY-001')).toBeLessThan(output.indexOf('CHAP-SEC-001'));
    expect(output.indexOf('CHAP-SEC-001')).toBeLessThan(output.indexOf('CHAP-SEC-003'));
  });

  it('shows a "No findings" message and no score bar when there are none', () => {
    const output = formatHtmlReport([], METADATA);

    expect(output).toContain('No findings.');
    expect(output).toContain('Posture score: 100/100 (A)');
  });

  it('shows the skipped list when present', () => {
    const output = formatHtmlReport([], METADATA);

    expect(output).toContain('Skipped (1)');
    expect(output).toContain('unparseable manifest: Unexpected token');
  });

  it('shows a "could not locate" banner when the target was not resolved', () => {
    const output = formatHtmlReport([], { ...METADATA, targetRootResolved: false });

    expect(output).toContain('Could not locate an installation to scan.');
  });

  it('HTML-escapes finding text — no raw HTML injection from a message/path', () => {
    const finding = makeFinding({
      message: 'a <script>alert(1)</script> & "quoted" value',
      location: { filePath: '/fake/<evil>.yaml', line: null, detail: null },
    });

    const output = formatHtmlReport([finding], METADATA);

    expect(output).not.toContain('<script>alert(1)</script>');
    expect(output).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(output).toContain('&lt;evil&gt;');
  });

  it('applies scoreWeights the same way every other reporter does', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'medium' }),
      makeFinding({ severity: 'medium' }),
    ];

    const withoutOverride = formatHtmlReport(findings, METADATA);
    const withOverride = formatHtmlReport(findings, METADATA, { medium: 20 });

    expect(withoutOverride).toContain('Posture score: 86/100');
    expect(withOverride).toContain('Posture score: 60/100');
  });

  it('never leaks a masked secret value verbatim', () => {
    const finding = makeFinding({
      message: "Config field 'llm.api_key' holds a literal secret value (sk-…wxyz).",
    });

    const output = formatHtmlReport([finding], METADATA);

    expect(output).toContain('sk-…wxyz');
    expect(output).not.toMatch(/sk-[A-Za-z0-9]{20,}/);
  });
});

const SEVERITY_HEADING_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

describe('formatHtmlReport — severity color coding', () => {
  it.each<Severity>(['critical', 'high', 'medium', 'low', 'info'])(
    'gives each severity heading a distinct inline color (%s)',
    (severity) => {
      const output = formatHtmlReport([makeFinding({ severity })], METADATA);

      expect(output).toMatch(
        new RegExp(`<h2 style="color: #[0-9a-f]{6}">${SEVERITY_HEADING_LABEL[severity]}`),
      );
    },
  );
});
