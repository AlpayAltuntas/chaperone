import YAML from 'yaml';
import { parseKeyPathSegments } from '../discovery/configParser.js';

/**
 * Sets values in a YAML or JSON config's source text and returns the new
 * text, preserving everything else. YAML goes through `YAML.Document`
 * (comments and layout survive). JSON is edited in place by byte offset,
 * using the value positions `YAML.parseDocument` reports (JSON is YAML
 * 1.2), so key order, indentation, and spacing are untouched
 * (PROPOSED_FIXES.md 5). Key paths use maskConfig's form
 * (`trust.tool_allowlist[0]`) and must already exist.
 */
export function setConfigValues(
  source: string,
  format: 'yaml' | 'json',
  edits: ReadonlyArray<{ keyPath: string; value: string | boolean }>,
): string {
  const doc = YAML.parseDocument(source, { keepSourceTokens: true });
  if (format === 'yaml') {
    for (const { keyPath, value } of edits) {
      doc.setIn(parseKeyPathSegments(keyPath), value);
    }
    return doc.toString();
  }
  const replacements: Array<{ start: number; end: number; text: string }> = [];
  for (const { keyPath, value } of edits) {
    const node: unknown = doc.getIn(parseKeyPathSegments(keyPath), true);
    if (!YAML.isScalar(node) || node.range === null || node.range === undefined) {
      throw new Error(`cannot locate '${keyPath}' in the JSON config`);
    }
    replacements.push({ start: node.range[0], end: node.range[1], text: JSON.stringify(value) });
  }
  let result = source;
  for (const { start, end, text } of replacements.sort((a, b) => b.start - a.start)) {
    result = `${result.slice(0, start)}${text}${result.slice(end)}`;
  }
  return result;
}
