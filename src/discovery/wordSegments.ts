/**
 * Splits an identifier into lowercase segments on `_`, `-`, and camelCase
 * boundaries, e.g. `apiKey`/`api_key`/`API_KEY` -> `['api', 'key']`, or
 * `deleteFile` -> `['delete', 'file']`. Shared by `configParser.ts`
 * (secret-key-name matching, e.g. `private_key`) and
 * `astCapabilities.ts` (destructive-action identifier matching, e.g.
 * `deleteFile`) — the same underlying question in both places: "does
 * this identifier contain a specific whole word as one of its parts",
 * robust against both false negatives a bare word-boundary regex
 * produces (`\bdelete\b` doesn't match `deleteFile` — no non-word
 * boundary between `e` and `F`) and false positives a substring match
 * produces (`token` matching inside `tokenizer`).
 */
export function splitWordSegments(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .split(/[_-]+/)
    .map((segment) => segment.toLowerCase())
    .filter((segment) => segment.length > 0);
}
