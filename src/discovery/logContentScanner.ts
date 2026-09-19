import { closeSync, openSync, readFileSync, readSync, statSync } from 'node:fs';
import type { LoggedSecretMatch } from '../model/types.js';
import { looksLikeSecretKeyName, maskSecretValue } from './configParser.js';
import { errorMessage } from './errors.js';

// Bounded scan (improvement_plan.md 1.8/2.1): only the last MAX_SCAN_BYTES
// of the log file are ever read, and scanning stops after MAX_MATCHES —
// this is a security tool auditing files that could themselves be huge or
// adversarial, not a general-purpose log viewer.
const MAX_SCAN_BYTES = 256 * 1024;
const MAX_MATCHES = 20;

// A permissive key=value / "key": "value" extractor over free-text log
// lines, not a real log-format parser — deliberately simple, matching
// CHAP-SUP-003's precedent of a documented, weak-but-honest v1 heuristic
// rather than a generic entropy scanner (improvement_plan.md 2.1 offers
// both options; this picks the one that reuses existing, tested
// secret-key-name logic instead of inventing new matching from scratch).
const KEY_VALUE_PATTERN = /["']?([A-Za-z0-9_.-]{2,40})["']?\s*[:=]\s*["']?([^\s"',}]{8,})["']?/g;

export interface LogContentScanResult {
  matches: LoggedSecretMatch[];
  skippedReason: string | null;
}

/**
 * Scans existing log file content for secret-shaped key/value pairs
 * already written to disk — distinct from CHAP-SEC-004/CHAP-OBS-002,
 * which only reason about whether logging *will* leak going forward, not
 * whether it already has. Every matched value is masked before being
 * placed in the model, the same way configParser.ts masks config
 * secrets; the real value is never retained.
 */
export function scanExistingLogContent(logPath: string): LogContentScanResult {
  let size: number;
  try {
    size = statSync(logPath).size;
  } catch {
    return { matches: [], skippedReason: null };
  }
  if (size === 0) {
    return { matches: [], skippedReason: null };
  }

  let content: string;
  try {
    content = readBoundedTail(logPath, size);
  } catch (err) {
    return { matches: [], skippedReason: `could not read log content: ${errorMessage(err)}` };
  }

  const matches: LoggedSecretMatch[] = [];
  for (const line of content.split('\n')) {
    if (matches.length >= MAX_MATCHES) {
      break;
    }
    KEY_VALUE_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = KEY_VALUE_PATTERN.exec(line)) !== null && matches.length < MAX_MATCHES) {
      const key = match[1];
      const value = match[2];
      if (key === undefined || value === undefined || !looksLikeSecretKeyName(key)) {
        continue;
      }
      matches.push({ keyName: key, displayValue: maskSecretValue(value) });
    }
  }

  return {
    matches,
    skippedReason:
      size > MAX_SCAN_BYTES
        ? `log file is ${String(size)} bytes; only the last ${String(MAX_SCAN_BYTES)} bytes were scanned for existing secrets`
        : null,
  };
}

function readBoundedTail(logPath: string, size: number): string {
  if (size <= MAX_SCAN_BYTES) {
    return readFileSync(logPath, 'utf8');
  }
  const fd = openSync(logPath, 'r');
  try {
    const buffer = Buffer.alloc(MAX_SCAN_BYTES);
    readSync(fd, buffer, 0, MAX_SCAN_BYTES, size - MAX_SCAN_BYTES);
    return buffer.toString('utf8');
  } finally {
    closeSync(fd);
  }
}
