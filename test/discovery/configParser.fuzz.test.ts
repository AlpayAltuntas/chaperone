import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  extractEnvVarName,
  looksLikeEnvReference,
  looksLikeSecretKeyName,
  maskConfig,
  parseConfigSource,
} from '../../src/discovery/configParser.js';

// improvement_plan.md 5.2 — property-based/fuzz testing (fast-check) of
// the config parser, "exactly the kind of small, pure,
// input-shape-sensitive function that benefits most from this, beyond
// the specific hand-picked cases in the current test suite". Each
// property below runs against hundreds of generated inputs per test run
// (fast-check's default), not the handful of example-based cases
// test/discovery/configParser.test.ts already covers.

describe('parseConfigSource — fuzz', () => {
  it('never throws anything other than a real Error, for arbitrary JSON source text', () => {
    fc.assert(
      fc.property(fc.string(), (source) => {
        try {
          parseConfigSource(source, 'json');
        } catch (err) {
          expect(err).toBeInstanceOf(Error);
        }
      }),
    );
  });

  it('never throws anything other than a real Error, for arbitrary YAML source text', () => {
    fc.assert(
      fc.property(fc.string(), (source) => {
        try {
          parseConfigSource(source, 'yaml');
        } catch (err) {
          expect(err).toBeInstanceOf(Error);
        }
      }),
    );
  });

  it('behaves identically to a plain JSON.parse, for any generated JSON value', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const source = JSON.stringify(value);
        // Compared against JSON.parse(source), not the original `value`
        // — JSON itself is lossy for a handful of JS values (-0 stringifies
        // to "0", losing its sign), so the correct invariant is "does the
        // exact same lossiness JSON.parse already has", not "is this a
        // perfect round trip of the original fast-check-generated value".
        expect(parseConfigSource(source, 'json')).toEqual(JSON.parse(source) as unknown);
      }),
    );
  });
});

describe('maskConfig — fuzz', () => {
  it('never throws for an arbitrary JSON-shaped tree', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => maskConfig(value)).not.toThrow();
      }),
    );
  });

  it('never throws for arbitrary non-JSON-shaped values either (functions, symbols, etc. embedded in objects)', () => {
    fc.assert(
      fc.property(fc.anything(), (value) => {
        expect(() => maskConfig(value)).not.toThrow();
      }),
    );
  });

  // The real security property: a literal secret-shaped value, once
  // masked, must never appear verbatim anywhere in the returned data
  // tree — not "usually", not "for the hand-picked examples", but for
  // any randomly generated secret-looking key + a long, non-env-
  // reference-looking literal value.
  it('never leaks the real literal value of a secret-shaped field into the masked output', () => {
    const secretKeyArbitrary = fc.constantFrom(
      'api_key',
      'apiKey',
      'token',
      'secret',
      'password',
      'private_key',
      'credential',
    );
    // Long (>8 chars, so maskSecretValue's partial-reveal form is used,
    // the stricter case) and alphanumeric-only, so it can never
    // accidentally look like an env-var reference (${...}/env:.../$VAR)
    // and get skipped from masking entirely.
    const secretValueArbitrary = fc
      .string({
        minLength: 12,
        maxLength: 40,
        unit: fc.constantFrom(
          ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split(''),
        ),
      })
      .filter((v) => !looksLikeEnvReference(v));

    fc.assert(
      fc.property(secretKeyArbitrary, secretValueArbitrary, (key, value) => {
        const result = maskConfig({ [key]: value });
        const serialized = JSON.stringify(result.data);
        expect(serialized.includes(value)).toBe(false);
        expect(result.secretFields).toHaveLength(1);
        expect(result.secretFields[0]?.looksLikeEnvReference).toBe(false);
      }),
    );
  });

  it('never touches a value that already looks like an env-var reference', () => {
    const secretKeyArbitrary = fc.constantFrom('api_key', 'token', 'secret', 'password');
    const envVarNameArbitrary = fc
      .string({
        minLength: 1,
        maxLength: 20,
        unit: fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ_'.split('')),
      })
      .filter((s) => s.length > 0);

    fc.assert(
      fc.property(secretKeyArbitrary, envVarNameArbitrary, (key, varName) => {
        const reference = `\${${varName}}`;
        const result = maskConfig({ [key]: reference });
        expect((result.data as Record<string, unknown>)[key]).toBe(reference);
        expect(result.secretFields[0]?.looksLikeEnvReference).toBe(true);
      }),
    );
  });
});

describe('looksLikeSecretKeyName / looksLikeEnvReference — fuzz', () => {
  it('never throws for arbitrary key names', () => {
    fc.assert(
      fc.property(fc.string(), (key) => {
        expect(() => looksLikeSecretKeyName(key)).not.toThrow();
      }),
    );
  });

  it('never throws for arbitrary values', () => {
    fc.assert(
      fc.property(fc.string(), (value) => {
        expect(() => looksLikeEnvReference(value)).not.toThrow();
      }),
    );
  });

  it('${VAR}/env:VAR/$VAR are always recognized as an env reference, and extractEnvVarName round-trips the name', () => {
    const varNameArbitrary = fc
      .string({
        minLength: 1,
        maxLength: 20,
        unit: fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789'.split('')),
      })
      .filter((s) => s.length > 0 && !/^[0-9]/.test(s));

    fc.assert(
      fc.property(varNameArbitrary, (name) => {
        for (const form of [`\${${name}}`, `env:${name}`, `$${name}`]) {
          expect(looksLikeEnvReference(form)).toBe(true);
          expect(extractEnvVarName(form)).toBe(name);
        }
      }),
    );
  });

  it('a plain word with no secret-shaped segment is never flagged, for a fuzzed non-secret vocabulary', () => {
    const nonSecretWords = fc.constantFrom(
      'name',
      'description',
      'host',
      'port',
      'enabled',
      'level',
      'path',
      'provider',
      'tokenizer', // contains "token" as a substring, but not as a whole word segment
      'keyboard', // contains "key" as a substring, but not as a whole word segment
    );

    fc.assert(
      fc.property(nonSecretWords, (word) => {
        expect(looksLikeSecretKeyName(word)).toBe(false);
      }),
    );
  });
});
