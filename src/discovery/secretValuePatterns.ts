/**
 * Value-based secret detection (PROPOSED_FIXES.md 3.1). Key-name
 * matching alone misses a literal secret stored under an innocuous key
 * (`headers.Authorization`, `base_url`, `github`), and that value then
 * survives masking into the model. These patterns recognize the value
 * itself.
 *
 * Precision over recall: every pattern is anchored to a provider prefix,
 * a fixed structure, or an explicit scheme. There's no entropy scoring,
 * which is too noisy on hashes, UUIDs, and base64 (see DECISIONS.md).
 */

interface TokenPattern {
  name: string;
  /** Matched against a whole token, i.e. bounded by non-token characters on both sides. */
  token: RegExp;
}

// Ordered most-specific first: `sk-ant-`/`sk-proj-` must win over `sk-`.
const TOKEN_PATTERNS: readonly TokenPattern[] = [
  { name: 'Anthropic API key', token: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI API key', token: /sk-proj-[A-Za-z0-9_-]{20,}/ },
  { name: 'Stripe live key', token: /(?:sk|rk)_live_[A-Za-z0-9]{20,}/ },
  { name: 'OpenAI-style API key', token: /sk-[A-Za-z0-9]{32,}/ },
  { name: 'GitHub token', token: /(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{30,}/ },
  { name: 'GitHub fine-grained token', token: /github_pat_[A-Za-z0-9_]{22,}/ },
  { name: 'Slack token', token: /xox[abposr]-[A-Za-z0-9-]{10,}/ },
  { name: 'AWS access key ID', token: /(?:AKIA|ASIA)[A-Z0-9]{16}/ },
  { name: 'Google API key', token: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'GitLab token', token: /glpat-[A-Za-z0-9_-]{20,}/ },
  { name: 'npm token', token: /npm_[A-Za-z0-9]{36}/ },
  { name: 'Hugging Face token', token: /hf_[A-Za-z0-9]{30,}/ },
];

// Characters that can appear inside a token above. A match only counts
// when it isn't embedded in a longer run of these, so `task-ant-…` or
// `xhf_…` never match.
const TOKEN_CHAR = 'A-Za-z0-9_-';

const COMPILED_TOKEN_PATTERNS = TOKEN_PATTERNS.map(({ name, token }) => ({
  name,
  regex: new RegExp(`(?<![${TOKEN_CHAR}])(${token.source})(?![${TOKEN_CHAR}])`, 'g'),
}));

const PEM_PRIVATE_KEY = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;

// `scheme://user:password@host`. The password must be non-empty; a bare
// `user@host` has no secret in it.
const URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)([^:/@\s]+):([^@\s/]+)@/gi;

// `Bearer <token>` / `Basic <base64>` / `token <value>` as a whole value
// (an Authorization header). The credential must be at least 8
// characters so `Bearer x` placeholders don't match.
const AUTH_SCHEME = /^(Bearer|Basic|Token)\s+(\S{8,})$/i;

// The same "this is an indirect reference" forms configParser.ts accepts.
const ENV_REF = /^(?:\$\{[A-Za-z0-9_]+(?::[-=?+][^}]*)?\}|\$[A-Za-z0-9_]+|env:[A-Za-z0-9_]+)$/i;

export interface SecretValueMatch {
  /** Human-readable name of the first pattern that matched, e.g. "GitHub token". */
  pattern: string;
  /** The input with every secret portion masked; safe to store and print. */
  masked: string;
}

/**
 * Returns a match when `value` contains a secret-shaped literal, with
 * every secret portion masked. Returns null when nothing matches,
 * including when the credential part is itself an env reference
 * (`Bearer ${TOKEN}`, `https://user:${PASS}@host`).
 */
export function detectSecretValue(
  value: string,
  maskSecret: (secret: string) => string,
): SecretValueMatch | null {
  const authScheme = AUTH_SCHEME.exec(value.trim());
  if (authScheme?.[1] !== undefined && authScheme[2] !== undefined) {
    const credential = authScheme[2];
    if (ENV_REF.test(credential)) {
      return null;
    }
    return {
      pattern: `${authScheme[1]} credential`,
      masked: `${authScheme[1]} ${maskSecret(credential)}`,
    };
  }

  if (PEM_PRIVATE_KEY.test(value)) {
    return { pattern: 'PEM private key', masked: maskSecret(value) };
  }

  const matchedPatterns: string[] = [];
  let masked = value;

  masked = masked.replace(URL_USERINFO, (whole, scheme: string, user: string, password: string) => {
    if (ENV_REF.test(password)) {
      return whole;
    }
    matchedPatterns.push('password in URL');
    return `${scheme}${user}:***@`;
  });

  for (const { name, regex } of COMPILED_TOKEN_PATTERNS) {
    masked = masked.replace(regex, (token: string) => {
      matchedPatterns.push(name);
      return maskSecret(token);
    });
  }

  const [first] = matchedPatterns;
  return first === undefined ? null : { pattern: first, masked };
}

export interface SecretInText {
  pattern: string;
  /** The matched secret, masked. */
  masked: string;
  /** The raw matched text, for overlap checks by the caller only; never store it. */
  raw: string;
}

/**
 * Finds secret-shaped tokens anywhere in free text (log lines). Unlike
 * `detectSecretValue`, it reports each occurrence separately, and an
 * auth scheme is matched mid-line (`Authorization: Bearer …`).
 */
export function findSecretsInText(
  text: string,
  maskSecret: (secret: string) => string,
): SecretInText[] {
  const found: SecretInText[] = [];

  for (const match of text.matchAll(/\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{16,})/g)) {
    const [raw, scheme, credential] = match;
    if (scheme !== undefined && credential !== undefined) {
      found.push({ pattern: `${scheme} credential`, masked: maskSecret(credential), raw });
    }
  }

  for (const match of text.matchAll(URL_USERINFO)) {
    const [raw, , , password] = match;
    if (password !== undefined && !ENV_REF.test(password)) {
      found.push({ pattern: 'password in URL', masked: '***', raw });
    }
  }

  for (const { name, regex } of COMPILED_TOKEN_PATTERNS) {
    for (const match of text.matchAll(regex)) {
      const raw = match[1];
      // A token inside an auth header already matched above is one secret, not two.
      if (raw !== undefined && !found.some((f) => f.raw.includes(raw))) {
        found.push({ pattern: name, masked: maskSecret(raw), raw });
      }
    }
  }

  return found;
}
