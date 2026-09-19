import { createRequire } from 'node:module';
import path from 'node:path';
import { z } from 'zod';
import { CheckCategorySchema, SeveritySchema } from '../model/types.js';
import type { Check } from './types.js';

// Plugin system (improvement_plan.md 3.13). Explicit trust boundary,
// stated as plainly as the plan itself asks for: a plugin is arbitrary
// code with full access to AgentModel, loaded and EXECUTED — module-load
// side effects run at require() time, then each check's own run(model)
// executes with the same access every built-in check has — with NO
// sandboxing whatsoever. Loading a plugin means trusting it as
// completely as any other dependency you'd `npm install` and run. Only
// ever load a plugin you've read and trust; `--plugin`/`.chaperonerc.json`'s
// `plugins` array are both entirely opt-in — nothing is ever loaded
// without the user naming it explicitly.
//
// Loaded via Node's synchronous `require()` (via createRequire), not a
// dynamic `import()` — deliberately, so `chaperone scan`'s CLI action
// stays fully synchronous (loadPlugins runs before any check runs, no
// different in kind from loading `.chaperonerc.json` itself). This means
// a plugin module must be loadable as CommonJS: a `.cjs` file works
// regardless of context; a `.js` file works only where the nearest
// package.json says `"type": "commonjs"` (or has no `type` field at
// all). A genuine ESM-only plugin isn't supported in this v1 — a
// documented scope decision, not an oversight; see DECISIONS.md, Phase
// 21.

const require = createRequire(import.meta.url);

const CheckShapeSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  severity: SeveritySchema,
  category: CheckCategorySchema,
  owasp: z.string().min(1),
  detects: z.string().min(1),
  heuristic: z.string().min(1),
  remediation: z.string().min(1),
  severityNote: z.string().optional(),
});

function isValidCheck(value: unknown): value is Check {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  if (typeof (value as { run?: unknown }).run !== 'function') {
    return false;
  }
  return CheckShapeSchema.safeParse(value).success;
}

export interface LoadedPlugin {
  path: string;
  checks: Check[];
}

/**
 * Loads one plugin module and validates its exported checks. A plugin's
 * default export must be either a single `Check`-shaped object or an
 * array of them (mirroring how `ALL_CHECKS` is itself just an array) —
 * any other shape, or any check missing a required field, is a load
 * error, not a silently-skipped entry, since a plugin the user asked for
 * failing to load is worth stopping the scan over.
 */
export function loadPlugin(pluginPath: string): LoadedPlugin {
  const resolved = path.resolve(pluginPath);
  let moduleExports: unknown;
  try {
    moduleExports = require(resolved) as unknown;
  } catch (err) {
    throw new Error(
      `could not load plugin '${pluginPath}': ${err instanceof Error ? err.message : String(err)}`,
      {
        cause: err,
      },
    );
  }

  const defaultExport =
    typeof moduleExports === 'object' && moduleExports !== null && 'default' in moduleExports
      ? moduleExports.default
      : moduleExports;
  const candidates = Array.isArray(defaultExport) ? defaultExport : [defaultExport];

  const checks: Check[] = [];
  for (const candidate of candidates) {
    if (!isValidCheck(candidate)) {
      throw new Error(
        `plugin '${pluginPath}' does not export a valid Check (or Check[]) — expected an object (or array of objects) with id/title/severity/category/owasp/detects/heuristic/remediation and a run(model) function`,
      );
    }
    checks.push(candidate);
  }
  if (checks.length === 0) {
    throw new Error(`plugin '${pluginPath}' exported no checks`);
  }
  return { path: pluginPath, checks };
}

/** Loads every plugin in order, returning their combined checks flattened into one array. */
export function loadPlugins(pluginPaths: readonly string[]): Check[] {
  return pluginPaths.flatMap((pluginPath) => loadPlugin(pluginPath).checks);
}

/**
 * Combines built-in and plugin checks into one list, refusing a check-ID
 * collision — a plugin silently shadowing a built-in check (or another
 * plugin's check) would be a confusing way to lose a real finding.
 */
export function mergeChecks(builtIn: readonly Check[], pluginChecks: readonly Check[]): Check[] {
  const owner = new Map<string, string>();
  for (const check of builtIn) {
    owner.set(check.id, 'a built-in check');
  }
  for (const check of pluginChecks) {
    const existing = owner.get(check.id);
    if (existing !== undefined) {
      throw new Error(
        `plugin check ID '${check.id}' collides with ${existing} — plugin check IDs must be unique`,
      );
    }
    owner.set(check.id, 'another plugin check');
  }
  return [...builtIn, ...pluginChecks];
}
