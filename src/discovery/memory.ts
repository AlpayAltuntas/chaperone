import path from 'node:path';
import type { MemoryModel } from '../model/types.js';
import { isRecord } from './jsonUtils.js';
import { expandHome } from './pathUtils.js';

const EMPTY_MEMORY: MemoryModel = { present: false, dir: null };

/**
 * Projects a `memory_dir`/`state_dir` config field into a resolved
 * absolute path, mirroring `skills_dir`'s existing pattern
 * (discovery/index.ts). Closes the gap noted in improvement_plan.md 1.7:
 * instruction.md §2 lists persistent memory/state as one of five
 * discoverable artifacts, but no AgentModel field for it existed before
 * this.
 */
export function extractMemoryModel(rawConfig: unknown, targetRoot: string): MemoryModel {
  if (!isRecord(rawConfig)) {
    return EMPTY_MEMORY;
  }
  const raw =
    typeof rawConfig['memory_dir'] === 'string'
      ? rawConfig['memory_dir']
      : typeof rawConfig['state_dir'] === 'string'
        ? rawConfig['state_dir']
        : null;
  if (raw === null) {
    return EMPTY_MEMORY;
  }
  return { present: true, dir: path.resolve(targetRoot, expandHome(raw)) };
}
