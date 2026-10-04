import path from 'node:path';
import type { MemoryModel } from '../model/types.js';
import { getConfigField, isRecord } from './jsonUtils.js';
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
  const memoryDir = getConfigField(rawConfig, 'memory_dir');
  const stateDir = getConfigField(rawConfig, 'state_dir');
  const raw =
    typeof memoryDir === 'string' ? memoryDir : typeof stateDir === 'string' ? stateDir : null;
  if (raw === null) {
    return EMPTY_MEMORY;
  }
  return { present: true, dir: path.resolve(targetRoot, expandHome(raw)) };
}
