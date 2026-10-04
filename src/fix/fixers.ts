import { readFileSync } from 'node:fs';
import { chapInj004AutoExecuteFromMessages } from '../checks/injection/chapInj004AutoExecuteFromMessages.js';
import { chapNet001GatewayExposed } from '../checks/network/chapNet001GatewayExposed.js';
import { chapObs004MemoryStoreExposed } from '../checks/observability/chapObs004MemoryStoreExposed.js';
import { chapSec002GitTrackedSecrets } from '../checks/secrets/chapSec002GitTrackedSecrets.js';
import { chapSec003PermissiveFilePermissions } from '../checks/secrets/chapSec003PermissiveFilePermissions.js';
import { chapSec006SidecarSecretFileExposed } from '../checks/secrets/chapSec006SidecarSecretFileExposed.js';
import { chapSec008WritableByOthers } from '../checks/secrets/chapSec008WritableByOthers.js';
import { findConfigKey, isRecord } from '../discovery/jsonUtils.js';
import type { AgentModel } from '../model/types.js';
import { setConfigValues } from './configEdit.js';
import { gitignoreAction } from './gitignore.js';
import type { FixAction, FixChange, FixPlan, Fixer } from './types.js';

// Fixers beyond CHAP-SEC-001 (PROPOSED_FIXES.md 5). Each runs its own
// check against the model to decide what to fix, so a fixer can never
// propose a change for something the scan wouldn't report.

function octal(mode: number): string {
  return mode.toString(8).padStart(3, '0');
}

function modeOf(model: AgentModel, filePath: string): number | null {
  return model.permissions.find((p) => p.path === filePath)?.mode ?? null;
}

function plan(
  checkId: string,
  entries: Array<{ action: FixAction; change: FixChange }>,
  notes: string[] = [],
): FixPlan | null {
  return entries.length === 0
    ? null
    : {
        checkId,
        actions: entries.map((e) => e.action),
        changes: entries.map((e) => e.change),
        notes,
      };
}

function chmodEntry(
  model: AgentModel,
  filePath: string,
  mode: number,
): { action: FixAction; change: FixChange } {
  const current = modeOf(model, filePath);
  return {
    action: { kind: 'chmod', filePath, mode },
    change: {
      keyPath: filePath,
      oldDisplayValue: current === null ? 'mode unknown' : `mode ${octal(current)}`,
      newValue: `mode ${octal(mode)}`,
    },
  };
}

/** The actual key path for a snake_case path, in whatever spelling the config uses; null when absent. */
function actualKeyPath(model: AgentModel, snakePath: readonly string[]): string | null {
  let node: unknown = model.config.data;
  const actual: string[] = [];
  for (const segment of snakePath) {
    if (!isRecord(node)) {
      return null;
    }
    const key = findConfigKey(node, segment);
    if (key === undefined) {
      return null;
    }
    actual.push(key);
    node = node[key];
  }
  return actual.join('.');
}

function configValueFixer(
  checkId: string,
  hasFinding: (model: AgentModel) => boolean,
  snakePath: readonly string[],
  value: string | boolean,
  describeOld: (model: AgentModel) => string,
): Fixer {
  return {
    checkId,
    plan(model) {
      const { path: filePath, format } = model.config;
      const keyPath = actualKeyPath(model, snakePath);
      if (filePath === null || format === null || keyPath === null || !hasFinding(model)) {
        return null;
      }
      const content = setConfigValues(readFileSync(filePath, 'utf8'), format, [{ keyPath, value }]);
      return {
        checkId,
        changes: [
          { keyPath, oldDisplayValue: describeOld(model), newValue: JSON.stringify(value) },
        ],
        actions: [{ kind: 'write-file', filePath, content }],
        notes: [],
      };
    },
  };
}

export const chapSec002Fixer: Fixer = {
  checkId: 'CHAP-SEC-002',
  plan(model) {
    const finding = chapSec002GitTrackedSecrets.run(model)[0];
    const entry =
      finding === undefined || model.config.path === null
        ? null
        : gitignoreAction(model, model.config.path, false);
    return plan('CHAP-SEC-002', entry === null ? [] : [entry], [
      'If the file was already committed, `git rm --cached` it and rotate the secrets it held: .gitignore only affects untracked files.',
    ]);
  },
};

export const chapSec003Fixer: Fixer = {
  checkId: 'CHAP-SEC-003',
  plan(model) {
    const finding = chapSec003PermissiveFilePermissions.run(model)[0];
    return plan(
      'CHAP-SEC-003',
      finding === undefined || model.config.path === null
        ? []
        : [chmodEntry(model, model.config.path, 0o600)],
    );
  },
};

export const chapSec006Fixer: Fixer = {
  checkId: 'CHAP-SEC-006',
  plan(model) {
    const entries = chapSec006SidecarSecretFileExposed.run(model).flatMap((finding) => {
      const file = finding.location.filePath;
      if (file === null) {
        return [];
      }
      const result: Array<{ action: FixAction; change: FixChange }> = [];
      if (finding.message.includes('git repository')) {
        const entry = gitignoreAction(model, file, false);
        if (entry !== null) {
          result.push(entry);
        }
      }
      if (finding.message.includes('readable by group or other')) {
        result.push(chmodEntry(model, file, 0o600));
      }
      return result;
    });
    return plan('CHAP-SEC-006', entries);
  },
};

export const chapSec008Fixer: Fixer = {
  checkId: 'CHAP-SEC-008',
  plan(model) {
    const entries = chapSec008WritableByOthers.run(model).flatMap((finding) => {
      const file = finding.location.filePath;
      const current = file === null ? null : modeOf(model, file);
      return file === null || current === null ? [] : [chmodEntry(model, file, current & ~0o022)];
    });
    return plan('CHAP-SEC-008', entries);
  },
};

export const chapObs004Fixer: Fixer = {
  checkId: 'CHAP-OBS-004',
  plan(model) {
    const finding = chapObs004MemoryStoreExposed.run(model)[0];
    const dir = model.memory.dir;
    if (finding === undefined || dir === null) {
      return null;
    }
    const entries: Array<{ action: FixAction; change: FixChange }> = [];
    if (finding.message.includes('readable by group or other')) {
      entries.push(chmodEntry(model, dir, 0o700));
    }
    if (finding.message.includes('git repository')) {
      const entry = gitignoreAction(model, dir, true);
      if (entry !== null) {
        entries.push(entry);
      }
    }
    return plan('CHAP-OBS-004', entries);
  },
};

export const chapNet001Fixer = configValueFixer(
  'CHAP-NET-001',
  (model) => chapNet001GatewayExposed.run(model).some((f) => f.severity === 'critical'),
  ['gateway', 'host'],
  '127.0.0.1',
  (model) => JSON.stringify(model.gateway.bindHost),
);

export const chapInj004Fixer = configValueFixer(
  'CHAP-INJ-004',
  (model) => chapInj004AutoExecuteFromMessages.run(model).length > 0,
  ['trust', 'auto_execute_links'],
  false,
  () => 'true',
);
