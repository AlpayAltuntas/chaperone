import { statSync } from 'node:fs';
import type { FilePermissionFact } from '../model/types.js';

const GROUP_OR_OTHER_READ = 0o044;
const GROUP_OR_OTHER_WRITE = 0o022;

/**
 * Reads POSIX file-mode facts for a single path. Meaningful on macOS/Linux
 * self-hosted installs (the target environment per instruction.md §2); on
 * platforms without POSIX permission bits the reported mode may not reflect
 * real access control.
 */
export function getFilePermissionFact(targetPath: string): FilePermissionFact {
  try {
    const stat = statSync(targetPath);
    const mode = stat.mode & 0o777;
    return {
      path: targetPath,
      exists: true,
      mode,
      isDirectory: stat.isDirectory(),
      groupOrOtherReadable: (mode & GROUP_OR_OTHER_READ) !== 0,
      groupOrOtherWritable: (mode & GROUP_OR_OTHER_WRITE) !== 0,
    };
  } catch {
    return {
      path: targetPath,
      exists: false,
      mode: null,
      isDirectory: false,
      groupOrOtherReadable: null,
      groupOrOtherWritable: null,
    };
  }
}
