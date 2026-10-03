import { statSync } from 'node:fs';
import type { FilePermissionFact, PermissionRole } from '../model/types.js';

const GROUP_OR_OTHER_READ = 0o044;
const GROUP_OR_OTHER_WRITE = 0o022;

/**
 * Reads POSIX file-mode facts for a single path. Meaningful on macOS/Linux
 * self-hosted installs (the target environment per instruction.md §2). On
 * Windows the mode Node reports is synthesized from the read-only
 * attribute and says nothing about other users, so readable/writable are
 * reported as unknown (null) there rather than guessed.
 */
export function getFilePermissionFact(
  targetPath: string,
  role: PermissionRole,
  platform: NodeJS.Platform = process.platform,
): FilePermissionFact {
  try {
    const stat = statSync(targetPath);
    const mode = stat.mode & 0o777;
    const posix = platform !== 'win32';
    return {
      path: targetPath,
      role,
      exists: true,
      mode,
      isDirectory: stat.isDirectory(),
      groupOrOtherReadable: posix ? (mode & GROUP_OR_OTHER_READ) !== 0 : null,
      groupOrOtherWritable: posix ? (mode & GROUP_OR_OTHER_WRITE) !== 0 : null,
    };
  } catch {
    return {
      path: targetPath,
      role,
      exists: false,
      mode: null,
      isDirectory: false,
      groupOrOtherReadable: null,
      groupOrOtherWritable: null,
    };
  }
}
