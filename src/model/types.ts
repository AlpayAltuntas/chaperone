import { z } from 'zod';

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const CheckCategorySchema = z.enum([
  'secrets',
  'agency',
  'supply-chain',
  'injection',
  'network',
  'observability',
]);
export type CheckCategory = z.infer<typeof CheckCategorySchema>;

export const InspectedKindSchema = z.enum([
  'config',
  'gitignore',
  'skill-manifest',
  'skill-source',
  'skill-install-script',
  'skill-lockfile',
  'log-file',
  'other',
]);
export type InspectedKind = z.infer<typeof InspectedKindSchema>;

export const InspectedEntrySchema = z.object({
  path: z.string(),
  kind: InspectedKindSchema,
});
export type InspectedEntry = z.infer<typeof InspectedEntrySchema>;

export const SkippedEntrySchema = z.object({
  path: z.string(),
  reason: z.string(),
});
export type SkippedEntry = z.infer<typeof SkippedEntrySchema>;

// A JSON-like value tree. Config files are parsed into this shape regardless
// of source format (YAML or JSON) so the rest of the model never needs to
// know which parser produced it.
export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema),
  ]),
);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// A field whose key name looks secret-bearing (api_key, token, password, ...).
// `displayValue` is what's safe to show in reports and the parsed `data`
// tree: the masked literal when it was a literal secret, or the value
// verbatim when it was already an indirect reference (e.g. `${VAR}`,
// `env:VAR`) and therefore not sensitive. The real literal value is never
// retained anywhere in the model.
export const SecretFieldSchema = z.object({
  keyPath: z.string(),
  displayValue: z.string(),
  looksLikeEnvReference: z.boolean(),
  // 1-indexed source line (improvement_plan.md 1.17), for YAML and JSON
  // configs alike via YAML.parseDocument (PROPOSED_FIXES.md 4.2). null
  // when the key path can't be located (e.g. a sidecar file).
  line: z.number().nullable(),
  // How the field was recognized (PROPOSED_FIXES.md 3.1): its key name
  // (`api_key`), or its value alone (a `ghp_…` token under `github`).
  detectedBy: z.enum(['key-name', 'value-pattern']),
  // The value pattern that matched (e.g. "GitHub token"), if any. Set for
  // every value-pattern field, and for a key-name field whose value also
  // matches one.
  pattern: z.string().nullable(),
});
export type SecretField = z.infer<typeof SecretFieldSchema>;

export const ConfigModelSchema = z.object({
  path: z.string().nullable(),
  format: z.enum(['yaml', 'json']).nullable(),
  data: JsonValueSchema.nullable(),
  secretFields: z.array(SecretFieldSchema),
  // keyPath (as maskConfig writes it) -> 1-indexed source line, for YAML
  // and JSON configs alike. Used to point config findings at their line.
  keyLines: z.record(z.string(), z.number()),
});
export type ConfigModel = z.infer<typeof ConfigModelSchema>;

// ---------------------------------------------------------------------------
// Sidecar secret files (feeds CHAP-SEC-006) — .env/secrets.yaml/
// secrets.json discovered alongside the main config, fed through the same
// masking pipeline configParser.ts already applies to config.yaml.
// ---------------------------------------------------------------------------

export const SidecarSecretFileSchema = z.object({
  path: z.string(),
  format: z.enum(['dotenv', 'yaml', 'json', 'ini', 'netrc', 'key']),
  secretFields: z.array(SecretFieldSchema),
});
export type SidecarSecretFile = z.infer<typeof SidecarSecretFileSchema>;

// ---------------------------------------------------------------------------
// Persistent memory/state (feeds CHAP-OBS-004) — instruction.md §2's fifth
// discoverable artifact. Mirrors skills_dir's config-field pattern: a
// memory_dir/state_dir path is resolved, existence/permissions checked, no
// content ever read (memory can hold arbitrary conversational history).
// ---------------------------------------------------------------------------

export const MemoryModelSchema = z.object({
  present: z.boolean(),
  dir: z.string().nullable(),
});
export type MemoryModel = z.infer<typeof MemoryModelSchema>;

// ---------------------------------------------------------------------------
// Git context (feeds CHAP-SEC-002)
// ---------------------------------------------------------------------------

// Discovery only ever reads: whether an ancestor `.git` directory exists,
// and the raw lines of a `.gitignore` at that repo root, per the read
// boundary in instruction.md §8. Matching those patterns against the config
// path is check logic (pure, no I/O), left to CHAP-SEC-002 in a later phase.
// One `.gitignore` file's raw lines, plus the directory it lives in
// (relative to the git root, '' for the root's own .gitignore) — feeds
// checks/shared/gitignoreMatch.ts's nested-.gitignore support
// (improvement_plan.md 1.14). Patterns are the file's raw, unprocessed
// lines; scoping a nested file's patterns to its own directory is pure
// logic with no I/O, so it stays in the check-side matcher, same "I/O in
// discovery, logic in checks" split CHAP-SEC-002 already established.
export const GitignoreFileSchema = z.object({
  dirRelativeToRoot: z.string(),
  patterns: z.array(z.string()),
});
export type GitignoreFile = z.infer<typeof GitignoreFileSchema>;

export const GitContextSchema = z.object({
  hasAncestorGitDir: z.boolean(),
  gitDirPath: z.string().nullable(),
  gitRootPath: z.string().nullable(),
  // Every `.gitignore` found from the git root down to the scanned
  // target root (inclusive of both ends) — not just the root one. See
  // gitContext.ts for exactly how deep this walk goes.
  gitignoreFiles: z.array(GitignoreFileSchema),
  configPathRelativeToGitRoot: z.string().nullable(),
});
export type GitContext = z.infer<typeof GitContextSchema>;

// ---------------------------------------------------------------------------
// File permissions (feeds CHAP-SEC-003)
// ---------------------------------------------------------------------------

// What a permission fact is about, so a check can pick the paths it
// cares about (CHAP-SEC-008 looks at everything that controls what the
// agent runs; CHAP-SEC-003 only at the config file).
export const PermissionRoleSchema = z.enum([
  'config',
  'log',
  'memory-dir',
  'sidecar',
  'target-root',
  'skills-dir',
  'skill-dir',
]);
export type PermissionRole = z.infer<typeof PermissionRoleSchema>;

export const FilePermissionFactSchema = z.object({
  path: z.string(),
  role: PermissionRoleSchema,
  exists: z.boolean(),
  mode: z.number().nullable(),
  isDirectory: z.boolean(),
  // null when the path doesn't exist, or on Windows, where POSIX mode
  // bits don't reflect real access control (the reported mode is
  // synthesized from the read-only attribute).
  groupOrOtherReadable: z.boolean().nullable(),
  groupOrOtherWritable: z.boolean().nullable(),
});
export type FilePermissionFact = z.infer<typeof FilePermissionFactSchema>;

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

// Where a capability was seen (PROPOSED_FIXES.md 4.2): the file, the
// 1-indexed line (null when only a pattern pre-pass ran), and the API
// name (`child_process.execSync`, `fetch`, `deleteFile`). Never a source
// snippet.
export const CapabilityEvidenceSchema = z.object({
  capability: z.enum([
    'shellExec',
    'fileSystemAccess',
    'networkAccess',
    'dynamicEval',
    'destructive',
  ]),
  file: z.string(),
  line: z.number().nullable(),
  api: z.string(),
  // fileSystemAccess only: whether this write's path is scoped to the
  // skill's own directory or a fixed base (PROPOSED_FIXES.md 2.6).
  scoped: z.boolean().optional(),
});
export type CapabilityEvidence = z.infer<typeof CapabilityEvidenceSchema>;

export const SkillCapabilitiesSchema = z.object({
  shellExec: z.boolean(),
  fileSystemAccess: z.boolean(),
  // True when the source shows evidence of scoping file access to a fixed
  // base directory (e.g. `path.join(__dirname, ...)`), the proxy CHAP-AGY-002
  // uses for "no path scoping". Meaningless when fileSystemAccess is false.
  fileSystemScoped: z.boolean(),
  networkAccess: z.boolean(),
  destructiveKeywords: z.array(z.string()),
  // eval()/Function() — CHAP-SUP-005 (improvement_plan.md 2.6).
  dynamicEval: z.boolean(),
  // True when a bounded, intra-file taint analysis traces a network/fs
  // read's result into a shell-exec call's argument — a real (if
  // limited) data-flow signal CHAP-INJ-002 uses to distinguish a
  // confirmed chain from a mere shape-match (improvement_plan.md 1.16).
  dataFlowToShellExec: z.boolean(),
  // Capped per capability (see mergeCapabilities); in source order.
  evidence: z.array(CapabilityEvidenceSchema),
});
export type SkillCapabilities = z.infer<typeof SkillCapabilitiesSchema>;

export const SkillProvenanceSchema = z.object({
  sourceUrl: z.string().nullable(),
  pinnedRef: z.boolean().nullable(),
  author: z.string().nullable(),
});
export type SkillProvenance = z.infer<typeof SkillProvenanceSchema>;

export const SkillDependencyInfoSchema = z.object({
  // Which package ecosystem the manifest belongs to (PROPOSED_FIXES.md
  // 3.4); null when there's no manifest. CHAP-SUP-003/006 only have npm
  // data, so they skip PyPI dependencies.
  ecosystem: z.enum(['npm', 'pypi']).nullable(),
  manifestPath: z.string().nullable(),
  lockfilePath: z.string().nullable(),
  // Declared dependency names (package.json's "dependencies" keys) — feeds
  // CHAP-SUP-006's typosquat-risk check (improvement_plan.md 2.7).
  names: z.array(z.string()),
  // Declared dependency name -> its raw version specifier string from
  // package.json (e.g. "^4.17.15"), not a resolved/installed version —
  // no lockfile parsing, no node_modules inspection. Feeds CHAP-SUP-003's
  // offline vulnerability-database match (improvement_plan.md 1.15/Phase
  // 18).
  versionsByName: z.record(z.string(), z.string()),
});
export type SkillDependencyInfo = z.infer<typeof SkillDependencyInfoSchema>;

export const SkillInstallScriptFindingSchema = z.object({
  path: z.string(),
  dangerousPatterns: z.array(z.string()),
});
export type SkillInstallScriptFinding = z.infer<typeof SkillInstallScriptFindingSchema>;

export const SkillInstallScriptInfoSchema = z.object({
  scripts: z.array(SkillInstallScriptFindingSchema),
});
export type SkillInstallScriptInfo = z.infer<typeof SkillInstallScriptInfoSchema>;

// How an MCP server is launched (PROPOSED_FIXES.md 3.9). Arguments and
// URLs are stored masked (a token passed as an argument never reaches the
// model); env and header blocks keep key names only, never values.
export const SkillLaunchSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('stdio'),
    command: z.string(),
    args: z.array(z.string()),
    envKeys: z.array(z.string()),
  }),
  z.object({
    kind: z.literal('remote'),
    url: z.string(),
    headerKeys: z.array(z.string()),
  }),
]);
export type SkillLaunch = z.infer<typeof SkillLaunchSchema>;

export const SkillSchema = z.object({
  name: z.string(),
  dir: z.string(),
  manifestPath: z.string().nullable(),
  capabilities: SkillCapabilitiesSchema,
  provenance: SkillProvenanceSchema,
  dependencies: SkillDependencyInfoSchema,
  installScripts: SkillInstallScriptInfoSchema,
  // Declared manifest conventions consumed by CHAP-AGY-003/004 (Phase 3).
  // null means "not declared" — a check decides what that means, discovery
  // just reports what it found.
  confirmationRequired: z.boolean().nullable(),
  domainAllowlist: z.array(z.string()).nullable(),
  // Set for an MCP server; null for a skill whose code Chaperone reads.
  launch: SkillLaunchSchema.nullable(),
});
export type Skill = z.infer<typeof SkillSchema>;

// ---------------------------------------------------------------------------
// Containers (feeds CHAP-AGY-005) — a container the agent or one of its
// tools is launched in, from an MCP server's `docker run` arguments or a
// docker-compose service, with any host-level privileges it is granted.
// ---------------------------------------------------------------------------

export const ContainerLaunchSchema = z.object({
  name: z.string(),
  source: z.string(),
  line: z.number().nullable(),
  // e.g. "--privileged", "pid: host", "bind mount of /var/run/docker.sock"
  hostPrivileges: z.array(z.string()),
});
export type ContainerLaunch = z.infer<typeof ContainerLaunchSchema>;

// ---------------------------------------------------------------------------
// Claude Code settings (PROPOSED_FIXES.md 6.1) — one entry per settings
// file read, masked like the main config. `scope` decides which keys take
// effect: `permissions.defaultMode: bypassPermissions` is ignored in
// project/local files by current Claude Code.
// ---------------------------------------------------------------------------

export const ClaudeCodeSettingsFileSchema = z.object({
  path: z.string(),
  scope: z.enum(['user', 'project', 'local']),
  data: JsonValueSchema.nullable(),
  secretFields: z.array(SecretFieldSchema),
  keyLines: z.record(z.string(), z.number()),
});
export type ClaudeCodeSettingsFile = z.infer<typeof ClaudeCodeSettingsFileSchema>;

// ---------------------------------------------------------------------------
// Gateway / network
// ---------------------------------------------------------------------------

export const GatewayModelSchema = z.object({
  present: z.boolean(),
  bindHost: z.string().nullable(),
  port: z.number().nullable(),
  authConfigured: z.boolean().nullable(),
  authTokenIsDefaultOrEmpty: z.boolean().nullable(),
  tlsEnabled: z.boolean().nullable(),
});
export type GatewayModel = z.infer<typeof GatewayModelSchema>;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

// A secret-shaped key=value/key:"value" pair found in *existing* log file
// content (feeds CHAP-SEC-005) — distinct from CHAP-SEC-004/OBS-002, which
// only reason about whether logging config is likely to leak going
// forward. `displayValue` is already masked the same way config secrets
// are (configParser.ts's maskSecretValue); the real value is never
// retained.
export const LoggedSecretMatchSchema = z.object({
  keyName: z.string(),
  displayValue: z.string(),
});
export type LoggedSecretMatch = z.infer<typeof LoggedSecretMatchSchema>;

export const LoggingModelSchema = z.object({
  present: z.boolean(),
  level: z.string().nullable(),
  path: z.string().nullable(),
  redactSecrets: z.boolean().nullable(),
  auditLogEnabled: z.boolean().nullable(),
  existingSecretMatches: z.array(LoggedSecretMatchSchema),
});
export type LoggingModel = z.infer<typeof LoggingModelSchema>;

// ---------------------------------------------------------------------------
// Recoverability (feeds CHAP-OBS-003)
// ---------------------------------------------------------------------------

export const RecoverabilityModelSchema = z.object({
  killSwitchDocumented: z.boolean(),
});
export type RecoverabilityModel = z.infer<typeof RecoverabilityModelSchema>;

// ---------------------------------------------------------------------------
// Top-level AgentModel
// ---------------------------------------------------------------------------

export const AgentModelSchema = z.object({
  targetRoot: z.string(),
  config: ConfigModelSchema,
  sidecarSecretFiles: z.array(SidecarSecretFileSchema),
  git: GitContextSchema,
  permissions: z.array(FilePermissionFactSchema),
  skills: z.array(SkillSchema),
  containers: z.array(ContainerLaunchSchema),
  // Claude Code settings files (`--profile claude-code`); empty otherwise.
  claudeCodeSettings: z.array(ClaudeCodeSettingsFileSchema),
  gateway: GatewayModelSchema,
  logging: LoggingModelSchema,
  memory: MemoryModelSchema,
  recoverability: RecoverabilityModelSchema,
  inspected: z.array(InspectedEntrySchema),
  skipped: z.array(SkippedEntrySchema),
});
export type AgentModel = z.infer<typeof AgentModelSchema>;

// ---------------------------------------------------------------------------
// Finding (produced by the check engine, Phase 2+)
// ---------------------------------------------------------------------------

export const FindingLocationSchema = z.object({
  filePath: z.string().nullable(),
  line: z.number().nullable(),
  detail: z.string().nullable(),
});
export type FindingLocation = z.infer<typeof FindingLocationSchema>;

export const FindingSchema = z.object({
  checkId: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  category: CheckCategorySchema,
  owasp: z.string(),
  message: z.string(),
  location: FindingLocationSchema,
  // Further places the same finding applies to (e.g. every shell-exec
  // call in a skill after the first); emitted as SARIF relatedLocations.
  relatedLocations: z.array(FindingLocationSchema).optional(),
  remediation: z.string(),
});
export type Finding = z.infer<typeof FindingSchema>;
