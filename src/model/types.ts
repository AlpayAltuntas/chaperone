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
});
export type SecretField = z.infer<typeof SecretFieldSchema>;

export const ConfigModelSchema = z.object({
  path: z.string().nullable(),
  format: z.enum(['yaml', 'json']).nullable(),
  data: JsonValueSchema.nullable(),
  secretFields: z.array(SecretFieldSchema),
});
export type ConfigModel = z.infer<typeof ConfigModelSchema>;

// ---------------------------------------------------------------------------
// Sidecar secret files (feeds CHAP-SEC-006) — .env/secrets.yaml/
// secrets.json discovered alongside the main config, fed through the same
// masking pipeline configParser.ts already applies to config.yaml.
// ---------------------------------------------------------------------------

export const SidecarSecretFileSchema = z.object({
  path: z.string(),
  format: z.enum(['dotenv', 'yaml', 'json']),
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
export const GitContextSchema = z.object({
  hasAncestorGitDir: z.boolean(),
  gitDirPath: z.string().nullable(),
  gitRootPath: z.string().nullable(),
  gitignorePatterns: z.array(z.string()),
  configPathRelativeToGitRoot: z.string().nullable(),
});
export type GitContext = z.infer<typeof GitContextSchema>;

// ---------------------------------------------------------------------------
// File permissions (feeds CHAP-SEC-003)
// ---------------------------------------------------------------------------

export const FilePermissionFactSchema = z.object({
  path: z.string(),
  exists: z.boolean(),
  mode: z.number().nullable(),
  isDirectory: z.boolean(),
  groupOrOtherReadable: z.boolean().nullable(),
  groupOrOtherWritable: z.boolean().nullable(),
});
export type FilePermissionFact = z.infer<typeof FilePermissionFactSchema>;

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

export const SkillCapabilitiesSchema = z.object({
  shellExec: z.boolean(),
  fileSystemAccess: z.boolean(),
  // True when the source shows evidence of scoping file access to a fixed
  // base directory (e.g. `path.join(__dirname, ...)`), the proxy CHAP-AGY-002
  // uses for "no path scoping". Meaningless when fileSystemAccess is false.
  fileSystemScoped: z.boolean(),
  networkAccess: z.boolean(),
  destructiveKeywords: z.array(z.string()),
});
export type SkillCapabilities = z.infer<typeof SkillCapabilitiesSchema>;

export const SkillProvenanceSchema = z.object({
  sourceUrl: z.string().nullable(),
  pinnedRef: z.boolean().nullable(),
  author: z.string().nullable(),
});
export type SkillProvenance = z.infer<typeof SkillProvenanceSchema>;

export const SkillDependencyInfoSchema = z.object({
  manifestPath: z.string().nullable(),
  lockfilePath: z.string().nullable(),
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
});
export type Skill = z.infer<typeof SkillSchema>;

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
  remediation: z.string(),
});
export type Finding = z.infer<typeof FindingSchema>;
