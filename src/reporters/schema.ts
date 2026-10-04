import { z } from 'zod';
import {
  FindingSchema,
  InspectedEntrySchema,
  SeveritySchema,
  SkippedEntrySchema,
} from '../model/types.js';

/**
 * The JSON reporter's output shape, per instruction.md §9 ("schema-stable,
 * suitable for automation... define and document the schema with zod").
 * `formatJsonReport` validates every report against this before emitting
 * it, so schema-stability is enforced, not just documented.
 */
export const ScanReportSchema = z.object({
  tool: z.object({
    name: z.literal('chaperone'),
    version: z.string(),
  }),
  target: z.string(),
  targetRootResolved: z.boolean(),
  // The discovery profile, and whether it was auto-detected (PROPOSED_FIXES.md 6.3).
  profile: z.object({ name: z.string(), detected: z.boolean() }).optional(),
  advisoryData: z
    .object({
      snapshotDate: z.string(),
      bundledAdvisories: z.number(),
      extraFile: z.string().nullable(),
      extraAdvisories: z.number(),
    })
    .optional(),
  timestamp: z.string(),
  summary: z.object({
    totalFindings: z.number(),
    bySeverity: z.record(SeveritySchema, z.number()),
    score: z.number(),
    band: z.enum(['A', 'B', 'C', 'D', 'F']),
    // Optional so reports written before scoring v2 still load as baselines.
    scoreVersion: z.number().optional(),
  }),
  findings: z.array(FindingSchema),
  inspected: z.array(InspectedEntrySchema),
  skipped: z.array(SkippedEntrySchema),
});
export type ScanReport = z.infer<typeof ScanReportSchema>;
