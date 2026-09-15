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
  timestamp: z.string(),
  summary: z.object({
    totalFindings: z.number(),
    bySeverity: z.record(SeveritySchema, z.number()),
    score: z.number(),
    band: z.enum(['A', 'B', 'C', 'D', 'F']),
  }),
  findings: z.array(FindingSchema),
  inspected: z.array(InspectedEntrySchema),
  skipped: z.array(SkippedEntrySchema),
});
export type ScanReport = z.infer<typeof ScanReportSchema>;
