/**
 * Experiential-stance attribution guard (deterministic layer)
 *
 * Extraction must be able to tell whose story it is: a pasted stranger's
 * story or an assistant-invented anecdote must not be encoded as the
 * subject's own wound, insight, or heaviest grief.
 *
 * Two layers of defence in ddna-tools (mirroring deepadata-edm-sdk 0.8.9):
 * 1. Prompt — extraction prompts require a top-level experiential_stance
 *    classification and forbid encoding non-subject material into subject
 *    significance fields.
 * 2. Deterministic guard (this module) — if the model still returns a
 *    non-subject stance with populated significance fields, those fields
 *    are cleared and weights floored. Free; always on.
 *
 * The SDK's third layer (an LLM classifier pass that re-derives stance) is
 * part of the commercial path and intentionally not ported here; the
 * deterministic guard is the OSS floor.
 *
 * experiential_stance is proposed for EDM v0.9. Until the spec lands it
 * travels in the extraction result only, never in the artifact body, so
 * artifacts stay v0.8.0-conformant.
 */

/**
 * Experiential stance — whose experience the emotionally salient material
 * is, relative to the subject.
 */
export const EXPERIENTIAL_STANCE = [
  'lived',
  'witnessed',
  'quoted_third_party',
  'assistant_generated',
  'hypothetical',
] as const;

export type ExperientialStance = (typeof EXPERIENTIAL_STANCE)[number];

/** Stances whose material must not populate subject significance fields */
const NON_SUBJECT_STANCES: ReadonlySet<ExperientialStance> = new Set([
  'quoted_third_party',
  'assistant_generated',
  'hypothetical',
]);

export function isNonSubjectStance(stance: ExperientialStance | null): boolean {
  return stance !== null && NON_SUBJECT_STANCES.has(stance);
}

function parseStance(value: unknown): ExperientialStance | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase().replace(/[\s-]+/g, '_') as ExperientialStance;
  return (EXPERIENTIAL_STANCE as readonly string[]).includes(normalized) ? normalized : null;
}

/** Read and remove the top-level experiential_stance key from extracted fields */
export function takeStance(extracted: Record<string, unknown>): ExperientialStance | null {
  const stance = parseStance(extracted['experiential_stance']);
  delete extracted['experiential_stance'];
  return stance;
}

/**
 * Deterministic demotion: clear subject-significance fields when the
 * emotionally salient material is not the subject's own experience.
 * Mutates `extracted` in place; returns the list of fields touched.
 *
 * Kept fields (anchor, spark, narrative, milky_way) still describe the
 * content; the cleared set is exactly the fields that assert something
 * about the SUBJECT's inner life. witnessed is a subject stance and is
 * NOT demoted.
 */
export function applyStanceGuard(
  extracted: Record<string, unknown>,
  stance: ExperientialStance | null
): string[] {
  if (!isNonSubjectStance(stance)) return [];

  const cleared: string[] = [];
  const clearString = (domain: string, field: string) => {
    const d = extracted[domain] as Record<string, unknown> | undefined;
    if (d && d[field] != null) {
      d[field] = null;
      cleared.push(`${domain}.${field}`);
    }
  };

  clearString('core', 'wound');
  clearString('constellation', 'identity_thread');
  clearString('constellation', 'expressed_insight');
  clearString('constellation', 'somatic_signature');

  const constellation = extracted['constellation'] as Record<string, unknown> | undefined;
  if (constellation && constellation['transformational_pivot'] === true) {
    constellation['transformational_pivot'] = false;
    cleared.push('constellation.transformational_pivot');
  }

  const gravity = extracted['gravity'] as Record<string, unknown> | undefined;
  if (gravity) {
    for (const field of ['emotional_weight', 'strength_score'] as const) {
      const v = gravity[field];
      if (typeof v === 'number' && v > 0.2) {
        gravity[field] = 0.2;
        cleared.push(`gravity.${field}`);
      }
    }
  }

  // Impulse fields assert the subject's motivational state — for material
  // the subject didn't live, they describe the story's narrator instead.
  const impulse = extracted['impulse'] as Record<string, unknown> | undefined;
  if (impulse) {
    for (const [field, value] of Object.entries(impulse)) {
      if (value != null) {
        impulse[field] = null;
        cleared.push(`impulse.${field}`);
      }
    }
  }

  return cleared;
}

export interface StanceGuardResult {
  /** Stance claimed by the extraction model (consumed from the payload) */
  stance: ExperientialStance | null;
  /** Field paths cleared or floored by the guard */
  fieldsCleared: string[];
  /** Telemetry note describing what happened */
  note: string;
}

/**
 * Consume the experiential_stance key from an extraction payload and apply
 * the deterministic guard. Shared by all three provider extractors so the
 * guard is always on and stance never survives into the extracted fields
 * (and therefore never into an assembled artifact).
 */
export function consumeStance(extracted: Record<string, unknown>): StanceGuardResult {
  const stance = takeStance(extracted);
  const fieldsCleared = applyStanceGuard(extracted, stance);
  const noteParts = [`experiential_stance=${stance ?? 'null'}`];
  if (fieldsCleared.length > 0) {
    noteParts.push(`stance_guard_cleared: ${fieldsCleared.join(', ')}`);
  }
  return { stance, fieldsCleared, note: noteParts.join('; ') };
}
