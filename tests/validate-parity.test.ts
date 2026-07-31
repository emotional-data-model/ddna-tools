/**
 * Validator parity tests (session-09 two-validator drift, 2026-07-29).
 *
 * The CLI `validate` command must return the same verdict seal enforces:
 * both now call validateEdmSchemaSync (ajv over the resolved profile
 * schema). These tests prove seal-iff-validate on one artifact set,
 * covering the three drift classes the legacy heuristic missed:
 *   1. minItems (gravity.resilience_markers: [])
 *   2. additionalProperties (unknown top-level domain)
 *   3. per-profile required domains (missing telemetry)
 * plus the conformant control (resilience_markers: null / populated).
 */

import { describe, it, expect } from 'vitest';

import { validateEdmSchemaSync } from '../src/lib/validate-schema.js';
import { validate as legacyHeuristicValidate } from '../src/lib/validate.js';
import { seal, SchemaValidationError } from '../src/lib/seal.js';
import { keygen } from '../src/lib/keygen.js';

/** Minimal full-profile v0.8.3 artifact that passes the bundled schema. */
function validFullArtifact(): Record<string, unknown> {
  return {
    meta: {
      version: '0.8.3',
      profile: 'full',
      created_at: '2026-03-11T10:00:00.000Z',
      visibility: 'shared',
      pii_tier: 'moderate',
      source_type: 'text',
      consent_basis: 'consent',
    },
    core: {
      anchor: 'wedding day',
      spark: 'anniversary photo',
      wound: 'time passing',
      fuel: 'deep love',
      bridge: 'renewal',
      echo: 'wedding music',
      narrative:
        'Looking at wedding photos on our anniversary, feeling the passage of time.',
    },
    constellation: {
      emotion_primary: 'joy',
      emotion_subtone: ['grateful', 'tender'],
      narrative_arc: 'connection',
    },
    milky_way: {
      event_type: 'anniversary celebration',
      location_context: 'home',
      associated_people: ['spouse'],
    },
    gravity: {
      emotional_weight: 0.9,
      valence: 'positive',
      tether_type: 'person',
      recurrence_pattern: 'cyclical',
      strength_score: 0.95,
    },
    impulse: {
      primary_energy: 'love',
      drive_state: 'approach',
      motivational_orientation: 'belonging',
      temporal_focus: 'present',
      directionality: 'outward',
      social_visibility: 'relational',
      urgency: 'calm',
      risk_posture: 'balanced',
      agency_level: 'high',
      regulation_state: 'regulated',
      attachment_style: 'secure',
      coping_style: 'reframe_meaning',
    },
    governance: {
      jurisdiction: 'GDPR',
      retention_policy: { basis: 'user_defined', ttl_days: null, on_expiry: null },
      subject_rights: { portable: true, erasable: true, explainable: true },
      exportability: 'allowed',
    },
    telemetry: {
      entry_confidence: 0.95,
      extraction_model: 'claude-3-5-sonnet',
      extraction_provider: 'anthropic',
    },
    system: { embeddings: null, indices: null },
    crosswalks: {
      plutchik_primary: 'joy',
      geneva_emotion_wheel: null,
      DSM5_specifiers: null,
      ISO_27557_labels: null,
    },
  };
}

/** Seal verdict as a boolean, for parity comparison with the validator. */
async function sealAccepts(artifact: unknown): Promise<boolean> {
  const keys = keygen();
  try {
    await seal(artifact as never, keys.privateKey, keys.did);
    return true;
  } catch (error) {
    if (error instanceof SchemaValidationError) return false;
    throw error;
  }
}

describe('validator parity with seal (session-09 drift classes)', () => {
  it('control: valid full artifact — validator VALID and seal accepts', async () => {
    const artifact = validFullArtifact();
    expect(validateEdmSchemaSync(artifact).valid).toBe(true);
    expect(await sealAccepts(artifact)).toBe(true);
  });

  it('control: resilience_markers null (conformant "none") — both accept', async () => {
    const artifact = validFullArtifact();
    (artifact.gravity as Record<string, unknown>).resilience_markers = null;
    expect(validateEdmSchemaSync(artifact).valid).toBe(true);
    expect(await sealAccepts(artifact)).toBe(true);
  });

  it('drift class 1 (minItems): resilience_markers [] — both reject', async () => {
    const artifact = validFullArtifact();
    (artifact.gravity as Record<string, unknown>).resilience_markers = [];
    const result = validateEdmSchemaSync(artifact);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.keyword === 'minItems')).toBe(true);
    expect(await sealAccepts(artifact)).toBe(false);
  });

  it('drift class 2 (additionalProperties): unknown top-level domain — both reject', async () => {
    const artifact = validFullArtifact();
    artifact.not_a_domain = { anything: 1 };
    const result = validateEdmSchemaSync(artifact);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.keyword === 'additionalProperties')).toBe(true);
    expect(await sealAccepts(artifact)).toBe(false);
  });

  it('drift class 3 (required domains): missing telemetry — both reject', async () => {
    const artifact = validFullArtifact();
    delete artifact.telemetry;
    const result = validateEdmSchemaSync(artifact);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.keyword === 'required')).toBe(true);
    expect(await sealAccepts(artifact)).toBe(false);
  });

  it('documents the legacy drift: heuristic validate() passes all three drift classes', () => {
    // This is WHY the CLI switched validators. The legacy heuristic stays
    // exported for enum-level feedback but must never gate a seal claim.
    const emptyMarkers = validFullArtifact();
    (emptyMarkers.gravity as Record<string, unknown>).resilience_markers = [];
    expect(legacyHeuristicValidate(emptyMarkers).valid).toBe(true);

    const unknownDomain = validFullArtifact();
    unknownDomain.not_a_domain = { anything: 1 };
    expect(legacyHeuristicValidate(unknownDomain).valid).toBe(true);

    const missingDomain = validFullArtifact();
    delete missingDomain.telemetry;
    expect(legacyHeuristicValidate(missingDomain).valid).toBe(true);
  });
});
