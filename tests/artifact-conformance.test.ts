/**
 * Executable conformance guarantee for the extraction-parity release:
 *
 * (a) Artifacts assembled from extraction results contain NO
 *     experiential_stance key anywhere — stance is consumed by the
 *     attribution guard and travels in the extraction result (and, for
 *     the full profile, telemetry notes) only.
 * (b) Assembled artifacts validate against the bundled EDM v0.8.0 schemas
 *     (which carry the nullable-enum conformance fix).
 *
 * LLM calls are faked; everything downstream of the model response is the
 * real production path (parse -> guard -> assembly -> Ajv).
 */

import { describe, it, expect } from 'vitest';
import type OpenAI from 'openai';

import { extractWithKimi, assembleProfileArtifact } from '../src/extractors/index.js';
import type { EdmProfile } from '../src/extractors/types.js';
import { validateEdmSchemaSync } from '../src/lib/validate-schema.js';

// ============================================================================
// Helpers
// ============================================================================

function findKeyDeep(obj: unknown, key: string, path = '$'): string[] {
  if (typeof obj !== 'object' || obj === null) return [];
  const hits: string[] = [];
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (k === key) hits.push(`${path}.${k}`);
    hits.push(...findKeyDeep(v, key, `${path}.${k}`));
  }
  return hits;
}

const fakeClient = (payload: unknown): OpenAI =>
  ({
    chat: {
      completions: {
        create: async () => ({
          choices: [{ message: { content: JSON.stringify(payload) } }],
        }),
      },
    },
  }) as unknown as OpenAI;

/** Full production path downstream of the model response */
async function extractAndAssemble(
  profile: EdmProfile,
  payload: Record<string, unknown>
): Promise<{ artifact: Record<string, Record<string, unknown>>; result: Awaited<ReturnType<typeof extractWithKimi>> }> {
  const result = await extractWithKimi(fakeClient(payload), { text: 'USER: here is a story...' }, 'test-model', profile);
  const artifact = assembleProfileArtifact(
    result.extracted as unknown as Record<string, unknown>,
    { consentBasis: 'consent', visibility: 'private', piiTier: 'moderate' },
    {
      confidence: result.confidence,
      model: result.model,
      profile: result.profile,
      provider: 'kimi',
      notes: result.notes,
      hasText: true,
      hasImage: false,
    }
  ) as Record<string, Record<string, unknown>>;
  return { artifact, result };
}

// ============================================================================
// Profile-shaped extraction payloads (stance-bearing)
// ============================================================================

const essentialExtraction = (stance: string | null): Record<string, unknown> => ({
  experiential_stance: stance,
  core: {
    anchor: 'a pasted story',
    spark: 'a request',
    wound: 'her loss',
    fuel: null,
    bridge: null,
    echo: 'the last line',
  },
  constellation: {
    emotion_primary: 'sadness',
    emotion_subtone: ['heavy'],
    narrative_arc: 'loss',
  },
});

const extendedExtraction = (stance: string | null): Record<string, unknown> => ({
  experiential_stance: stance,
  core: {
    anchor: 'a pasted story',
    spark: 'a request',
    wound: 'her loss',
    fuel: null,
    bridge: null,
    echo: 'the last line',
    narrative:
      'On a winter evening the subject pasted a story. The smell of coffee hung in the air. Years later it still echoes.',
  },
  constellation: {
    emotion_primary: 'sadness',
    emotion_subtone: ['heavy'],
    higher_order_emotion: null,
    meta_emotional_state: null,
    interpersonal_affect: null,
    narrative_arc: 'loss',
    relational_dynamics: 'grief',
    temporal_context: null,
    memory_type: null,
    media_format: 'text',
    narrative_archetype: null,
    symbolic_anchor: null,
    relational_perspective: 'self',
    temporal_rhythm: null,
    identity_thread: 'the storyteller',
    expressed_insight: 'grief travels',
    transformational_pivot: true,
    somatic_signature: 'tight chest',
    arc_type: 'grief',
  },
  milky_way: {
    event_type: null,
    location_context: null,
    associated_people: [],
    visibility_context: 'private',
    tone_shift: null,
  },
  gravity: {
    emotional_weight: 0.9,
    valence: 'negative',
    tether_type: 'person',
    recurrence_pattern: null,
    strength_score: 0.8,
  },
});

const fullExtraction = (stance: string | null): Record<string, unknown> => ({
  ...extendedExtraction(stance),
  gravity: {
    emotional_weight: 0.9,
    emotional_density: 'high',
    valence: 'negative',
    viscosity: 'enduring',
    gravity_type: null,
    tether_type: 'person',
    recall_triggers: ['rain'],
    retrieval_keys: ['story'],
    nearby_themes: [],
    recurrence_pattern: null,
    strength_score: 0.8,
    temporal_decay: 'slow',
    resilience_markers: null,
    adaptation_trajectory: null,
  },
  impulse: {
    primary_energy: 'compassion',
    drive_state: 'process',
    motivational_orientation: 'meaning',
    temporal_focus: 'past',
    directionality: 'inward',
    social_visibility: 'private',
    urgency: 'calm',
    risk_posture: null,
    agency_level: 'medium',
    regulation_state: 'regulated',
    attachment_style: null,
    coping_style: 'process',
  },
});

const PAYLOADS: Record<EdmProfile, (stance: string | null) => Record<string, unknown>> = {
  essential: essentialExtraction,
  extended: extendedExtraction,
  full: fullExtraction,
};

const ALL_STANCES = [
  'lived',
  'witnessed',
  'quoted_third_party',
  'assistant_generated',
  'hypothetical',
  null,
];

// ============================================================================
// Conformance: no stance leakage, bundled v0.8.0 schema validity
// ============================================================================

describe('artifact conformance (no stance leakage, bundled v0.8.0 schemas)', () => {
  it.each(['essential', 'extended', 'full'] as EdmProfile[])(
    '%s: artifacts validate and contain no experiential_stance key for any stance',
    async (profile) => {
      for (const stance of ALL_STANCES) {
        const { artifact } = await extractAndAssemble(profile, PAYLOADS[profile](stance));

        expect(findKeyDeep(artifact, 'experiential_stance')).toEqual([]);

        const validation = validateEdmSchemaSync(artifact);
        if (!validation.valid) {
          console.error(profile, stance, JSON.stringify(validation.errors, null, 2));
        }
        expect(validation.valid).toBe(true);
        expect(validation.profile).toBe(profile);
      }
    }
  );

  it('guard demotions produce explicit nulls, not omissions, and stay schema-valid', async () => {
    const { artifact } = await extractAndAssemble('extended', extendedExtraction('assistant_generated'));

    expect('wound' in artifact.core!).toBe(true);
    expect(artifact.core!.wound).toBeNull();
    expect(artifact.constellation!.identity_thread).toBeNull();
    expect(artifact.constellation!.expressed_insight).toBeNull();
    expect(artifact.constellation!.somatic_signature).toBeNull();
    expect(artifact.constellation!.transformational_pivot).toBe(false);
    expect(artifact.gravity!.emotional_weight).toBe(0.2);
    expect(artifact.gravity!.strength_score).toBe(0.2);

    expect(validateEdmSchemaSync(artifact).valid).toBe(true);
  });

  it('full profile: impulse domain nulled on non-subject stance, stance recorded in telemetry notes only', async () => {
    const { artifact } = await extractAndAssemble('full', fullExtraction('quoted_third_party'));

    for (const value of Object.values(artifact.impulse!)) {
      expect(value).toBeNull();
    }
    expect(findKeyDeep(artifact, 'experiential_stance')).toEqual([]);
    expect(artifact.telemetry!.extraction_notes).toContain(
      'experiential_stance=quoted_third_party'
    );
    expect(validateEdmSchemaSync(artifact).valid).toBe(true);
  });

  it('witnessed is NOT demoted in any profile', async () => {
    for (const profile of ['essential', 'extended', 'full'] as EdmProfile[]) {
      const { artifact, result } = await extractAndAssemble(profile, PAYLOADS[profile]('witnessed'));
      expect(artifact.core!.wound).toBe('her loss');
      if (artifact.gravity) {
        expect(artifact.gravity.emotional_weight).toBe(0.9);
      }
      expect(result.stanceFieldsCleared).toEqual([]);
    }
  });

  it('essential: guard degrades gracefully with no gravity/impulse domains present', async () => {
    const { artifact, result } = await extractAndAssemble('essential', essentialExtraction('quoted_third_party'));

    expect(artifact.core!.wound).toBeNull();
    expect('gravity' in artifact).toBe(false);
    expect('impulse' in artifact).toBe(false);
    expect(result.stanceFieldsCleared).toEqual(['core.wound']);
    expect(validateEdmSchemaSync(artifact).valid).toBe(true);
  });
});
