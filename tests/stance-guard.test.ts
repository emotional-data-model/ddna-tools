/**
 * Tests for the deterministic experiential-stance attribution guard.
 *
 * Per-stance demotion contract (parity with deepadata-edm-sdk 0.8.9):
 * - quoted_third_party / assistant_generated / hypothetical: clear
 *   core.wound, constellation.{identity_thread, expressed_insight,
 *   somatic_signature}, force transformational_pivot=false, null the
 *   impulse domain, floor emotional_weight/strength_score at 0.2
 * - lived / witnessed / null: untouched (witnessed is NOT demoted)
 */

import { describe, it, expect } from 'vitest';
import type Anthropic from '@anthropic-ai/sdk';
import type OpenAI from 'openai';

import {
  EXPERIENTIAL_STANCE,
  isNonSubjectStance,
  takeStance,
  applyStanceGuard,
  consumeStance,
  extractWithLlm,
  extractWithOpenAI,
  extractWithKimi,
} from '../src/extractors/index.js';

// ============================================================================
// Fixtures
// ============================================================================

const fullPayload = (stance: string | null): Record<string, unknown> => ({
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
    resilience_markers: [],
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

const NON_SUBJECT = ['quoted_third_party', 'assistant_generated', 'hypothetical'] as const;
const SUBJECT_OR_UNKNOWN = ['lived', 'witnessed', null] as const;

// Fake LLM clients: the production path downstream of the model response
const fakeAnthropic = (payload: unknown): Anthropic =>
  ({
    messages: {
      create: async () => ({
        content: [{ type: 'text', text: JSON.stringify(payload) }],
      }),
    },
  }) as unknown as Anthropic;

const fakeOpenAI = (payload: unknown): OpenAI =>
  ({
    chat: {
      completions: {
        create: async () => ({
          choices: [{ message: { content: JSON.stringify(payload) } }],
        }),
      },
    },
  }) as unknown as OpenAI;

// ============================================================================
// Stance parsing
// ============================================================================

describe('takeStance', () => {
  it('consumes and removes the top-level key', () => {
    const extracted = fullPayload('lived');
    expect(takeStance(extracted)).toBe('lived');
    expect('experiential_stance' in extracted).toBe(false);
  });

  it('normalises spacing, hyphens, and case', () => {
    expect(takeStance({ experiential_stance: ' Quoted Third-Party ' })).toBe(
      'quoted_third_party'
    );
  });

  it('returns null for unknown or non-string values', () => {
    expect(takeStance({ experiential_stance: 'first_person' })).toBeNull();
    expect(takeStance({ experiential_stance: 42 })).toBeNull();
    expect(takeStance({})).toBeNull();
  });

  it('covers all five canonical stances', () => {
    expect(EXPERIENTIAL_STANCE).toEqual([
      'lived',
      'witnessed',
      'quoted_third_party',
      'assistant_generated',
      'hypothetical',
    ]);
    for (const stance of EXPERIENTIAL_STANCE) {
      expect(takeStance({ experiential_stance: stance })).toBe(stance);
    }
  });
});

// ============================================================================
// Per-stance demotion
// ============================================================================

describe('applyStanceGuard', () => {
  it.each(NON_SUBJECT)('%s: clears subject-significance fields', (stance) => {
    const extracted = fullPayload(stance);
    takeStance(extracted);
    const cleared = applyStanceGuard(extracted, stance);

    const core = extracted.core as Record<string, unknown>;
    const constellation = extracted.constellation as Record<string, unknown>;
    const gravity = extracted.gravity as Record<string, unknown>;
    const impulse = extracted.impulse as Record<string, unknown>;

    expect(core.wound).toBeNull();
    expect(constellation.identity_thread).toBeNull();
    expect(constellation.expressed_insight).toBeNull();
    expect(constellation.somatic_signature).toBeNull();
    expect(constellation.transformational_pivot).toBe(false);
    expect(gravity.emotional_weight).toBe(0.2);
    expect(gravity.strength_score).toBe(0.2);
    for (const value of Object.values(impulse)) {
      expect(value).toBeNull();
    }

    // content-describing fields are kept
    expect(core.anchor).toBe('a pasted story');
    expect(core.narrative).toBeTruthy();
    expect(constellation.emotion_primary).toBe('sadness');

    expect(cleared).toContain('core.wound');
    expect(cleared).toContain('constellation.transformational_pivot');
    expect(cleared).toContain('gravity.emotional_weight');
    expect(cleared).toContain('impulse.drive_state');
  });

  it.each(SUBJECT_OR_UNKNOWN)('%s: leaves the extraction untouched', (stance) => {
    const extracted = fullPayload(stance);
    takeStance(extracted);
    const cleared = applyStanceGuard(extracted, stance);

    expect(cleared).toEqual([]);
    expect((extracted.core as Record<string, unknown>).wound).toBe('her loss');
    expect((extracted.gravity as Record<string, unknown>).emotional_weight).toBe(0.9);
    expect(
      (extracted.constellation as Record<string, unknown>).transformational_pivot
    ).toBe(true);
  });

  it('floors weights at 0.2 without raising values already below it', () => {
    const extracted = fullPayload('hypothetical');
    takeStance(extracted);
    (extracted.gravity as Record<string, unknown>).emotional_weight = 0.15;
    const cleared = applyStanceGuard(extracted, 'hypothetical');

    expect((extracted.gravity as Record<string, unknown>).emotional_weight).toBe(0.15);
    expect(cleared).not.toContain('gravity.emotional_weight');
    expect(cleared).toContain('gravity.strength_score');
  });

  it('degrades gracefully when domains are missing from the payload', () => {
    expect(applyStanceGuard({ core: { anchor: 'x' } }, 'quoted_third_party')).toEqual([]);
    expect(applyStanceGuard({ core: { wound: 'y' } }, 'assistant_generated')).toEqual([
      'core.wound',
    ]);
  });

  it('isNonSubjectStance: only the three non-subject stances qualify', () => {
    expect(isNonSubjectStance('quoted_third_party')).toBe(true);
    expect(isNonSubjectStance('assistant_generated')).toBe(true);
    expect(isNonSubjectStance('hypothetical')).toBe(true);
    expect(isNonSubjectStance('lived')).toBe(false);
    expect(isNonSubjectStance('witnessed')).toBe(false);
    expect(isNonSubjectStance(null)).toBe(false);
  });
});

// ============================================================================
// consumeStance (telemetry note format)
// ============================================================================

describe('consumeStance', () => {
  it('records the stance and the cleared fields in the note', () => {
    const extracted = fullPayload('assistant_generated');
    const { stance, fieldsCleared, note } = consumeStance(extracted);

    expect(stance).toBe('assistant_generated');
    expect(fieldsCleared.length).toBeGreaterThan(0);
    expect(note).toContain('experiential_stance=assistant_generated');
    expect(note).toContain('stance_guard_cleared:');
    expect('experiential_stance' in extracted).toBe(false);
  });

  it('records null stance with no demotions', () => {
    const { stance, fieldsCleared, note } = consumeStance(fullPayload(null));
    expect(stance).toBeNull();
    expect(fieldsCleared).toEqual([]);
    expect(note).toBe('experiential_stance=null');
  });
});

// ============================================================================
// Extractor integration: guard is always on, in every provider path
// ============================================================================

describe('extractors apply the guard', () => {
  it('extractWithLlm (Anthropic): stance consumed, fields demoted, result carries stance', async () => {
    const result = await extractWithLlm(
      fakeAnthropic(fullPayload('quoted_third_party')),
      { text: 'USER: here is a story...' },
      'test-model',
      'full'
    );

    const extracted = result.extracted as unknown as Record<string, Record<string, unknown>>;
    expect('experiential_stance' in extracted).toBe(false);
    expect(extracted.core!.wound).toBeNull();
    expect(extracted.gravity!.emotional_weight).toBe(0.2);
    expect(result.experientialStance).toBe('quoted_third_party');
    expect(result.stanceFieldsCleared).toContain('core.wound');
    expect(result.notes).toContain('experiential_stance=quoted_third_party');
  });

  it('extractWithOpenAI: same contract', async () => {
    const result = await extractWithOpenAI(
      fakeOpenAI(fullPayload('hypothetical')),
      { text: 'a draft about invented people' },
      'test-model',
      0,
      'full'
    );

    const extracted = result.extracted as unknown as Record<string, Record<string, unknown>>;
    expect('experiential_stance' in extracted).toBe(false);
    expect(extracted.core!.wound).toBeNull();
    expect(result.experientialStance).toBe('hypothetical');
  });

  it('extractWithKimi: same contract', async () => {
    const result = await extractWithKimi(
      fakeOpenAI(fullPayload('assistant_generated')),
      { text: 'USER: write me a funny anecdote' },
      'test-model',
      'full'
    );

    const extracted = result.extracted as unknown as Record<string, Record<string, unknown>>;
    expect('experiential_stance' in extracted).toBe(false);
    expect(extracted.core!.wound).toBeNull();
    expect(result.experientialStance).toBe('assistant_generated');
  });

  it('lived stance passes through every provider untouched', async () => {
    const results = await Promise.all([
      extractWithLlm(fakeAnthropic(fullPayload('lived')), { text: 'memory' }, 'm', 'full'),
      extractWithOpenAI(fakeOpenAI(fullPayload('lived')), { text: 'memory' }, 'm', 0, 'full'),
      extractWithKimi(fakeOpenAI(fullPayload('lived')), { text: 'memory' }, 'm', 'full'),
    ]);

    for (const result of results) {
      const extracted = result.extracted as unknown as Record<string, Record<string, unknown>>;
      expect(extracted.core!.wound).toBe('her loss');
      expect(extracted.gravity!.emotional_weight).toBe(0.9);
      expect(result.experientialStance).toBe('lived');
      expect(result.stanceFieldsCleared).toEqual([]);
    }
  });

  it('confidence is computed pre-guard (demotion does not lower it)', async () => {
    const demoted = await extractWithLlm(
      fakeAnthropic(fullPayload('quoted_third_party')),
      { text: 't' },
      'm',
      'full'
    );
    const untouched = await extractWithLlm(
      fakeAnthropic(fullPayload('lived')),
      { text: 't' },
      'm',
      'full'
    );
    expect(demoted.confidence).toBe(untouched.confidence);
  });
});
