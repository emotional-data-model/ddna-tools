/**
 * Tests for EDM extraction functionality
 *
 * Note: These tests validate types, prompts, and helper functions.
 * Actual LLM extraction requires API keys and is tested separately.
 */

import { describe, it, expect } from 'vitest';

import {
  EXTRACTION_SYSTEM_PROMPT,
  ESSENTIAL_PROFILE_PROMPT,
  EXTENDED_PROFILE_PROMPT,
  getProfilePrompt,
  calculateProfileConfidence,
  PROFILE_REQUIRED_FIELDS,
} from '../src/extractors/index.js';

import type {
  EdmProfile,
  ExtractionInput,
  LlmExtractionResult,
} from '../src/extractors/types.js';

// ============================================================================
// PROMPT TESTS
// ============================================================================

describe('extraction prompts', () => {
  it('should have EXTRACTION_SYSTEM_PROMPT defined', () => {
    expect(EXTRACTION_SYSTEM_PROMPT).toBeDefined();
    expect(typeof EXTRACTION_SYSTEM_PROMPT).toBe('string');
    expect(EXTRACTION_SYSTEM_PROMPT.length).toBeGreaterThan(1000);
  });

  it('should have ESSENTIAL_PROFILE_PROMPT defined', () => {
    expect(ESSENTIAL_PROFILE_PROMPT).toBeDefined();
    expect(ESSENTIAL_PROFILE_PROMPT).toContain('PROFILE: ESSENTIAL');
    expect(ESSENTIAL_PROFILE_PROMPT).toContain('core');
    expect(ESSENTIAL_PROFILE_PROMPT).toContain('constellation');
  });

  it('should have EXTENDED_PROFILE_PROMPT defined', () => {
    expect(EXTENDED_PROFILE_PROMPT).toBeDefined();
    expect(EXTENDED_PROFILE_PROMPT).toContain('PROFILE: EXTENDED');
    expect(EXTENDED_PROFILE_PROMPT).toContain('milky_way');
    expect(EXTENDED_PROFILE_PROMPT).toContain('gravity');
  });

  it('should return correct prompt for each profile', () => {
    expect(getProfilePrompt('essential')).toBe(ESSENTIAL_PROFILE_PROMPT);
    expect(getProfilePrompt('extended')).toBe(EXTENDED_PROFILE_PROMPT);
    expect(getProfilePrompt('full')).toBeNull(); // Full uses EXTRACTION_SYSTEM_PROMPT
  });
});

// ============================================================================
// PROFILE REQUIRED FIELDS TESTS
// ============================================================================

describe('PROFILE_REQUIRED_FIELDS', () => {
  it('should have required fields for essential profile', () => {
    const fields = PROFILE_REQUIRED_FIELDS.essential;
    expect(fields).toContain('core.anchor');
    expect(fields).toContain('core.spark');
    expect(fields).toContain('constellation.emotion_primary');
    expect(fields.length).toBe(5);
  });

  it('should have required fields for extended profile', () => {
    const fields = PROFILE_REQUIRED_FIELDS.extended;
    expect(fields).toContain('core.narrative');
    expect(fields).toContain('milky_way.event_type');
    expect(fields).toContain('gravity.emotional_weight');
    expect(fields.length).toBe(15);
  });

  it('should have required fields for full profile', () => {
    const fields = PROFILE_REQUIRED_FIELDS.full;
    expect(fields).toContain('impulse.drive_state');
    expect(fields).toContain('impulse.motivational_orientation');
    expect(fields.length).toBe(21);
  });
});

// ============================================================================
// CONFIDENCE CALCULATION TESTS
// ============================================================================

describe('calculateProfileConfidence', () => {
  it('should return 1.0 for fully populated essential profile', () => {
    const extracted = {
      core: {
        anchor: 'dad\'s workshop',
        spark: 'sawdust smell',
        wound: null, // Optional
        fuel: 'curiosity',
        bridge: 'memory of tools',
        echo: 'his voice',
      },
      constellation: {
        emotion_primary: 'tenderness',
        emotion_subtone: ['nostalgic', 'warm'],
        narrative_arc: 'reflection',
      },
    };

    const confidence = calculateProfileConfidence(extracted, 'essential');
    expect(confidence).toBe(1.0);
  });

  it('should return partial confidence for partially populated profile', () => {
    const extracted = {
      core: {
        anchor: 'dad\'s workshop',
        spark: null,
        wound: null,
        fuel: null,
        bridge: null,
        echo: null,
      },
      constellation: {
        emotion_primary: 'tenderness',
        emotion_subtone: [],
        narrative_arc: null,
      },
    };

    const confidence = calculateProfileConfidence(extracted, 'essential');
    expect(confidence).toBeLessThan(1.0);
    expect(confidence).toBeGreaterThan(0);
  });

  it('should return 0.0 for empty profile', () => {
    const extracted = {
      core: {
        anchor: null,
        spark: null,
        wound: null,
        fuel: null,
        bridge: null,
        echo: null,
      },
      constellation: {
        emotion_primary: null,
        emotion_subtone: [],
        narrative_arc: null,
      },
    };

    const confidence = calculateProfileConfidence(extracted, 'essential');
    expect(confidence).toBe(0);
  });

  it('should handle extended profile with gravity fields', () => {
    const extracted = {
      core: {
        anchor: 'workshop',
        spark: 'smell',
        wound: null,
        fuel: 'curiosity',
        bridge: 'memory',
        echo: 'voice',
        narrative: 'A story of remembering...',
      },
      constellation: {
        emotion_primary: 'tenderness',
        emotion_subtone: ['nostalgic'],
        narrative_arc: 'reflection',
        relational_dynamics: 'parent_child',
        temporal_context: 'childhood',
        memory_type: 'formative_experience',
      },
      milky_way: {
        event_type: 'daily routine',
        location_context: 'garage',
        associated_people: ['dad'],
        visibility_context: 'private',
        tone_shift: null,
      },
      gravity: {
        emotional_weight: 0.7,
        valence: 'positive',
        tether_type: 'person',
        recurrence_pattern: 'cyclical',
        strength_score: 0.8,
      },
    };

    const confidence = calculateProfileConfidence(extracted, 'extended');
    expect(confidence).toBe(1.0);
  });
});

// ============================================================================
// TYPE TESTS
// ============================================================================

describe('types', () => {
  it('should accept valid EdmProfile values', () => {
    const profiles: EdmProfile[] = ['essential', 'extended', 'full'];
    expect(profiles).toHaveLength(3);
  });

  it('should accept valid ExtractionInput', () => {
    const input: ExtractionInput = {
      text: 'I remember the smell of sawdust...',
    };
    expect(input.text).toBeDefined();
    expect(input.image).toBeUndefined();

    const inputWithImage: ExtractionInput = {
      text: 'A photo of dad',
      image: 'base64data...',
      imageMediaType: 'image/jpeg',
    };
    expect(inputWithImage.image).toBeDefined();
  });
});

// ============================================================================
// PROMPT CONTENT VALIDATION
// ============================================================================

describe('prompt content validation', () => {
  it('should contain all core fields in full prompt', () => {
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"anchor"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"spark"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"wound"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"fuel"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"bridge"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"echo"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"narrative"');
  });

  it('should contain arc_type field (v0.7.0+ addition)', () => {
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"arc_type"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('moral_awakening');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('gratitude');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('authenticity');
  });

  it('should contain impulse domain in full prompt', () => {
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"impulse"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"drive_state"');
    expect(EXTRACTION_SYSTEM_PROMPT).toContain('"regulation_state"');
  });

  it('should NOT contain impulse domain in extended prompt', () => {
    expect(EXTENDED_PROFILE_PROMPT).not.toContain('"impulse"');
  });

  it('should NOT contain partner profile references', () => {
    // Per ADR-0023, partner profiles are NOT in OSS
    expect(EXTRACTION_SYSTEM_PROMPT).not.toContain('partner:');
    expect(ESSENTIAL_PROFILE_PROMPT).not.toContain('partner:');
    expect(EXTENDED_PROFILE_PROMPT).not.toContain('partner:');
  });
});
