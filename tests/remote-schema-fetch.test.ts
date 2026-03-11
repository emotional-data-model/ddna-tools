/**
 * Remote Schema Fetch Verification Tests
 *
 * Verifies that validateEdmSchema() successfully fetches schemas from
 * the live canonical URLs at https://deepadata.com/schemas/edm/v0.6.0/
 *
 * When schemaSource === 'remote', the fetch worked.
 * When schemaSource === 'bundled', it fell back (URL unreachable or fetch failed).
 */

import { describe, it, expect } from 'vitest';
import { validateEdmSchema, formatValidationErrors } from '../src/lib/validate-schema.js';

// Valid v0.6.0 Essential profile artifact
const validEssentialArtifact = {
  meta: {
    version: '0.6.0',
    profile: 'essential',
    created_at: '2026-03-11T10:00:00.000Z',
    visibility: 'private',
    pii_tier: 'none',
    consent_basis: 'consent',
  },
  core: {
    anchor: 'grandmother',
    spark: 'old photographs',
    wound: 'loss',
    fuel: 'love',
    bridge: 'acceptance',
    echo: 'her laughter',
  },
  constellation: {
    emotion_primary: 'gratitude',
    emotion_subtone: ['bittersweet', 'nostalgic'],
    narrative_arc: 'reflection',
  },
  governance: {
    jurisdiction: 'GDPR',
    retention_policy: {
      basis: 'user_defined',
      ttl_days: 365,
      on_expiry: 'soft_delete',
    },
    subject_rights: {
      portable: true,
      erasable: true,
      explainable: true,
    },
  },
  telemetry: {
    entry_confidence: 0.92,
    extraction_model: 'claude-3-5-sonnet',
  },
};

// Valid v0.6.0 Extended profile artifact
const validExtendedArtifact = {
  meta: {
    version: '0.6.0',
    profile: 'extended',
    created_at: '2026-03-11T10:00:00.000Z',
    visibility: 'private',
    pii_tier: 'low',
    consent_basis: 'consent',
  },
  core: {
    anchor: 'childhood home',
    spark: 'returning visit',
    wound: 'change',
    fuel: 'curiosity',
    bridge: 'understanding',
    echo: 'familiar smells',
    narrative: 'Returning to the childhood home after many years, finding it changed yet familiar.',
  },
  constellation: {
    emotion_primary: 'longing',
    emotion_subtone: ['nostalgic', 'peaceful'],
    narrative_arc: 'reflection',
  },
  milky_way: {
    event_type: 'homecoming',
    location_context: 'childhood neighborhood',
    associated_people: ['family'],
  },
  gravity: {
    emotional_weight: 0.75,
    valence: 'mixed',
    tether_type: 'place',
    recurrence_pattern: 'cyclical',
    strength_score: 0.8,
  },
  governance: {
    jurisdiction: 'GDPR',
    retention_policy: {
      basis: 'user_defined',
      ttl_days: 730,
      on_expiry: 'anonymize',
    },
    subject_rights: {
      portable: true,
      erasable: true,
      explainable: true,
    },
  },
  telemetry: {
    entry_confidence: 0.88,
    extraction_model: 'claude-3-5-sonnet',
  },
};

// Valid v0.6.0 Full profile artifact
const validFullArtifact = {
  meta: {
    version: '0.6.0',
    profile: 'full',
    created_at: '2026-03-11T10:00:00.000Z',
    visibility: 'shared',
    pii_tier: 'moderate',
    consent_basis: 'consent',
  },
  core: {
    anchor: 'wedding day',
    spark: 'anniversary photo',
    wound: 'time passing',
    fuel: 'deep love',
    bridge: 'renewal',
    echo: 'wedding music',
    narrative: 'Looking at wedding photos on our anniversary, feeling the passage of time and the strength of our bond.',
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
    retention_policy: {
      basis: 'user_defined',
      ttl_days: null,
      on_expiry: null,
    },
    subject_rights: {
      portable: true,
      erasable: true,
      explainable: true,
    },
    exportability: 'allowed',
  },
  telemetry: {
    entry_confidence: 0.95,
    extraction_model: 'claude-3-5-sonnet',
    extraction_provider: 'anthropic',
  },
  system: {
    embeddings: null,
    indices: null,
  },
  crosswalks: {
    plutchik_primary: 'joy',
    geneva_emotion_wheel: null,
    DSM5_specifiers: null,
    HMD_v2_memory_type: null,
    ISO_27557_labels: null,
  },
};

describe('Remote Schema Fetch Verification', () => {
  describe('Live Canonical URL Tests', () => {
    it('should fetch essential profile schema from remote URL (v0.6.0)', async () => {
      const result = await validateEdmSchema(validEssentialArtifact);

      console.log('\n=== Essential Profile ===');
      console.log(formatValidationErrors(result));
      console.log(`schemaSource: ${result.schemaSource}`);

      expect(result.profile).toBe('essential');
      expect(result.schemaSource).toBe('remote');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    }, 10000); // 10s timeout for network

    it('should fetch extended profile schema from remote URL (v0.6.0)', async () => {
      const result = await validateEdmSchema(validExtendedArtifact);

      console.log('\n=== Extended Profile ===');
      console.log(formatValidationErrors(result));
      console.log(`schemaSource: ${result.schemaSource}`);

      expect(result.profile).toBe('extended');
      expect(result.schemaSource).toBe('remote');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    }, 10000);

    it('should fetch full profile schema from remote URL (v0.6.0)', async () => {
      const result = await validateEdmSchema(validFullArtifact);

      console.log('\n=== Full Profile ===');
      console.log(formatValidationErrors(result));
      console.log(`schemaSource: ${result.schemaSource}`);

      expect(result.profile).toBe('full');
      expect(result.schemaSource).toBe('remote');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    }, 10000);
  });

  describe('Summary Report', () => {
    it('should verify all three profiles and report results', async () => {
      const profiles = ['essential', 'extended', 'full'] as const;
      const artifacts = {
        essential: validEssentialArtifact,
        extended: validExtendedArtifact,
        full: validFullArtifact,
      };

      console.log('\n' + '='.repeat(60));
      console.log('REMOTE SCHEMA FETCH VERIFICATION REPORT');
      console.log('='.repeat(60));

      const results: Record<string, { source: string; valid: boolean; errors: number }> = {};

      for (const profile of profiles) {
        const result = await validateEdmSchema(artifacts[profile]);
        results[profile] = {
          source: result.schemaSource,
          valid: result.valid,
          errors: result.errors.length,
        };

        const status = result.schemaSource === 'remote' ? '✓ REMOTE' : '✗ BUNDLED (fallback)';
        const validity = result.valid ? 'valid' : `invalid (${result.errors.length} errors)`;

        console.log(`\n${profile.toUpperCase()} profile:`);
        console.log(`  Schema source: ${status}`);
        console.log(`  Validation:    ${validity}`);

        if (!result.valid) {
          result.errors.forEach((err) => {
            console.log(`    - ${err.path}: ${err.message}`);
          });
        }
      }

      console.log('\n' + '='.repeat(60));

      // All profiles should use remote schemas
      const allRemote = Object.values(results).every((r) => r.source === 'remote');
      const allValid = Object.values(results).every((r) => r.valid);

      console.log(`\nSUMMARY:`);
      console.log(`  All profiles using remote schema: ${allRemote ? 'YES' : 'NO'}`);
      console.log(`  All artifacts valid: ${allValid ? 'YES' : 'NO'}`);
      console.log('='.repeat(60) + '\n');

      // Assertions
      expect(allRemote).toBe(true);
      expect(allValid).toBe(true);
    }, 30000); // 30s total timeout for all three
  });
});
