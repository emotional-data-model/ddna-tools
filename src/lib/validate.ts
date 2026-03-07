/**
 * Schema Validation for EDM Artifacts
 * Validates artifacts against EDM v0.5.1 JSON schema
 *
 * FREE: Does not require a DeepaData API key.
 */

import type { EdmPayload } from './types.js';

/**
 * Validation error detail
 */
export interface ValidationError {
  /** Path to the invalid field */
  path: string;
  /** Error message */
  message: string;
  /** Expected value or type */
  expected?: string;
  /** Actual value or type received */
  actual?: string;
}

/**
 * Validation result
 */
export interface ValidationResult {
  /** Whether the artifact is valid */
  valid: boolean;
  /** List of validation errors */
  errors: ValidationError[];
  /** EDM schema version validated against */
  schemaVersion: string;
}

/**
 * Schema version this validator supports
 */
const SCHEMA_VERSION = '0.5.1';

/**
 * Required domains in an EDM artifact
 */
const REQUIRED_DOMAINS = ['meta', 'core'] as const;

/**
 * Optional domains in an EDM artifact
 */
const OPTIONAL_DOMAINS = [
  'constellation',
  'milky_way',
  'gravity',
  'impulse',
  'governance',
  'telemetry',
  'system',
  'crosswalks',
] as const;

/**
 * Required fields in meta domain
 */
const META_REQUIRED_FIELDS = [
  'version',
  'created_at',
  'visibility',
  'pii_tier',
  'source_type',
  'consent_basis',
] as const;

/**
 * Valid enum values for meta fields
 */
const META_ENUMS = {
  visibility: ['private', 'shared', 'public'],
  pii_tier: ['none', 'low', 'moderate', 'high', 'extreme'],
  source_type: ['text', 'audio', 'image', 'video', 'mixed'],
  consent_basis: ['consent', 'contract', 'legitimate_interest', 'none'],
} as const;

/**
 * Valid enum values for constellation fields
 */
const CONSTELLATION_ENUMS = {
  emotion_primary: [
    'joy', 'sadness', 'fear', 'anger', 'wonder', 'peace',
    'tenderness', 'reverence', 'pride', 'anxiety', 'gratitude',
    'longing', 'hope', 'shame',
  ],
  narrative_arc: ['overcoming', 'transformation', 'connection', 'reflection', 'closure'],
  relational_dynamics: [
    'parent_child', 'grandparent_grandchild', 'romantic_partnership', 'couple',
    'sibling_bond', 'family', 'friendship', 'friend', 'companionship', 'colleague',
    'mentorship', 'reunion', 'community_ritual', 'grief', 'self_reflection',
    'professional', 'therapeutic', 'service', 'adversarial',
  ],
  temporal_context: ['childhood', 'early_adulthood', 'midlife', 'late_life', 'recent', 'future', 'timeless'],
  memory_type: ['legacy_artifact', 'fleeting_moment', 'milestone', 'reflection', 'formative_experience'],
  media_format: ['photo', 'video', 'audio', 'text', 'photo_with_story'],
  narrative_archetype: [
    'hero', 'caregiver', 'seeker', 'sage', 'lover', 'outlaw',
    'innocent', 'orphan', 'magician', 'creator', 'everyman', 'jester', 'ruler', 'mentor',
  ],
  relational_perspective: ['self', 'partner', 'family', 'friends', 'community', 'humanity'],
  temporal_rhythm: ['still', 'sudden', 'rising', 'fading', 'recurring', 'spiraling', 'dragging', 'suspended', 'looping', 'cyclic'],
} as const;

/**
 * Valid enum values for gravity fields
 */
const GRAVITY_ENUMS = {
  emotional_density: ['low', 'medium', 'high'],
  valence: ['positive', 'negative', 'mixed'],
  viscosity: ['low', 'medium', 'high', 'enduring', 'fluid'],
  tether_type: ['person', 'symbol', 'event', 'place', 'ritual', 'object', 'tradition', 'identity', 'self'],
  recurrence_pattern: ['cyclical', 'isolated', 'chronic', 'emerging'],
  temporal_decay: ['fast', 'moderate', 'slow'],
  adaptation_trajectory: ['improving', 'stable', 'declining', 'integrative', 'emerging'],
} as const;

/**
 * Valid enum values for impulse fields
 */
const IMPULSE_ENUMS = {
  drive_state: ['explore', 'approach', 'avoid', 'repair', 'persevere', 'share', 'confront', 'protect', 'process'],
  motivational_orientation: ['belonging', 'safety', 'mastery', 'meaning', 'autonomy', 'authenticity'],
  temporal_focus: ['past', 'present', 'future'],
  directionality: ['inward', 'outward', 'transcendent'],
  social_visibility: ['private', 'relational', 'collective'],
  urgency: ['calm', 'elevated', 'pressing', 'acute'],
  risk_posture: ['cautious', 'balanced', 'bold'],
  agency_level: ['low', 'medium', 'high'],
  regulation_state: ['regulated', 'wavering', 'dysregulated'],
  attachment_style: ['secure', 'anxious', 'avoidant', 'disorganized'],
  coping_style: ['reframe_meaning', 'seek_support', 'distract', 'ritualize', 'confront', 'detach', 'process'],
} as const;

/**
 * Valid enum values for governance fields
 */
const GOVERNANCE_ENUMS = {
  jurisdiction: ['GDPR', 'CCPA', 'HIPAA', 'PIPEDA', 'LGPD', 'None', 'Mixed'],
  exportability: ['allowed', 'restricted', 'forbidden'],
} as const;

/**
 * Valid enum values for milky_way fields
 */
const MILKY_WAY_ENUMS = {
  visibility_context: ['private', 'family_only', 'shared_publicly'],
} as const;

/**
 * Validate an EDM artifact against the v0.5.1 schema
 *
 * FREE: Does not require a DeepaData API key.
 *
 * @param artifact - EDM artifact to validate
 * @returns Validation result
 */
export function validate(artifact: unknown): ValidationResult {
  const errors: ValidationError[] = [];

  // Check if artifact is an object
  if (!artifact || typeof artifact !== 'object') {
    return {
      valid: false,
      errors: [{ path: '', message: 'Artifact must be an object', expected: 'object', actual: typeof artifact }],
      schemaVersion: SCHEMA_VERSION,
    };
  }

  const obj = artifact as Record<string, unknown>;

  // Check required domains
  for (const domain of REQUIRED_DOMAINS) {
    if (!(domain in obj) || obj[domain] === null || obj[domain] === undefined) {
      errors.push({
        path: domain,
        message: `Required domain '${domain}' is missing`,
        expected: 'object',
        actual: 'undefined',
      });
    } else if (typeof obj[domain] !== 'object') {
      errors.push({
        path: domain,
        message: `Domain '${domain}' must be an object`,
        expected: 'object',
        actual: typeof obj[domain],
      });
    }
  }

  // Validate meta domain
  if (obj.meta && typeof obj.meta === 'object') {
    const meta = obj.meta as Record<string, unknown>;

    // Check required fields
    for (const field of META_REQUIRED_FIELDS) {
      if (!(field in meta) || meta[field] === undefined) {
        errors.push({
          path: `meta.${field}`,
          message: `Required field 'meta.${field}' is missing`,
        });
      }
    }

    // Validate enum fields
    for (const [field, validValues] of Object.entries(META_ENUMS)) {
      const value = meta[field];
      if (value !== null && value !== undefined && !validValues.includes(value as never)) {
        errors.push({
          path: `meta.${field}`,
          message: `Invalid value for 'meta.${field}'`,
          expected: validValues.join(' | '),
          actual: String(value),
        });
      }
    }

    // Validate version format
    if (meta.version && typeof meta.version === 'string') {
      if (!/^0\.[4-9]\.[0-9]+$/.test(meta.version)) {
        errors.push({
          path: 'meta.version',
          message: 'Invalid EDM version format',
          expected: '0.5.x or 0.4.x',
          actual: meta.version,
        });
      }
    }

    // Validate created_at format
    if (meta.created_at && typeof meta.created_at === 'string') {
      const date = new Date(meta.created_at);
      if (isNaN(date.getTime())) {
        errors.push({
          path: 'meta.created_at',
          message: 'Invalid ISO 8601 timestamp',
          actual: meta.created_at,
        });
      }
    }
  }

  // Validate core domain structure
  if (obj.core && typeof obj.core === 'object') {
    const core = obj.core as Record<string, unknown>;
    const coreFields = ['anchor', 'spark', 'wound', 'fuel', 'bridge', 'echo', 'narrative'];
    for (const field of coreFields) {
      if (field in core && core[field] !== null && typeof core[field] !== 'string') {
        errors.push({
          path: `core.${field}`,
          message: `Field 'core.${field}' must be a string or null`,
          expected: 'string | null',
          actual: typeof core[field],
        });
      }
    }
  }

  // Validate constellation enum fields
  if (obj.constellation && typeof obj.constellation === 'object') {
    const constellation = obj.constellation as Record<string, unknown>;
    for (const [field, validValues] of Object.entries(CONSTELLATION_ENUMS)) {
      const value = constellation[field];
      if (value !== null && value !== undefined && !validValues.includes(value as never)) {
        errors.push({
          path: `constellation.${field}`,
          message: `Invalid value for 'constellation.${field}'`,
          expected: validValues.join(' | '),
          actual: String(value),
        });
      }
    }

    // Validate transformational_pivot is boolean
    if ('transformational_pivot' in constellation) {
      if (typeof constellation.transformational_pivot !== 'boolean') {
        errors.push({
          path: 'constellation.transformational_pivot',
          message: 'Field must be a boolean',
          expected: 'boolean',
          actual: typeof constellation.transformational_pivot,
        });
      }
    }

    // Validate emotion_subtone is array
    if ('emotion_subtone' in constellation && constellation.emotion_subtone !== null) {
      if (!Array.isArray(constellation.emotion_subtone)) {
        errors.push({
          path: 'constellation.emotion_subtone',
          message: 'Field must be an array',
          expected: 'string[]',
          actual: typeof constellation.emotion_subtone,
        });
      }
    }
  }

  // Validate gravity enum fields and numeric ranges
  if (obj.gravity && typeof obj.gravity === 'object') {
    const gravity = obj.gravity as Record<string, unknown>;
    for (const [field, validValues] of Object.entries(GRAVITY_ENUMS)) {
      const value = gravity[field];
      if (value !== null && value !== undefined && !validValues.includes(value as never)) {
        errors.push({
          path: `gravity.${field}`,
          message: `Invalid value for 'gravity.${field}'`,
          expected: validValues.join(' | '),
          actual: String(value),
        });
      }
    }

    // Validate numeric fields (0.0 - 1.0)
    const numericFields = ['emotional_weight', 'strength_score'];
    for (const field of numericFields) {
      if (field in gravity && gravity[field] !== null) {
        const value = gravity[field];
        if (typeof value !== 'number' || value < 0 || value > 1) {
          errors.push({
            path: `gravity.${field}`,
            message: `Field must be a number between 0 and 1`,
            expected: 'number (0.0-1.0)',
            actual: String(value),
          });
        }
      }
    }
  }

  // Validate impulse enum fields
  if (obj.impulse && typeof obj.impulse === 'object') {
    const impulse = obj.impulse as Record<string, unknown>;
    for (const [field, validValues] of Object.entries(IMPULSE_ENUMS)) {
      const value = impulse[field];
      if (value !== null && value !== undefined && !validValues.includes(value as never)) {
        errors.push({
          path: `impulse.${field}`,
          message: `Invalid value for 'impulse.${field}'`,
          expected: validValues.join(' | '),
          actual: String(value),
        });
      }
    }
  }

  // Validate governance enum fields
  if (obj.governance && typeof obj.governance === 'object') {
    const governance = obj.governance as Record<string, unknown>;
    for (const [field, validValues] of Object.entries(GOVERNANCE_ENUMS)) {
      const value = governance[field];
      if (value !== null && value !== undefined && !validValues.includes(value as never)) {
        errors.push({
          path: `governance.${field}`,
          message: `Invalid value for 'governance.${field}'`,
          expected: validValues.join(' | '),
          actual: String(value),
        });
      }
    }
  }

  // Validate milky_way enum fields
  if (obj.milky_way && typeof obj.milky_way === 'object') {
    const milkyWay = obj.milky_way as Record<string, unknown>;
    for (const [field, validValues] of Object.entries(MILKY_WAY_ENUMS)) {
      const value = milkyWay[field];
      if (value !== null && value !== undefined && !validValues.includes(value as never)) {
        errors.push({
          path: `milky_way.${field}`,
          message: `Invalid value for 'milky_way.${field}'`,
          expected: validValues.join(' | '),
          actual: String(value),
        });
      }
    }

    // Validate associated_people is array
    if ('associated_people' in milkyWay && milkyWay.associated_people !== null) {
      if (!Array.isArray(milkyWay.associated_people)) {
        errors.push({
          path: 'milky_way.associated_people',
          message: 'Field must be an array',
          expected: 'string[]',
          actual: typeof milkyWay.associated_people,
        });
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    schemaVersion: SCHEMA_VERSION,
  };
}

/**
 * Quick validation check (returns boolean only)
 *
 * @param artifact - EDM artifact to validate
 * @returns true if valid
 */
export function isValid(artifact: unknown): boolean {
  return validate(artifact).valid;
}
