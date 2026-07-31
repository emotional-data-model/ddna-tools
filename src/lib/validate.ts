/**
 * Heuristic field/enum checks for EDM artifacts (LEGACY — not seal-grade).
 *
 * This module checks required meta fields, enum membership, and a few
 * types. It does NOT run the JSON Schema: minItems/maxItems,
 * additionalProperties, per-profile required domains, and nested
 * structures are unchecked. An artifact this module passes can still be
 * rejected by seal (the session-09 two-validator drift, 2026-07-29).
 *
 * Seal-grade validation is `validateEdmSchemaSync` in validate-schema.ts
 * (ajv over the resolved profile schema) — the CLI `validate` command and
 * seal both use it. This module remains exported for API compatibility
 * and for fast enum-level feedback only.
 *
 * Enum values are derived from bundled schema fragments at module load
 * (schemas/fragments/*.json, synced from the installed edm-spec package).
 *
 * FREE: Does not require a DeepaData API key.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EDM_VERSION } from './edm-version.js';

// =============================================================================
// Schema Loading
// =============================================================================

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = join(__dirname, '../../schemas/fragments');

interface SchemaProperty {
  enum?: (string | null)[];
  type?: string | string[];
  properties?: Record<string, SchemaProperty>;
}

interface SchemaFragment {
  properties?: Record<string, SchemaProperty>;
}

function loadFragment(name: string): SchemaFragment {
  const path = join(SCHEMAS_DIR, `${name}.json`);
  return JSON.parse(readFileSync(path, 'utf-8'));
}

/**
 * Extract enum values from a schema property, filtering out null
 */
function extractEnum(prop: SchemaProperty | undefined): string[] | null {
  if (!prop || !prop.enum) return null;
  return prop.enum.filter((v): v is string => v !== null);
}

// Load schema fragments at module init
const metaSchema = loadFragment('meta');
const constellationSchema = loadFragment('constellation');
const gravitySchema = loadFragment('gravity');
const impulseSchema = loadFragment('impulse');
const governanceSchema = loadFragment('governance');
const milkyWaySchema = loadFragment('milky_way');

// =============================================================================
// Derived Enum Values (single source of truth: schema fragments)
// =============================================================================

const META_ENUMS: Record<string, string[] | null> = {
  visibility: extractEnum(metaSchema.properties?.visibility),
  pii_tier: extractEnum(metaSchema.properties?.pii_tier),
  source_type: extractEnum(metaSchema.properties?.source_type),
  consent_basis: extractEnum(metaSchema.properties?.consent_basis),
};

const CONSTELLATION_ENUMS: Record<string, string[] | null> = {
  temporal_context: extractEnum(constellationSchema.properties?.temporal_context),
  memory_type: extractEnum(constellationSchema.properties?.memory_type),
  media_format: extractEnum(constellationSchema.properties?.media_format),
  narrative_archetype: extractEnum(constellationSchema.properties?.narrative_archetype),
  relational_perspective: extractEnum(constellationSchema.properties?.relational_perspective),
  temporal_rhythm: extractEnum(constellationSchema.properties?.temporal_rhythm),
  // These fields use x_constraints (free text with canonical suggestions), not strict enums
  // emotion_primary, narrative_arc, relational_dynamics: null (skip enum check)
};

const GRAVITY_ENUMS: Record<string, string[] | null> = {
  emotional_density: extractEnum(gravitySchema.properties?.emotional_density),
  valence: extractEnum(gravitySchema.properties?.valence),
  viscosity: extractEnum(gravitySchema.properties?.viscosity),
  temporal_decay: extractEnum(gravitySchema.properties?.temporal_decay),
  adaptation_trajectory: extractEnum(gravitySchema.properties?.adaptation_trajectory),
  // tether_type, recurrence_pattern: free text with canonical suggestions
};

const IMPULSE_ENUMS: Record<string, string[] | null> = {
  drive_state: extractEnum(impulseSchema.properties?.drive_state),
  motivational_orientation: extractEnum(impulseSchema.properties?.motivational_orientation),
  temporal_focus: extractEnum(impulseSchema.properties?.temporal_focus),
  directionality: extractEnum(impulseSchema.properties?.directionality),
  social_visibility: extractEnum(impulseSchema.properties?.social_visibility),
  urgency: extractEnum(impulseSchema.properties?.urgency),
  risk_posture: extractEnum(impulseSchema.properties?.risk_posture),
  agency_level: extractEnum(impulseSchema.properties?.agency_level),
  regulation_state: extractEnum(impulseSchema.properties?.regulation_state),
  attachment_style: extractEnum(impulseSchema.properties?.attachment_style),
  // coping_style: free text with canonical suggestions
};

const GOVERNANCE_ENUMS: Record<string, string[] | null> = {
  jurisdiction: extractEnum(governanceSchema.properties?.jurisdiction),
  exportability: extractEnum(governanceSchema.properties?.exportability),
};

const MILKY_WAY_ENUMS: Record<string, string[] | null> = {
  visibility_context: extractEnum(milkyWaySchema.properties?.visibility_context),
};

// =============================================================================
// Types
// =============================================================================

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

// =============================================================================
// Constants
// =============================================================================

/**
 * Schema version this validator supports — derived from the installed
 * edm-spec package (src/lib/edm-version.ts), never restated as a literal.
 */
const SCHEMA_VERSION = EDM_VERSION;

/**
 * Accepted version pattern
 * TODO(ADR-0021): Replace pattern matching with version-routed schema selection
 */
const ACCEPTED_VERSION_PATTERN = /^0\.[3-9]\.[0-9]+$/;
const ACCEPTED_VERSION_RANGE = '0.3.x through 0.9.x';

/**
 * Required domains in an EDM artifact
 */
const REQUIRED_DOMAINS = ['meta', 'core'] as const;

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

// =============================================================================
// Validation
// =============================================================================

/**
 * Validate enum field against schema-derived values
 */
function validateEnumField(
  domain: Record<string, unknown>,
  field: string,
  validValues: string[] | null,
  domainPath: string,
  errors: ValidationError[]
): void {
  if (!validValues) return; // No enum constraint (free text)

  const value = domain[field];
  if (value !== null && value !== undefined && !validValues.includes(value as string)) {
    errors.push({
      path: `${domainPath}.${field}`,
      message: `Invalid value for '${domainPath}.${field}'`,
      expected: validValues.join(' | '),
      actual: String(value),
    });
  }
}

/**
 * Validate an EDM artifact against the bundled v0.8-line schema
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

    // Validate enum fields from schema
    for (const [field, validValues] of Object.entries(META_ENUMS)) {
      validateEnumField(meta, field, validValues, 'meta', errors);
    }

    // Validate version format
    // TODO(ADR-0021): Replace pattern matching with version-routed schema selection
    if (meta.version && typeof meta.version === 'string') {
      if (!ACCEPTED_VERSION_PATTERN.test(meta.version)) {
        errors.push({
          path: 'meta.version',
          message: 'Invalid EDM version format',
          expected: ACCEPTED_VERSION_RANGE,
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
      validateEnumField(constellation, field, validValues, 'constellation', errors);
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
      validateEnumField(gravity, field, validValues, 'gravity', errors);
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
      validateEnumField(impulse, field, validValues, 'impulse', errors);
    }
  }

  // Validate governance enum fields
  if (obj.governance && typeof obj.governance === 'object') {
    const governance = obj.governance as Record<string, unknown>;

    for (const [field, validValues] of Object.entries(GOVERNANCE_ENUMS)) {
      validateEnumField(governance, field, validValues, 'governance', errors);
    }
  }

  // Validate milky_way enum fields
  if (obj.milky_way && typeof obj.milky_way === 'object') {
    const milkyWay = obj.milky_way as Record<string, unknown>;

    for (const [field, validValues] of Object.entries(MILKY_WAY_ENUMS)) {
      validateEnumField(milkyWay, field, validValues, 'milky_way', errors);
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
