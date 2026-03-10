/**
 * EDM Schema Validation
 *
 * Validates EDM artifacts against the v0.6.0 profile schemas using Ajv.
 * Schemas are bundled from edm-spec (essential, extended, full profiles).
 */

import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Get directory of this module
const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = join(__dirname, '../../schemas');

// Profile type
export type EdmProfile = 'essential' | 'extended' | 'full';

// Schema file mapping
const SCHEMA_FILES: Record<EdmProfile, string> = {
  essential: 'edm.v0.6.essential.schema.json',
  extended: 'edm.v0.6.extended.schema.json',
  full: 'edm.v0.6.full.schema.json',
};

// Validation result
export interface SchemaValidationResult {
  valid: boolean;
  profile: EdmProfile;
  errors: SchemaValidationError[];
}

export interface SchemaValidationError {
  path: string;
  message: string;
  keyword: string;
}

// Cache compiled validators
const validatorCache = new Map<EdmProfile, Ajv>();

/**
 * Recursively resolve $ref in a schema by inlining fragment references
 */
function resolveRefs(schema: Record<string, unknown>, schemasDir: string): Record<string, unknown> {
  if (typeof schema !== 'object' || schema === null) {
    return schema;
  }

  // If this node has a $ref to a fragment, inline it
  if (typeof schema['$ref'] === 'string' && schema['$ref'].startsWith('fragments/')) {
    const fragmentPath = join(schemasDir, schema['$ref']);
    try {
      const fragment = JSON.parse(readFileSync(fragmentPath, 'utf-8'));
      // Return the fragment schema (without $ref)
      return resolveRefs(fragment, schemasDir);
    } catch {
      // If fragment doesn't exist, return empty object
      return { type: 'object' };
    }
  }

  // Recursively resolve refs in all properties
  const resolved: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(schema)) {
    if (Array.isArray(value)) {
      resolved[key] = value.map((item) =>
        typeof item === 'object' && item !== null
          ? resolveRefs(item as Record<string, unknown>, schemasDir)
          : item
      );
    } else if (typeof value === 'object' && value !== null) {
      resolved[key] = resolveRefs(value as Record<string, unknown>, schemasDir);
    } else {
      resolved[key] = value;
    }
  }
  return resolved;
}

/**
 * Load and compile schema for a given profile
 */
function getValidator(profile: EdmProfile): Ajv {
  if (validatorCache.has(profile)) {
    return validatorCache.get(profile)!;
  }

  const ajv = new Ajv({
    allErrors: true,
    strict: false,
  });
  addFormats(ajv);

  // Load the main profile schema and inline all $refs
  const schemaPath = join(SCHEMAS_DIR, SCHEMA_FILES[profile]);
  const rawSchema = JSON.parse(readFileSync(schemaPath, 'utf-8'));
  const resolvedSchema = resolveRefs(rawSchema, SCHEMAS_DIR);

  ajv.addSchema(resolvedSchema, profile);

  validatorCache.set(profile, ajv);
  return ajv;
}

/**
 * Detect profile from artifact's meta.profile field
 */
export function detectProfile(artifact: unknown): EdmProfile | null {
  if (!artifact || typeof artifact !== 'object') {
    return null;
  }

  const a = artifact as Record<string, unknown>;
  const meta = a.meta as Record<string, unknown> | undefined;
  const profile = meta?.profile;

  if (profile === 'essential' || profile === 'extended' || profile === 'full') {
    return profile;
  }

  return null;
}

/**
 * Validate an EDM artifact against its profile schema.
 *
 * Reads meta.profile to determine which schema to use.
 * Fails fast with clear errors if validation fails.
 *
 * @param artifact - The EDM artifact to validate
 * @returns Validation result with profile and any errors
 * @throws Error if profile cannot be detected
 */
export function validateEdmSchema(artifact: unknown): SchemaValidationResult {
  // Detect profile
  const profile = detectProfile(artifact);
  if (!profile) {
    throw new Error(
      'Cannot validate: meta.profile is missing or invalid. ' +
        "Expected 'essential', 'extended', or 'full'."
    );
  }

  // Get validator for this profile
  const ajv = getValidator(profile);
  const validate = ajv.getSchema(profile);

  if (!validate) {
    throw new Error(`Schema not loaded for profile: ${profile}`);
  }

  // Validate
  const valid = validate(artifact) as boolean;

  if (valid) {
    return { valid: true, profile, errors: [] };
  }

  // Map Ajv errors to our format
  const errors: SchemaValidationError[] = (validate.errors || []).map((err) => ({
    path: err.instancePath || '/',
    message: err.message || 'Unknown validation error',
    keyword: err.keyword,
  }));

  return { valid: false, profile, errors };
}

/**
 * Format validation errors for display
 */
export function formatValidationErrors(result: SchemaValidationResult): string {
  if (result.valid) {
    return `✓ Valid EDM artifact (${result.profile} profile)`;
  }

  const lines = [
    `✗ Invalid EDM artifact (${result.profile} profile)`,
    '',
    'Errors:',
    ...result.errors.map(
      (e) => `  ${e.path}: ${e.message} [${e.keyword}]`
    ),
  ];

  return lines.join('\n');
}
