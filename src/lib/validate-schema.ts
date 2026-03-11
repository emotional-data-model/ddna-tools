/**
 * EDM Schema Validation
 *
 * Validates EDM artifacts against profile schemas using Ajv.
 *
 * Schema Loading Strategy:
 * 1. Attempt to fetch from canonical URL:
 *    https://deepadata.com/schemas/edm/{version}/edm.{profile}.schema.json
 * 2. Fall back to bundled schemas if fetch fails (offline/network error)
 *
 * Bundled schemas correspond to edm-spec v0.6.0 — update when spec version increments.
 */

import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Get directory of this module
const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = join(__dirname, '../../schemas');

// Remote schema base URL
const SCHEMA_BASE_URL = 'https://deepadata.com/schemas/edm';

// Fetch timeout in milliseconds
const FETCH_TIMEOUT_MS = 5000;

// Profile type
export type EdmProfile = 'essential' | 'extended' | 'full';

// Schema file mapping (for bundled fallback)
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
  /** Whether the schema was loaded from remote URL or bundled fallback */
  schemaSource: 'remote' | 'bundled';
}

export interface SchemaValidationError {
  path: string;
  message: string;
  keyword: string;
}

// Cache compiled validators by version+profile
const validatorCache = new Map<string, Ajv>();

// Cache fetched remote schemas
const remoteSchemaCache = new Map<string, Record<string, unknown>>();

/**
 * Extract version from artifact metadata
 */
function extractVersion(artifact: unknown): string | null {
  if (!artifact || typeof artifact !== 'object') {
    return null;
  }

  const a = artifact as Record<string, unknown>;
  const meta = a.meta as Record<string, unknown> | undefined;
  const version = meta?.version;

  if (typeof version === 'string' && /^0\.\d+\.\d+$/.test(version)) {
    // Convert "0.6.0" to "v0.6.0"
    return `v${version}`;
  }

  return null;
}

/**
 * Fetch schema from remote URL with timeout
 */
async function fetchRemoteSchema(
  version: string,
  profile: EdmProfile
): Promise<Record<string, unknown> | null> {
  const cacheKey = `${version}/${profile}`;

  // Check cache first
  if (remoteSchemaCache.has(cacheKey)) {
    return remoteSchemaCache.get(cacheKey)!;
  }

  const url = `${SCHEMA_BASE_URL}/${version}/edm.${profile}.schema.json`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/schema+json, application/json',
        'User-Agent': 'deepadata-ddna-tools/0.2.0',
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return null;
    }

    const schema = await response.json() as Record<string, unknown>;

    // Cache the fetched schema
    remoteSchemaCache.set(cacheKey, schema);

    return schema;
  } catch {
    // Network error, timeout, or abort — return null to trigger fallback
    return null;
  }
}

/**
 * Fetch fragment schema from remote URL
 */
async function fetchRemoteFragment(
  version: string,
  fragmentName: string
): Promise<Record<string, unknown> | null> {
  const cacheKey = `${version}/fragments/${fragmentName}`;

  if (remoteSchemaCache.has(cacheKey)) {
    return remoteSchemaCache.get(cacheKey)!;
  }

  const url = `${SCHEMA_BASE_URL}/${version}/fragments/${fragmentName}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/schema+json, application/json',
        'User-Agent': 'deepadata-ddna-tools/0.2.0',
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return null;
    }

    const schema = await response.json() as Record<string, unknown>;
    remoteSchemaCache.set(cacheKey, schema);
    return schema;
  } catch {
    return null;
  }
}

/**
 * Recursively resolve $ref in a schema by inlining fragment references
 * Works with both local files and remote fetch
 */
async function resolveRefsAsync(
  schema: Record<string, unknown>,
  version: string | null,
  useRemote: boolean
): Promise<Record<string, unknown>> {
  if (typeof schema !== 'object' || schema === null) {
    return schema;
  }

  // If this node has a $ref, resolve it
  if (typeof schema['$ref'] === 'string') {
    const ref = schema['$ref'];
    let fragmentName: string | null = null;

    // Handle relative refs: "fragments/governance.json"
    if (ref.startsWith('fragments/')) {
      fragmentName = ref.replace('fragments/', '');
    }
    // Handle absolute refs: "https://deepadata.com/schemas/edm/v0.6.0/fragments/governance.json"
    else if (ref.startsWith(SCHEMA_BASE_URL) && ref.includes('/fragments/')) {
      fragmentName = ref.split('/fragments/')[1];
    }

    if (fragmentName) {
      let fragment: Record<string, unknown> | null = null;

      if (useRemote && version) {
        fragment = await fetchRemoteFragment(version, fragmentName);
      }

      if (!fragment) {
        // Fall back to bundled fragment
        try {
          const fragmentPath = join(SCHEMAS_DIR, 'fragments', fragmentName);
          fragment = JSON.parse(readFileSync(fragmentPath, 'utf-8'));
        } catch {
          return { type: 'object' };
        }
      }

      // TypeScript guard: fragment is guaranteed non-null here
      if (!fragment) {
        return { type: 'object' };
      }

      return resolveRefsAsync(fragment, version, useRemote);
    }
  }

  // Recursively resolve refs in all properties
  const resolved: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(schema)) {
    if (Array.isArray(value)) {
      resolved[key] = await Promise.all(
        value.map(async (item) =>
          typeof item === 'object' && item !== null
            ? resolveRefsAsync(item as Record<string, unknown>, version, useRemote)
            : item
        )
      );
    } else if (typeof value === 'object' && value !== null) {
      resolved[key] = await resolveRefsAsync(value as Record<string, unknown>, version, useRemote);
    } else {
      resolved[key] = value;
    }
  }
  return resolved;
}

/**
 * Synchronously resolve $ref using bundled schemas only
 */
function resolveRefsSync(
  schema: Record<string, unknown>,
  schemasDir: string
): Record<string, unknown> {
  if (typeof schema !== 'object' || schema === null) {
    return schema;
  }

  // If this node has a $ref, resolve it
  if (typeof schema['$ref'] === 'string') {
    const ref = schema['$ref'];
    let fragmentPath: string | null = null;

    // Handle relative refs: "fragments/governance.json"
    if (ref.startsWith('fragments/')) {
      fragmentPath = join(schemasDir, ref);
    }
    // Handle absolute refs: "https://deepadata.com/schemas/edm/v0.6.0/fragments/governance.json"
    else if (ref.startsWith(SCHEMA_BASE_URL) && ref.includes('/fragments/')) {
      const fragmentName = ref.split('/fragments/')[1];
      fragmentPath = join(schemasDir, 'fragments', fragmentName);
    }

    if (fragmentPath) {
      try {
        const fragment = JSON.parse(readFileSync(fragmentPath, 'utf-8'));
        return resolveRefsSync(fragment, schemasDir);
      } catch {
        return { type: 'object' };
      }
    }
  }

  const resolved: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(schema)) {
    if (Array.isArray(value)) {
      resolved[key] = value.map((item) =>
        typeof item === 'object' && item !== null
          ? resolveRefsSync(item as Record<string, unknown>, schemasDir)
          : item
      );
    } else if (typeof value === 'object' && value !== null) {
      resolved[key] = resolveRefsSync(value as Record<string, unknown>, schemasDir);
    } else {
      resolved[key] = value;
    }
  }
  return resolved;
}

/**
 * Load and compile schema for a given profile (bundled fallback only)
 */
function getBundledValidator(profile: EdmProfile): Ajv {
  const cacheKey = `bundled/${profile}`;

  if (validatorCache.has(cacheKey)) {
    return validatorCache.get(cacheKey)!;
  }

  const ajv = new Ajv({
    allErrors: true,
    strict: false,
  });
  addFormats(ajv);

  const schemaPath = join(SCHEMAS_DIR, SCHEMA_FILES[profile]);
  const rawSchema = JSON.parse(readFileSync(schemaPath, 'utf-8'));
  const resolvedSchema = resolveRefsSync(rawSchema, SCHEMAS_DIR);

  ajv.addSchema(resolvedSchema, profile);
  validatorCache.set(cacheKey, ajv);

  return ajv;
}

/**
 * Load and compile schema from remote or bundled source
 */
async function getValidatorAsync(
  version: string | null,
  profile: EdmProfile
): Promise<{ ajv: Ajv; source: 'remote' | 'bundled' }> {
  // Try remote first if we have a version
  if (version) {
    const cacheKey = `${version}/${profile}`;

    if (validatorCache.has(cacheKey)) {
      return { ajv: validatorCache.get(cacheKey)!, source: 'remote' };
    }

    const remoteSchema = await fetchRemoteSchema(version, profile);

    if (remoteSchema) {
      const ajv = new Ajv({
        allErrors: true,
        strict: false,
      });
      addFormats(ajv);

      const resolvedSchema = await resolveRefsAsync(remoteSchema, version, true);
      ajv.addSchema(resolvedSchema, profile);
      validatorCache.set(cacheKey, ajv);

      return { ajv, source: 'remote' };
    }
  }

  // Fall back to bundled
  return { ajv: getBundledValidator(profile), source: 'bundled' };
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
 * Attempts to fetch the schema from the canonical URL based on
 * artifact.meta.version and artifact.meta.profile. Falls back to
 * bundled schemas if the remote fetch fails.
 *
 * @param artifact - The EDM artifact to validate
 * @returns Validation result with profile, errors, and schema source
 * @throws Error if profile cannot be detected
 */
export async function validateEdmSchema(artifact: unknown): Promise<SchemaValidationResult> {
  // Detect profile
  const profile = detectProfile(artifact);
  if (!profile) {
    throw new Error(
      'Cannot validate: meta.profile is missing or invalid. ' +
        "Expected 'essential', 'extended', or 'full'."
    );
  }

  // Extract version for remote URL
  const version = extractVersion(artifact);

  // Get validator (tries remote first, falls back to bundled)
  const { ajv, source } = await getValidatorAsync(version, profile);
  const validate = ajv.getSchema(profile);

  if (!validate) {
    throw new Error(`Schema not loaded for profile: ${profile}`);
  }

  // Validate
  const valid = validate(artifact) as boolean;

  if (valid) {
    return { valid: true, profile, errors: [], schemaSource: source };
  }

  // Map Ajv errors to our format
  const errors: SchemaValidationError[] = (validate.errors || []).map((err) => ({
    path: err.instancePath || '/',
    message: err.message || 'Unknown validation error',
    keyword: err.keyword,
  }));

  return { valid: false, profile, errors, schemaSource: source };
}

/**
 * Synchronous validation using bundled schemas only.
 * Use this when you cannot use async/await.
 */
export function validateEdmSchemaSync(artifact: unknown): SchemaValidationResult {
  const profile = detectProfile(artifact);
  if (!profile) {
    throw new Error(
      'Cannot validate: meta.profile is missing or invalid. ' +
        "Expected 'essential', 'extended', or 'full'."
    );
  }

  const ajv = getBundledValidator(profile);
  const validate = ajv.getSchema(profile);

  if (!validate) {
    throw new Error(`Schema not loaded for profile: ${profile}`);
  }

  const valid = validate(artifact) as boolean;

  if (valid) {
    return { valid: true, profile, errors: [], schemaSource: 'bundled' };
  }

  const errors: SchemaValidationError[] = (validate.errors || []).map((err) => ({
    path: err.instancePath || '/',
    message: err.message || 'Unknown validation error',
    keyword: err.keyword,
  }));

  return { valid: false, profile, errors, schemaSource: 'bundled' };
}

/**
 * Format validation errors for display
 */
export function formatValidationErrors(result: SchemaValidationResult): string {
  if (result.valid) {
    return `✓ Valid EDM artifact (${result.profile} profile, ${result.schemaSource} schema)`;
  }

  const lines = [
    `✗ Invalid EDM artifact (${result.profile} profile, ${result.schemaSource} schema)`,
    '',
    'Errors:',
    ...result.errors.map(
      (e) => `  ${e.path}: ${e.message} [${e.keyword}]`
    ),
  ];

  return lines.join('\n');
}
