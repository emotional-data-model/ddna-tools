/**
 * Stateless Mode Utilities
 * Functions for privacy-preserving artifact handling
 *
 * These functions are FREE and do not require a DeepaData API key.
 */

import type { EdmPayload } from './types.js';

/**
 * Default TTL for stateless mode (24 hours)
 */
const DEFAULT_TTL_HOURS = 24;

/**
 * Fields to null in Gravity domain for stateless mode
 */
const GRAVITY_FIELDS_TO_NULL = [
  'recall_triggers',
  'retrieval_keys',
  'nearby_themes',
] as const;

/**
 * Fields to null in Milky_Way domain for stateless mode
 */
const MILKY_WAY_FIELDS_TO_NULL = [
  'location_context',
  'associated_people',
] as const;

/**
 * Fields to null in meta domain for stateless mode
 */
const META_FIELDS_TO_NULL = [
  'owner_user_id',
  'source_context',
] as const;

/**
 * Redaction result with statistics
 */
export interface RedactionResult {
  /** The redacted artifact */
  artifact: EdmPayload;
  /** Number of fields that were nulled */
  fieldsRedacted: number;
  /** List of field paths that were redacted */
  redactedPaths: string[];
}

/**
 * TTL check result
 */
export interface TtlResult {
  /** Whether the artifact has expired */
  expired: boolean;
  /** Age of the artifact in hours */
  ageHours: number;
  /** TTL threshold in hours */
  ttlHours: number;
  /** Time remaining before expiry (negative if expired) */
  hoursRemaining: number;
  /** Created timestamp from artifact */
  createdAt: string | null;
}

/**
 * Deep clone an object
 */
function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Redact an EDM artifact for stateless mode
 *
 * Nulls sensitive fields:
 * - All Gravity domain fields (recall_triggers, retrieval_keys, nearby_themes)
 * - All Milky_Way identifying fields (location_context, associated_people)
 * - Meta identifying fields (owner_user_id, source_context)
 *
 * FREE: Does not require a DeepaData API key.
 *
 * @param artifact - EDM artifact to redact
 * @returns Redaction result with artifact and statistics
 */
export function redact(artifact: EdmPayload): RedactionResult {
  const redacted = deepClone(artifact);
  const redactedPaths: string[] = [];

  // Redact Gravity fields
  if (redacted.gravity && typeof redacted.gravity === 'object') {
    const gravity = redacted.gravity as Record<string, unknown>;
    for (const field of GRAVITY_FIELDS_TO_NULL) {
      if (field in gravity) {
        if (Array.isArray(gravity[field])) {
          gravity[field] = [];
        } else {
          gravity[field] = null;
        }
        redactedPaths.push(`gravity.${field}`);
      }
    }
  }

  // Redact Milky_Way fields
  if (redacted.milky_way && typeof redacted.milky_way === 'object') {
    const milkyWay = redacted.milky_way as Record<string, unknown>;
    for (const field of MILKY_WAY_FIELDS_TO_NULL) {
      if (field in milkyWay) {
        if (field === 'associated_people') {
          milkyWay[field] = [];
        } else {
          milkyWay[field] = null;
        }
        redactedPaths.push(`milky_way.${field}`);
      }
    }
  }

  // Redact meta fields
  if (redacted.meta && typeof redacted.meta === 'object') {
    const meta = redacted.meta as Record<string, unknown>;
    for (const field of META_FIELDS_TO_NULL) {
      if (field in meta) {
        meta[field] = null;
        redactedPaths.push(`meta.${field}`);
      }
    }
  }

  return {
    artifact: redacted,
    fieldsRedacted: redactedPaths.length,
    redactedPaths,
  };
}

/**
 * Check if an EDM artifact has expired based on its created_at timestamp
 *
 * Default TTL is 24 hours for stateless mode.
 *
 * FREE: Does not require a DeepaData API key.
 *
 * @param artifact - EDM artifact to check
 * @param ttlHours - TTL in hours (default: 24)
 * @returns TTL check result
 */
export function isExpired(artifact: EdmPayload, ttlHours: number = DEFAULT_TTL_HOURS): TtlResult {
  // Extract created_at from meta domain
  const meta = artifact.meta;
  const createdAt = meta?.created_at as string | undefined;

  if (!createdAt) {
    // No timestamp - consider expired for safety
    return {
      expired: true,
      ageHours: Infinity,
      ttlHours,
      hoursRemaining: -Infinity,
      createdAt: null,
    };
  }

  // Parse timestamp
  const createdDate = new Date(createdAt);
  if (isNaN(createdDate.getTime())) {
    // Invalid timestamp - consider expired for safety
    return {
      expired: true,
      ageHours: Infinity,
      ttlHours,
      hoursRemaining: -Infinity,
      createdAt,
    };
  }

  // Calculate age
  const now = new Date();
  const ageMs = now.getTime() - createdDate.getTime();
  const ageHours = ageMs / (1000 * 60 * 60);
  const hoursRemaining = ttlHours - ageHours;

  return {
    expired: ageHours >= ttlHours,
    ageHours: Math.round(ageHours * 100) / 100,
    ttlHours,
    hoursRemaining: Math.round(hoursRemaining * 100) / 100,
    createdAt,
  };
}

/**
 * Check if an artifact is in stateless mode
 * (all identifying fields are null/empty)
 *
 * @param artifact - EDM artifact to check
 * @returns true if artifact appears to be in stateless mode
 */
export function isStateless(artifact: EdmPayload): boolean {
  const meta = artifact.meta as Record<string, unknown> | undefined;
  const milkyWay = artifact.milky_way as Record<string, unknown> | undefined;
  const gravity = artifact.gravity as Record<string, unknown> | undefined;

  // Check meta fields
  if (meta?.owner_user_id !== null && meta?.owner_user_id !== undefined) {
    return false;
  }

  // Check milky_way fields
  if (milkyWay?.location_context !== null && milkyWay?.location_context !== undefined) {
    return false;
  }
  const associatedPeople = milkyWay?.associated_people as unknown[] | undefined;
  if (associatedPeople && associatedPeople.length > 0) {
    return false;
  }

  // Check gravity fields
  const recallTriggers = gravity?.recall_triggers as unknown[] | undefined;
  if (recallTriggers && recallTriggers.length > 0) {
    return false;
  }
  const retrievalKeys = gravity?.retrieval_keys as unknown[] | undefined;
  if (retrievalKeys && retrievalKeys.length > 0) {
    return false;
  }

  return true;
}
