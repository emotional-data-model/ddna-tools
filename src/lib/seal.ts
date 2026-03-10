/**
 * Sealing: EDM artifact -> .ddna envelope
 * Implements W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 *
 * IMPORTANT: seal() requires a DeepaData API key.
 * Get one at https://deepadata.com/api-keys
 * See https://deepadata.com/pricing for current rates.
 *
 * Free functions (no API key): verify(), inspect(), keygen(), validate(), redact()
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { isValidDidUrl } from './did.js';
import { validateEdmSchema } from './validate-schema.js';
import type {
  EdmPayload,
  DdnaHeader,
  DdnaEnvelope,
} from './types.js';

// API endpoint for commercial sealing
const DEEPADATA_SEAL_API = 'https://api.deepadata.com/v1/seal';

/**
 * Error thrown when API key is missing or invalid
 */
export class SealingApiKeyError extends Error {
  constructor() {
    super(
      'Sealing requires a DeepaData API key.\n' +
        'Get one at https://deepadata.com/api-keys\n' +
        'See https://deepadata.com/pricing for current rates.\n\n' +
        'verify() and inspect() are always free.'
    );
    this.name = 'SealingApiKeyError';
  }
}

/**
 * Error thrown when the sealing API returns an error
 */
export class SealingApiError extends Error {
  public statusCode: number;
  public apiMessage: string;

  constructor(statusCode: number, apiMessage: string) {
    super(`Sealing API error (${statusCode}): ${apiMessage}`);
    this.name = 'SealingApiError';
    this.statusCode = statusCode;
    this.apiMessage = apiMessage;
  }
}

/**
 * Error thrown when schema validation fails
 */
export class SchemaValidationError extends Error {
  public profile: string;
  public validationErrors: Array<{ path: string; message: string; keyword: string }>;

  constructor(
    profile: string,
    errors: Array<{ path: string; message: string; keyword: string }>
  ) {
    const summary = errors.slice(0, 3).map(e => `${e.path}: ${e.message}`).join('; ');
    const more = errors.length > 3 ? ` (+${errors.length - 3} more)` : '';
    super(`EDM schema validation failed (${profile} profile): ${summary}${more}`);
    this.name = 'SchemaValidationError';
    this.profile = profile;
    this.validationErrors = errors;
  }
}

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

/**
 * Validate EDM payload against profile schema
 *
 * Reads meta.profile to determine which schema to use (essential, extended, full).
 * Validates against bundled EDM v0.6.0 JSON Schema files.
 *
 * @param payload - EDM payload to validate
 * @throws SchemaValidationError if validation fails
 * @throws Error if payload structure is invalid or profile is missing
 */
function validateEdmPayload(payload: unknown): asserts payload is EdmPayload {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid EDM payload: must be an object');
  }

  const p = payload as Record<string, unknown>;

  // Basic structure check
  if (!p.meta || typeof p.meta !== 'object') {
    throw new Error("Invalid EDM payload: missing required domain 'meta'");
  }

  if (!p.core || typeof p.core !== 'object') {
    throw new Error("Invalid EDM payload: missing required domain 'core'");
  }

  // Full schema validation against profile
  const result = validateEdmSchema(payload);
  if (!result.valid) {
    throw new SchemaValidationError(result.profile, result.errors);
  }
}

/**
 * Seal options for customizing the sealing process
 */
export interface SealOptions {
  /**
   * DeepaData API key (required)
   * Get one at https://deepadata.com/api-keys
   * Also reads from DEEPADATA_API_KEY environment variable
   */
  apiKey?: string;
  /** Override ddna_header fields */
  header?: Partial<DdnaHeader>;
  /** Optional proof expiration (ISO 8601) */
  expires?: string;
  /** Optional domain restriction */
  domain?: string;
  /** Optional challenge value */
  challenge?: string;
  /** Optional nonce for replay prevention */
  nonce?: string;
  /** Custom timestamp for created field (ISO 8601) */
  created?: string;
}

/**
 * Resolve API key from options or environment
 */
function resolveApiKey(options?: SealOptions): string {
  const apiKey = options?.apiKey ?? process.env['DEEPADATA_API_KEY'];
  if (!apiKey) {
    throw new SealingApiKeyError();
  }
  return apiKey;
}

/**
 * Convert Uint8Array to hex string
 */
function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Seal an EDM payload into a .ddna envelope
 *
 * REQUIRES: DeepaData API key ($0.005 per seal)
 * Set DEEPADATA_API_KEY environment variable or pass options.apiKey
 *
 * @param edmPayload - The EDM artifact to seal
 * @param privateKey - 32-byte Ed25519 private key
 * @param verificationMethod - DID URL for the verification method
 * @param options - Sealing options (apiKey required)
 * @returns Sealed .ddna envelope
 * @throws SealingApiKeyError if no API key is provided
 * @throws SealingApiError if the API returns an error
 */
export async function seal(
  edmPayload: object,
  privateKey: Uint8Array,
  verificationMethod: string,
  options?: SealOptions
): Promise<DdnaEnvelope> {
  // Step 1: Validate API key (required for commercial sealing)
  const apiKey = resolveApiKey(options);

  // Step 2: Validate inputs
  validateEdmPayload(edmPayload);

  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${privateKey.length}`);
  }

  if (!isValidDidUrl(verificationMethod)) {
    throw new Error(`Invalid verification method: ${verificationMethod}`);
  }

  // Step 3: Prepare request payload for API
  const requestPayload = {
    edm_payload: edmPayload,
    private_key_hex: uint8ArrayToHex(privateKey),
    verification_method: verificationMethod,
    options: {
      header: options?.header,
      expires: options?.expires,
      domain: options?.domain,
      challenge: options?.challenge,
      nonce: options?.nonce,
      created: options?.created,
    },
  };

  // Step 4: Call DeepaData sealing API
  const response = await fetch(DEEPADATA_SEAL_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
      'User-Agent': 'deepadata-ddna-tools/0.2.0',
    },
    body: JSON.stringify(requestPayload),
  });

  // Step 5: Handle API response
  if (!response.ok) {
    let errorMessage = 'Unknown error';
    try {
      const errorBody = (await response.json()) as { error?: string; message?: string };
      errorMessage = errorBody.error || errorBody.message || errorMessage;
    } catch {
      errorMessage = await response.text();
    }
    throw new SealingApiError(response.status, errorMessage);
  }

  // Step 6: Parse and return envelope
  const envelope = (await response.json()) as DdnaEnvelope;
  return envelope;
}

/**
 * Synchronous sealing is no longer supported.
 *
 * Sealing requires a DeepaData API key and must use the async seal() function.
 * This function is deprecated and will throw an error.
 *
 * @deprecated Use seal() instead
 * @throws Error directing users to use async seal()
 */
export function sealSync(
  _edmPayload: object,
  _privateKey: Uint8Array,
  _verificationMethod: string,
  _options?: SealOptions
): DdnaEnvelope {
  throw new Error(
    'sealSync() is no longer supported.\n' +
      'Sealing requires a DeepaData API key and must use the async seal() function.\n' +
      'Get an API key at https://deepadata.com/api-keys'
  );
}
