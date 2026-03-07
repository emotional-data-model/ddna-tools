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
import { sha256 } from '@noble/hashes/sha256';
import canonicalize from 'canonicalize';
import { base58btc } from 'multiformats/bases/base58';
import { isValidDidUrl } from './did.js';
import type {
  EdmPayload,
  DdnaHeader,
  DdnaEnvelope,
  SigningDocument,
  ProofOptions,
  DataIntegrityProof,
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

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

/**
 * Deep clone an object using JSON serialization
 * This ensures the envelope payload is isolated from the input
 */
function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Validate EDM payload structure
 *
 * @param payload - EDM payload to validate
 * @throws Error if payload is invalid
 */
function validateEdmPayload(payload: unknown): asserts payload is EdmPayload {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid EDM payload: must be an object');
  }

  const p = payload as Record<string, unknown>;

  // Check for required domains (meta and core are typically required)
  if (!p.meta || typeof p.meta !== 'object') {
    throw new Error("Invalid EDM payload: missing required domain 'meta'");
  }

  if (!p.core || typeof p.core !== 'object') {
    throw new Error("Invalid EDM payload: missing required domain 'core'");
  }
}

/**
 * Extract governance fields from EDM payload to construct ddna_header
 * Uses EDM v0.4.0 canonical field names with backward compatibility
 *
 * @param payload - EDM payload
 * @param options - Optional header overrides
 * @returns Constructed ddna_header
 */
function constructDdnaHeader(
  payload: EdmPayload,
  options?: Partial<DdnaHeader>
): DdnaHeader {
  const meta = payload.meta || {};
  const governance = payload.governance as Record<string, unknown> | undefined;

  // Determine EDM version from payload
  // Canonical v0.4.0 uses meta.version, legacy uses meta.schema_version
  const rawVersion = (meta.version as string) ||
    (meta.schema_version as string) ||
    '0.4.0';
  // Normalize: strip "edm.v" prefix if present
  const edmVersion = rawVersion.replace(/^edm\.v/, '');

  // payload_type uses the full schema identifier (e.g., "edm.v0.4.0")
  const payloadType = `edm.v${edmVersion}`;

  // Extract governance info if present
  const jurisdiction = (governance?.jurisdiction as string) || options?.jurisdiction || 'UNKNOWN';
  const exportability = (governance?.exportability as DdnaHeader['exportability']) ||
    options?.exportability || 'allowed';

  // Consent basis: check meta (canonical v0.4.0 location) first
  const consentBasis = (meta.consent_basis as string) ||
    (governance?.consent_basis as string) ||
    options?.consent_basis ||
    'consent';

  // Owner ID: canonical v0.4.0 uses owner_user_id, legacy uses subject_id
  const ownerUserId = (meta.owner_user_id as string | null) ||
    (meta.subject_id as string | null) ||
    null;

  // Extract retention policy from governance if present
  const govRetention = governance?.retention_policy as Record<string, unknown> | undefined;
  const retentionPolicy: DdnaHeader['retention_policy'] = govRetention
    ? {
        basis: (govRetention.basis as DdnaHeader['retention_policy']['basis']) || 'user_defined',
        ttl_days: (govRetention.ttl_days as number | null) ?? null,
        on_expiry: (govRetention.on_expiry as DdnaHeader['retention_policy']['on_expiry']) || 'soft_delete',
      }
    : {
        basis: 'user_defined',
        ttl_days: null,
        on_expiry: 'soft_delete',
      };

  // Extract masking_rules from governance if present
  const maskingRules = (governance?.masking_rules as string[]) || [];

  const header: DdnaHeader = {
    ddna_version: '1.1',
    created_at: new Date().toISOString(),
    edm_version: edmVersion,
    owner_user_id: ownerUserId,
    exportability,
    jurisdiction,
    payload_type: payloadType,
    consent_basis: consentBasis,
    retention_policy: retentionPolicy,
    masking_rules: maskingRules,
    audit_chain: [
      {
        timestamp: new Date().toISOString(),
        event: 'created',
        agent: 'deepadata-ddna-tools/0.1.0',
      },
    ],
    ...options,
  };

  return header;
}

/**
 * Create signing input according to spec:
 * SHA-256(JCS(proof_options)) || SHA-256(JCS(document))
 *
 * @param proofOptions - Proof options (without proofValue)
 * @param document - Document to sign (ddna_header + edm_payload)
 * @returns 64-byte signing input
 */
function createSigningInput(
  proofOptions: ProofOptions,
  document: SigningDocument
): Uint8Array {
  // Step 1: Canonicalize both objects with JCS (RFC 8785)
  const canonicalProofOptions = canonicalize(proofOptions);
  const canonicalDocument = canonicalize(document);

  if (!canonicalProofOptions || !canonicalDocument) {
    throw new Error('Canonicalization failed');
  }

  // Step 2: Hash each canonical form with SHA-256
  const proofOptionsHash = sha256(new TextEncoder().encode(canonicalProofOptions));
  const documentHash = sha256(new TextEncoder().encode(canonicalDocument));

  // Step 3: Concatenate hashes (64 bytes total)
  const signingInput = new Uint8Array(64);
  signingInput.set(proofOptionsHash, 0);
  signingInput.set(documentHash, 32);

  return signingInput;
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
