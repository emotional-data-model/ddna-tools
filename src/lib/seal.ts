/**
 * Sealing: EDM artifact -> .ddna envelope
 * Implements W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 *
 * Local self-sealing — no external API required.
 * Any party may seal artifacts with their own Ed25519 keys.
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import canonicalize from 'canonicalize';
import { base58btc } from 'multiformats/bases/base58';
import { isValidDidUrl } from './did.js';
import { validateEdmSchemaSync } from './validate-schema.js';
import type {
  EdmPayload,
  DdnaHeader,
  DdnaEnvelope,
  DataIntegrityProof,
  ProofOptions,
  SigningDocument,
} from './types.js';

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

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

/**
 * Error thrown when signing key is missing
 */
export class SealingKeyError extends Error {
  constructor(message?: string) {
    super(
      message ||
      'No signing key provided.\n' +
      'Run: ddna keygen --output mykey\n' +
      'Then: ddna seal --key mykey.key ...'
    );
    this.name = 'SealingKeyError';
  }
}

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

  // Full schema validation against profile (sync version for pre-seal validation)
  const result = validateEdmSchemaSync(payload);
  if (!result.valid) {
    throw new SchemaValidationError(result.profile, result.errors);
  }
}

/**
 * Seal options for customizing the sealing process
 */
export interface SealOptions {
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
 * Build ddna_header from EDM payload
 */
function buildDdnaHeader(edmPayload: EdmPayload, overrides?: Partial<DdnaHeader>): DdnaHeader {
  const meta = edmPayload.meta || {};
  const governance = edmPayload.governance as Record<string, unknown> || {};

  // Extract profile from meta
  const profile = (meta as Record<string, unknown>).profile as string || 'full';

  // Build header with defaults and EDM payload values
  const header: DdnaHeader = {
    ddna_version: '1.1',
    created_at: new Date().toISOString(),
    edm_version: (meta as Record<string, unknown>).version as string || '0.6.0',
    owner_user_id: meta.owner_user_id || null,
    exportability: (governance.exportability as DdnaHeader['exportability']) || 'allowed',
    jurisdiction: (governance.jurisdiction as string) || 'XX',
    payload_type: `edm.v0.6.${profile}`,
    consent_basis: meta.consent_basis || 'consent',
    retention_policy: (governance.retention_policy as DdnaHeader['retention_policy']) || {
      basis: 'user_defined',
      ttl_days: null,
      on_expiry: 'soft_delete',
    },
    masking_rules: (governance.masking_rules as string[]) || [],
    audit_chain: [{
      timestamp: new Date().toISOString(),
      event: 'created',
      agent: 'ddna-tools',
    }],
  };

  // Apply overrides
  if (overrides) {
    Object.assign(header, overrides);
  }

  return header;
}

/**
 * Compute the signing input from document and proof options
 * Follows W3C Data Integrity eddsa-jcs-2022 specification
 */
function computeSigningInput(
  proofOptions: ProofOptions,
  document: SigningDocument
): Uint8Array {
  // Canonicalize both objects with JCS (RFC 8785)
  const canonicalProofOptions = canonicalize(proofOptions);
  const canonicalDocument = canonicalize(document);

  if (!canonicalProofOptions || !canonicalDocument) {
    throw new Error('Canonicalization failed during signing');
  }

  // Hash each canonical form with SHA-256
  const proofOptionsHash = sha256(new TextEncoder().encode(canonicalProofOptions));
  const documentHash = sha256(new TextEncoder().encode(canonicalDocument));

  // Concatenate hashes (64 bytes total)
  const signingInput = new Uint8Array(64);
  signingInput.set(proofOptionsHash, 0);
  signingInput.set(documentHash, 32);

  return signingInput;
}

/**
 * Seal an EDM payload into a .ddna envelope
 *
 * Local self-sealing with Ed25519. No external API required.
 *
 * @param edmPayload - The EDM artifact to seal
 * @param privateKey - 32-byte Ed25519 private key
 * @param verificationMethod - DID URL for the verification method (e.g., did:key:z6Mk...)
 * @param options - Optional sealing options
 * @returns Sealed .ddna envelope
 * @throws SealingKeyError if no key is provided
 * @throws SchemaValidationError if payload validation fails
 */
export async function seal(
  edmPayload: object,
  privateKey: Uint8Array,
  verificationMethod: string,
  options?: SealOptions
): Promise<DdnaEnvelope> {
  // Step 1: Validate inputs
  if (!privateKey || privateKey.length === 0) {
    throw new SealingKeyError();
  }

  validateEdmPayload(edmPayload);

  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${privateKey.length}`);
  }

  if (!isValidDidUrl(verificationMethod)) {
    throw new Error(`Invalid verification method: ${verificationMethod}`);
  }

  // Step 2: Build ddna_header
  const ddnaHeader = buildDdnaHeader(edmPayload as EdmPayload, options?.header);

  // Step 3: Create the document to sign (without proof)
  const document: SigningDocument = {
    ddna_header: ddnaHeader,
    edm_payload: edmPayload as EdmPayload,
  };

  // Step 4: Create proof options (all fields except proofValue)
  const created = options?.created || new Date().toISOString();
  const proofOptions: ProofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created,
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };

  // Add optional proof fields
  if (options?.expires) {
    (proofOptions as DataIntegrityProof).expires = options.expires;
  }
  if (options?.domain) {
    (proofOptions as DataIntegrityProof).domain = options.domain;
  }
  if (options?.challenge) {
    (proofOptions as DataIntegrityProof).challenge = options.challenge;
  }
  if (options?.nonce) {
    (proofOptions as DataIntegrityProof).nonce = options.nonce;
  }

  // Step 5: Compute signing input
  const signingInput = computeSigningInput(proofOptions, document);

  // Step 6: Sign with Ed25519
  const signature = await ed25519.signAsync(signingInput, privateKey);

  // Step 7: Encode signature as multibase base58-btc (prefix 'z')
  const proofValue = base58btc.encode(signature);

  // Step 8: Assemble complete proof
  const proof: DataIntegrityProof = {
    ...proofOptions,
    proofValue,
  };

  // Step 9: Assemble and return envelope
  const envelope: DdnaEnvelope = {
    ddna_header: ddnaHeader,
    edm_payload: edmPayload as EdmPayload,
    proof,
  };

  return envelope;
}

/**
 * Synchronous version of seal for environments that support it
 *
 * @param edmPayload - The EDM artifact to seal
 * @param privateKey - 32-byte Ed25519 private key
 * @param verificationMethod - DID URL for the verification method
 * @param options - Optional sealing options
 * @returns Sealed .ddna envelope
 */
export function sealSync(
  edmPayload: object,
  privateKey: Uint8Array,
  verificationMethod: string,
  options?: SealOptions
): DdnaEnvelope {
  // Step 1: Validate inputs
  if (!privateKey || privateKey.length === 0) {
    throw new SealingKeyError();
  }

  validateEdmPayload(edmPayload);

  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${privateKey.length}`);
  }

  if (!isValidDidUrl(verificationMethod)) {
    throw new Error(`Invalid verification method: ${verificationMethod}`);
  }

  // Step 2: Build ddna_header
  const ddnaHeader = buildDdnaHeader(edmPayload as EdmPayload, options?.header);

  // Step 3: Create the document to sign (without proof)
  const document: SigningDocument = {
    ddna_header: ddnaHeader,
    edm_payload: edmPayload as EdmPayload,
  };

  // Step 4: Create proof options
  const created = options?.created || new Date().toISOString();
  const proofOptions: ProofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created,
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };

  // Add optional proof fields
  if (options?.expires) {
    (proofOptions as DataIntegrityProof).expires = options.expires;
  }
  if (options?.domain) {
    (proofOptions as DataIntegrityProof).domain = options.domain;
  }
  if (options?.challenge) {
    (proofOptions as DataIntegrityProof).challenge = options.challenge;
  }
  if (options?.nonce) {
    (proofOptions as DataIntegrityProof).nonce = options.nonce;
  }

  // Step 5: Compute signing input
  const signingInput = computeSigningInput(proofOptions, document);

  // Step 6: Sign with Ed25519 (sync)
  const signature = ed25519.sign(signingInput, privateKey);

  // Step 7: Encode signature as multibase base58-btc
  const proofValue = base58btc.encode(signature);

  // Step 8: Assemble complete proof
  const proof: DataIntegrityProof = {
    ...proofOptions,
    proofValue,
  };

  // Step 9: Assemble and return envelope
  const envelope: DdnaEnvelope = {
    ddna_header: ddnaHeader,
    edm_payload: edmPayload as EdmPayload,
    proof,
  };

  return envelope;
}
