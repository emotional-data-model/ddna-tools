/**
 * ddna-tools v0.3.0
 * Reference implementation for .ddna envelope specification
 * Extraction, sealing, and verification with W3C Data Integrity Proofs
 *
 * W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 *
 * All operations are local. No external API required.
 *
 * Sealing & Verification:
 * - keygen() — generate Ed25519 key pair with DID
 * - seal() — create tamper-evident .ddna envelope (local signing)
 * - verify() — verify a sealed .ddna envelope
 * - inspect() — read envelope contents
 * - redact() — stateless mode, null sensitive fields
 * - validate() — schema validation against EDM v0.8.0
 * - isExpired() — check artifact TTL
 *
 * Extraction (v0.3.0):
 * - extractWithLlm() — Anthropic Claude extraction
 * - extractWithOpenAI() — OpenAI GPT extraction
 * - extractWithKimi() — Kimi K2 extraction
 *
 * Canonical profiles only (essential/extended/full).
 * Partner profiles require DeepaData API per EDM spec §3.7.6.
 */

// Core signing functions (local Ed25519 signing)
export { seal, sealSync, SealingKeyError, SchemaValidationError } from './seal.js';
export type { SealOptions } from './seal.js';

// Verification
export { verify, verifySync } from './verify.js';
export type { VerifyOptions } from './verify.js';

// Inspection
export { inspect, inspectEnvelope, inspectJson } from './inspect.js';

// Key generation
export { keygen, deriveKeyPair, keyToHex, hexToKey } from './keygen.js';

// Stateless mode utilities
export { redact, isExpired, isStateless } from './stateless.js';
export type { RedactionResult, TtlResult } from './stateless.js';

// Schema validation
export { validate, isValid } from './validate.js';
export type { ValidationResult, ValidationError } from './validate.js';

// EDM profile schema validation (v0.6.0)
// validateEdmSchema (async) fetches from canonical URL with bundled fallback
// validateEdmSchemaSync uses bundled schemas only (for sync contexts)
export {
  validateEdmSchema,
  validateEdmSchemaSync,
  detectProfile,
  formatValidationErrors,
} from './validate-schema.js';
export type {
  EdmProfile,
  SchemaValidationResult,
  SchemaValidationError as SchemaError,
} from './validate-schema.js';

// DID utilities
export { publicKeyToDid, didToPublicKey, isValidDidUrl, resolveVerificationMethod } from './did.js';

// Types
export type {
  DdnaEnvelope,
  DdnaHeader,
  DataIntegrityProof,
  ProofOptions,
  EdmPayload,
  EdmMeta,
  SigningDocument,
  VerifyResult,
  KeyPair,
  InspectionResult,
  RetentionPolicy,
  AuditEntry,
} from './types.js';

// =============================================================================
// Extraction (v0.3.0)
// =============================================================================

// Anthropic Claude extraction
export {
  extractWithLlm,
  createAnthropicClient,
  calculateConfidence,
  EXTRACTION_SYSTEM_PROMPT,
} from '../extractors/llm-extractor.js';

// OpenAI extraction
export {
  extractWithOpenAI,
  createOpenAIClient,
} from '../extractors/openai-extractor.js';

// Kimi K2 extraction
export {
  extractWithKimi,
  createKimiClient,
  getKimiModelId,
} from '../extractors/kimi-extractor.js';

// Profile prompts and utilities
export {
  ESSENTIAL_PROFILE_PROMPT,
  EXTENDED_PROFILE_PROMPT,
  getProfilePrompt,
  calculateProfileConfidence,
  PROFILE_REQUIRED_FIELDS,
} from '../extractors/profile-prompts.js';

// Extraction types
export type {
  EdmProfile as ExtractionProfile,
  ExtractionInput,
  LlmExtractionResult,
  LlmExtractedFields,
  Core,
  Constellation,
  MilkyWay,
  Gravity,
  Impulse,
  EssentialExtracted,
  ExtendedExtracted,
  FullExtracted,
} from '../extractors/types.js';
