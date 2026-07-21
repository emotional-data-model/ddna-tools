/**
 * ddna-tools
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
 * - validate() — schema validation against the bundled EDM v0.8-line schema
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

// EDM version truth — derived from the installed edm-spec package
export {
  EDM_VERSION,
  EDM_VERSION_LINE,
  EDM_SCHEMA_URL_VERSION,
  EDM_VERSION_LABEL,
} from './edm-version.js';

// EDM profile schema validation (bundled v0.8-line schemas)
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

// Experiential-stance attribution guard (deterministic, always on)
export {
  EXPERIENTIAL_STANCE,
  isNonSubjectStance,
  takeStance,
  applyStanceGuard,
  consumeStance,
} from '../extractors/stance-guard.js';

export type { ExperientialStance, StanceGuardResult } from '../extractors/stance-guard.js';

// Profile prompts and utilities
export {
  ESSENTIAL_PROFILE_PROMPT,
  EXTENDED_PROFILE_PROMPT,
  getProfilePrompt,
  calculateProfileConfidence,
  PROFILE_REQUIRED_FIELDS,
} from '../extractors/profile-prompts.js';

// Domain extractors (artifact assembly)
export {
  EDM_SCHEMA_VERSION,
  createMeta,
  createGovernance,
  createTelemetry,
  createSystem,
  createCrosswalks,
  detectSourceType,
} from '../extractors/domain-extractors.js';

// Artifact assembler
export {
  ESSENTIAL_PROFILE_FIELDS,
  EXTENDED_PROFILE_FIELDS,
  FULL_PROFILE_FIELDS,
  getProfileFields,
  getProfileDomains,
  filterByProfile,
  assembleProfileArtifact,
} from '../extractors/assembler.js';

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

// Domain types
export type {
  Meta,
  Governance,
  Telemetry,
  System,
  Crosswalks,
  ExtractionMetadata,
} from '../extractors/domain-extractors.js';

export type { AssemblyContext } from '../extractors/assembler.js';
