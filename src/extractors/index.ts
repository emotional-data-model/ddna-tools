/**
 * EDM Extraction for ddna-tools
 *
 * Reference implementation for canonical profile extraction.
 * Supports Anthropic Claude, OpenAI GPT, and Kimi K2.
 *
 * Partner profiles (partner:*) are intentionally excluded per ADR-0023.
 * Partner profile extraction requires DeepaData API or registry resolution
 * per EDM specification §3.7.6.
 */

// Types
export type {
  EdmProfile,
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
} from './types.js';

// Anthropic Claude extraction
export {
  extractWithLlm,
  createAnthropicClient,
  calculateConfidence,
  EXTRACTION_SYSTEM_PROMPT,
} from './llm-extractor.js';

// OpenAI extraction
export {
  extractWithOpenAI,
  createOpenAIClient,
} from './openai-extractor.js';

// Kimi K2 extraction
export {
  extractWithKimi,
  createKimiClient,
  getKimiModelId,
} from './kimi-extractor.js';

// Profile prompts and utilities
export {
  ESSENTIAL_PROFILE_PROMPT,
  EXTENDED_PROFILE_PROMPT,
  getProfilePrompt,
  calculateProfileConfidence,
  PROFILE_REQUIRED_FIELDS,
} from './profile-prompts.js';
