/**
 * OpenAI Extractor
 * Uses OpenAI GPT models to extract emotional data from content
 * Supports profile-aware extraction (essential/extended/full)
 *
 * Partner profiles are intentionally excluded per ADR-0023.
 */
import OpenAI from 'openai';
import type { ChatCompletionContentPart } from 'openai/resources/chat/completions.js';
import type { EdmProfile, ExtractionInput, LlmExtractionResult, LlmExtractedFields } from './types.js';
import { EXTRACTION_SYSTEM_PROMPT } from './llm-extractor.js';
import { getProfilePrompt, calculateProfileConfidence } from './profile-prompts.js';
import { consumeStance } from './stance-guard.js';

/**
 * Extract EDM fields from content using OpenAI
 */
export async function extractWithOpenAI(
  client: OpenAI,
  input: ExtractionInput,
  model: string = 'gpt-4o-mini',
  temperature: number = 0,
  profile: EdmProfile = 'full'
): Promise<LlmExtractionResult> {
  const userContent: ChatCompletionContentPart[] = [];

  // Add text content
  if (input.text) {
    userContent.push({
      type: 'text',
      text: input.text,
    });
  }

  // Add image if provided (OpenAI uses image_url with data URI)
  if (input.image) {
    const mediaType = input.imageMediaType ?? 'image/jpeg';
    userContent.push({
      type: 'image_url',
      image_url: {
        url: `data:${mediaType};base64,${input.image}`,
      },
    });
  }

  // Select profile-specific prompt or use full extraction prompt
  const profilePrompt = getProfilePrompt(profile);
  const systemPrompt = profilePrompt ?? EXTRACTION_SYSTEM_PROMPT;

  const response = await client.chat.completions.create({
    model,
    max_tokens: 4096,
    response_format: { type: 'json_object' },
    temperature,
    messages: [
      {
        role: 'system',
        content: systemPrompt,
      },
      {
        role: 'user',
        content: userContent,
      },
    ],
  });

  // Extract text response
  const text = response.choices[0]?.message?.content;
  if (!text) {
    throw new Error('No text response from OpenAI');
  }

  // Parse JSON response (strip markdown code fences if present)
  let jsonText = text.trim();
  const fenceMatch = jsonText.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?\s*```$/);
  if (fenceMatch?.[1]) {
    jsonText = fenceMatch[1].trim();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new Error(`Failed to parse OpenAI response as JSON: ${text.slice(0, 200)}...`);
  }

  // Calculate profile-aware confidence (pre-guard, matching SDK semantics)
  const confidence = calculateProfileConfidence(
    parsed as Record<string, Record<string, unknown>>,
    profile
  );

  // Consume experiential_stance and apply the deterministic attribution guard
  const guard = consumeStance(parsed as Record<string, unknown>);

  return {
    extracted: parsed as LlmExtractedFields,
    confidence,
    model,
    profile,
    notes: guard.note,
    experientialStance: guard.stance,
    stanceFieldsCleared: guard.fieldsCleared,
  };
}

/**
 * Create an OpenAI client
 */
export function createOpenAIClient(apiKey?: string): OpenAI {
  const key = apiKey ?? process.env['OPENAI_API_KEY'];
  if (!key) {
    throw new Error(
      'OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass apiKey directly.'
    );
  }
  return new OpenAI({ apiKey: key });
}
