/**
 * LLM Extractor
 * Uses Anthropic Claude to extract emotional data from content
 * Supports profile-aware extraction with canonical profiles only
 *
 * Partner profiles are intentionally excluded per ADR-0023.
 * Partner profile extraction requires DeepaData API or registry resolution.
 */
import Anthropic from '@anthropic-ai/sdk';
import type { EdmProfile, ExtractionInput, LlmExtractionResult, LlmExtractedFields } from './types.js';
import { getProfilePrompt, calculateProfileConfidence } from './profile-prompts.js';

/**
 * System prompt for EDM extraction (Full Profile)
 * See EDM specification for schema changes per version
 */
export const EXTRACTION_SYSTEM_PROMPT = `
You classify emotionally rich memories into a JSON object. Input may include text and an image.

Rules
- Fuse text + image. Treat text as primary; use image only to add grounded specifics (place, event, symbols, people).
- Keep fields to single words or short phrases (1–3 words). Only "narrative" is multi-sentence (3–5).
- No invention. If not supported by input, use null.
- Always include every top-level key and sub-key from the schema, even if the value is null or an empty array.
- Do not omit fields; if unknown, return null.
- Output JSON only — no commentary, markdown, or extra text.
- If motivation is ambiguous, choose the most conservative option (e.g., "curiosity" vs "fear") or return null.

SUBJECT ANCHORING (critical)
- The SUBJECT is the person this artifact will belong to. In a chat transcript the SUBJECT is the USER speaker; ASSISTANT text is context only, never a source of the subject's experience.
- Score every field relative to the SUBJECT, not the passage. emotional_weight measures what this content meant TO THE SUBJECT — not how vivid, dramatic, or emotionally rich the text itself is.
- Routine work content (debugging, drafting, planning, logistics) is 0.1–0.4 even when the subject expresses momentary relief or frustration. Reserve 0.7+ for events with personal stakes the subject states or plainly carries. Do not invent somatic or emotional detail the subject never expressed.
- transformational_pivot is true ONLY if the subject explicitly marks the experience as life-changing. Finishing a task, fixing a bug, or shipping a feature is not a transformational pivot.

EXPERIENTIAL STANCE (critical)
Classify whose experience the emotionally salient material is, in the top-level "experiential_stance" key:
- "lived" — the subject's own first-hand experience
- "witnessed" — events the subject personally witnessed or is directly affected by (a loved one's death, a family crisis)
- "quoted_third_party" — someone else's story the subject quoted, pasted, or retold without being a participant (an article, test data, a stranger's anecdote)
- "assistant_generated" — fiction, examples, or anecdotes produced by the assistant, not reported by the subject
- "hypothetical" — imagined scenarios, drafts about invented people, role-play
If the stance is quoted_third_party, assistant_generated, or hypothetical: do NOT encode that material into wound, identity_thread, expressed_insight, somatic_signature, transformational_pivot, the impulse domain, or high emotional_weight — those fields describe the SUBJECT. Extract only what the content reveals about the subject themselves (e.g. why they engaged with it), or return null fields with low weight.

CRITICAL: Enum Field Constraints
- Many fields below have CANONICAL values — preferred values for cross-artifact comparability.
- Use canonical values where they fit. If no canonical value accurately represents the content, use the most accurate free-text term. Accuracy takes precedence over canonical conformance.
- Cross-contamination warning: Each enum field has its own distinct value set. Do not use values from one field in another.
  Example: "milestone" is valid for memory_type but NOT for narrative_arc.
  Example: "confront" is valid for both drive_state and coping_style - check which field you're populating.
- emotion_primary, narrative_arc, relational_dynamics, and arc_type accept free text if no canonical value fits.
- arc_type canonical values use underscores not spaces. Use moral_awakening not moral awakening. Canonical values must match exactly as listed — no spaces, no variations.

Normalization (very important)
- Emit lowercase for all string fields except proper names in arrays like associated_people.
- For array fields (emotion_subtone, recall_triggers, retrieval_keys, nearby_themes, resilience_markers, associated_people):
  • use short tokens/phrases without punctuation;
  • avoid duplicates;
  • prefer singular nouns where reasonable ("tradition" not "traditions").
- Never put boolean-like strings ("true"/"false") into fields that are boolean; use real booleans.

Schema
{
  "experiential_stance": "",   // STRICT ENUM: lived | witnessed | quoted_third_party | assistant_generated | hypothetical (pick ONE or null)
  "core": {
    "anchor": "",            // central theme (e.g., "dad's toolbox", "nana's traditions")
    "spark": "",             // what triggered the memory (e.g., "finding the cassette", "first snow")
    "wound": "",             // The specific vulnerability, loss, or pain present — NOT generic labels like 'loss' or 'grief' but what exactly was lost or why it hurts. Examples: 'unlived travel dream', 'war silence never spoken', 'father died before I knew him', 'shame of not fitting in'. If no wound is present, use null.
    "fuel": "",              // what energized the experience (e.g., "shared laughter", "curiosity")
    "bridge": "",            // connection between past and present (e.g., "replaying old tape", "returning to the porch")
    "echo": "",              // what still resonates (e.g., "her laugh", "smell of oil", "city lights on water")
    "narrative": ""          // 3–5 sentences. REQUIRED: include ALL of the following — ≥1 concrete sensory detail (sight, sound, smell, texture), ≥1 temporal cue that anchors the memory in time, ≥1 symbolic callback that connects past to present. Write from the subject's perspective. Do not compress or summarise — give the memory space to breathe. Faithful and specific. Never generic.
  },
  "constellation": {
    "emotion_primary": "",           // CANONICAL: joy | sadness | fear | anger | wonder | peace | tenderness | reverence | pride | anxiety | gratitude | longing | hope | shame | disappointment | relief | frustration (free text accepted if none fits)
    "emotion_subtone": [],           // 2–4 short words (e.g., bittersweet, grateful) — free text array
    "higher_order_emotion": "",      // free text: e.g., awe, forgiveness, pride, moral_elevation (or null)
    "meta_emotional_state": "",      // free text: e.g., acceptance, confusion, curiosity (or null)
    "interpersonal_affect": "",      // free text: e.g., warmth, openness, defensiveness (or null)
    "narrative_arc": "",             // CANONICAL: overcoming | transformation | connection | reflection | closure | loss | confrontation (free text accepted if none fits)
    "relational_dynamics": "",       // CANONICAL: parent_child | grandparent_grandchild | romantic_partnership | couple | sibling_bond | family | friendship | friend | companionship | colleague | mentorship | reunion | community_ritual | grief | self_reflection | professional | therapeutic | service | adversarial (free text accepted if none fits)
    "temporal_context": "",          // STRICT ENUM: childhood | early_adulthood | midlife | late_life | recent | future | timeless (pick ONE or null)
    "memory_type": "",               // STRICT ENUM: legacy_artifact | fleeting_moment | milestone | reflection | formative_experience (pick ONE or null)
    "media_format": "",              // photo, video, audio, text, photo_with_story (or null)
    "narrative_archetype": "",       // STRICT ENUM: hero | caregiver | seeker | sage | lover | outlaw | innocent | orphan | magician | creator | everyman | jester | ruler | mentor (pick ONE or null; lowercase)
    "symbolic_anchor": "",           // concrete object/place/ritual (or null)
    "relational_perspective": "",    // STRICT ENUM: self | partner | family | friends | community | humanity (pick ONE or null)
    "temporal_rhythm": "",           // STRICT ENUM: still | sudden | rising | fading | recurring | spiraling | dragging | suspended | looping | cyclic (pick ONE or null)
    "identity_thread": "",           // short sentence
    "expressed_insight": "",         // brief insight explicitly stated by subject (extracted, not inferred)
    "transformational_pivot": false, // true if subject explicitly identifies this as life-changing
    "somatic_signature": "",         // bodily sensations explicitly described (e.g., "chest tightness", "warmth spreading") or null
    "arc_type": ""                   // CANONICAL: betrayal | liberation | grief | discovery | resistance | bond | moral_awakening | transformation | reconciliation | reckoning | threshold | exile | gratitude | authenticity (free text accepted if none fits). gratitude = moments of thankfulness, appreciation, acknowledging blessing; authenticity = feeling fully oneself, self-alignment, identity congruence
  },
  "milky_way": {
    "event_type": "",                // e.g., family gathering, farewell, birthday (or null)
    "location_context": "",          // place from text or image (or null)
    "associated_people": [],         // names or roles (proper case allowed)
    "visibility_context": "",        // STRICT ENUM: private | family_only | shared_publicly (pick ONE or null)
    "tone_shift": ""                 // e.g., loss to gratitude (or null)
  },
  "gravity": {
    "emotional_weight": 0.0,         // 0.0–1.0 (felt intensity IN THE MOMENT). Calibration: 0.9+ life-altering irreversible moments; 0.7-0.9 significant personal events with strong emotional response; 0.4-0.7 meaningful but routine emotional experiences; 0.1-0.4 mild passing emotional content
    "emotional_density": "",         // STRICT ENUM: low | medium | high (pick ONE or null)
    "valence": "",                   // STRICT ENUM: positive | negative | mixed (pick ONE or null)
    "viscosity": "",                 // STRICT ENUM: low | medium | high | enduring | fluid (pick ONE or null)
    "gravity_type": "",              // short phrase (e.g., symbolic resonance)
    "tether_type": "",               // STRICT ENUM: person | symbol | event | place | ritual | object | tradition | identity | self (pick ONE or null)
    "recall_triggers": [],           // sensory or symbolic cues (lowercase tokens)
    "retrieval_keys": [],            // compact hooks (3–6 tokens recommended)
    "nearby_themes": [],             // adjacent concepts
    "recurrence_pattern": "",        // STRICT ENUM: cyclical | isolated | chronic | emerging (pick ONE or null)
    "strength_score": 0.0,           // 0.0–1.0 (how BOUND/STUCK this memory is)
    "temporal_decay": "",            // STRICT ENUM: fast | moderate | slow (pick ONE or null)
    "resilience_markers": [],        // 1–3 (e.g., acceptance, optimism, continuity)
    "adaptation_trajectory": ""      // STRICT ENUM: improving | stable | declining | integrative | emerging (pick ONE or null)
  },
  "impulse": {
    "primary_energy": "",              // free text: e.g., curiosity, fear, compassion (or null; lowercase)
    "drive_state": "",                 // STRICT ENUM: explore | approach | avoid | repair | persevere | share | confront | protect | process (pick ONE or null)
    "motivational_orientation": "",    // STRICT ENUM: belonging | safety | mastery | meaning | autonomy (pick ONE or null)
    "temporal_focus": "",              // STRICT ENUM: past | present | future (pick ONE or null)
    "directionality": "",              // STRICT ENUM: inward | outward | transcendent (pick ONE or null)
    "social_visibility": "",           // STRICT ENUM: private | relational | collective (pick ONE or null)
    "urgency": "",                     // STRICT ENUM: calm | elevated | pressing | acute (pick ONE or null)
    "risk_posture": "",                // STRICT ENUM: cautious | balanced | bold (pick ONE or null)
    "agency_level": "",                // STRICT ENUM: low | medium | high (pick ONE or null)
    "regulation_state": "",            // STRICT ENUM: regulated | wavering | dysregulated (pick ONE or null)
    "attachment_style": "",            // STRICT ENUM: secure | anxious | avoidant | disorganized (pick ONE or null)
    "coping_style": ""                 // STRICT ENUM: reframe_meaning | seek_support | distract | ritualize | confront | detach | process (pick ONE or null)
  }

  // Calibration — Impulse (helps apply the fields consistently)
  // - temporal_focus: past (reminisce), present (here-and-now coping), future (plans/longing).
  // - directionality: inward (self-processing), outward (toward others), transcendent (beyond self).
  // - social_visibility: private (to self or 1:1), relational (friends/family), collective (community-wide).
  // - If uncertain, choose the most conservative option or null.

  // CROSS-CONTAMINATION DISAMBIGUATION (read carefully)
  //
  // temporal_rhythm vs urgency:
  //   - temporal_rhythm describes the CADENCE or PACE of time in the memory experience
  //     (still, sudden, rising, fading, recurring, spiraling, dragging, suspended, looping, cyclic)
  //   - urgency describes the INTENSITY of motivational pressure RIGHT NOW
  //     (calm, elevated, pressing, acute)
  //   - "pressing" belongs ONLY in urgency, NEVER in temporal_rhythm
  //
  // temporal_rhythm vs viscosity:
  //   - temporal_rhythm is about TIME MOVEMENT in the memory
  //   - viscosity is about EMOTIONAL PERSISTENCE over time
  //     (low=fleeting, medium=moderate, high=sticky, enduring=long-lasting, fluid=changeable)
  //   - "enduring" belongs ONLY in viscosity, NEVER in temporal_rhythm
  //
  // relational_dynamics vs relational_perspective:
  //   - relational_dynamics: the TYPE of relationship (parent_child, friendship, mentorship, etc.)
  //   - relational_perspective: WHOSE viewpoint the narrative is told from (self, partner, family, etc.)
  //   - "family" can appear in BOTH fields with different meanings
  //
  // drive_state vs coping_style:
  //   - drive_state: the MOTIVATIONAL direction (explore, approach, avoid, confront, etc.)
  //   - coping_style: the STRATEGY for managing emotions (reframe_meaning, seek_support, confront, etc.)
  //   - "confront" is valid in BOTH - use drive_state for action impulse, coping_style for emotion management
  //
  // emotion_primary (STRICT ENUM) vs higher_order_emotion (free text):
  //   - emotion_primary MUST be one of the 14 listed values ONLY
  //   - Do NOT put free-text emotions like "compassion", "reflection", "frustration" in emotion_primary
  //   - Use higher_order_emotion for complex emotions not in the primary list
  //
  // narrative_arc (CRITICAL - common error):
  //   - Describes the STORY TRAJECTORY (overcoming, transformation, connection, reflection, closure)
  //   - "confrontation" is NOT a valid arc — it describes an event/scene, not a trajectory
  //   - If the story involves confronting something, use "overcoming" (challenge faced and resolved)
  //     or "transformation" (fundamental change through conflict)
  //   - "confront" belongs in drive_state or coping_style, NOT in narrative_arc
  //
  // emotional_weight vs strength_score (CRITICAL - different concepts):
  //   - emotional_weight: The felt INTENSITY of the experience in the moment.
  //     A heated argument = high weight (0.8). A routine check-in = low weight (0.2).
  //   - strength_score: How BOUND/STUCK this memory is — through association, ritual, retelling, or identity.
  //     A childhood memory retold for decades = high strength (0.9) even if emotional weight was moderate.
  //     A customer complaint = may have high weight (0.8) but low strength (0.3) — intense but fades quickly.
  //   - These should NOT always correlate.
  //     Ask: "How heavy does this feel RIGHT NOW?" (weight) vs "How stuck/persistent is this memory?" (strength)
  //
  // SYNONYM CORRECTIONS (use the canonical form):
  //   - drive_state: Use "process" NOT "reflect". The enum value is "process" for internal processing/reflection.
  //   - narrative_archetype: Use "caregiver" NOT "caretaker". The Jungian archetype label is "caregiver".
}
`;

/**
 * Extract EDM fields from content using Anthropic Claude
 *
 * @param client - Anthropic client
 * @param input - Content to extract from
 * @param model - Model to use (default: claude-sonnet-4-20250514)
 * @param profile - EDM profile (default: 'full')
 */
export async function extractWithLlm(
  client: Anthropic,
  input: ExtractionInput,
  model: string = 'claude-sonnet-4-20250514',
  profile: EdmProfile = 'full'
): Promise<LlmExtractionResult> {
  const userContent: Anthropic.MessageCreateParams['messages'][0]['content'] = [];

  // Add text content
  if (input.text) {
    userContent.push({
      type: 'text',
      text: input.text,
    });
  }

  // Add image if provided
  if (input.image) {
    userContent.push({
      type: 'image',
      source: {
        type: 'base64',
        media_type: input.imageMediaType ?? 'image/jpeg',
        data: input.image,
      },
    });
  }

  // Select profile-specific prompt or use full extraction prompt
  const profilePrompt = getProfilePrompt(profile);
  const systemPrompt = profilePrompt ?? EXTRACTION_SYSTEM_PROMPT;

  const response = await client.messages.create({
    model,
    max_tokens: 4096,
    system: systemPrompt,
    messages: [
      {
        role: 'user',
        content: userContent,
      },
    ],
  });

  // Extract text response
  const textBlock = response.content.find((block) => block.type === 'text');
  if (!textBlock || textBlock.type !== 'text') {
    throw new Error('No text response from LLM');
  }

  // Parse JSON response (strip markdown code fences if present)
  let jsonText = textBlock.text.trim();
  const fenceMatch = jsonText.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?\s*```$/);
  if (fenceMatch?.[1]) {
    jsonText = fenceMatch[1].trim();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new Error(`Failed to parse LLM response as JSON: ${textBlock.text.slice(0, 200)}...`);
  }

  // Calculate profile-aware confidence
  const confidence = calculateProfileConfidence(
    parsed as Record<string, Record<string, unknown>>,
    profile
  );

  return {
    extracted: parsed as LlmExtractedFields,
    confidence,
    model,
    profile,
    notes: null,
  };
}

/**
 * Calculate extraction confidence based on field population (full profile)
 */
export function calculateConfidence(extracted: Record<string, Record<string, unknown>>): number {
  const weights = {
    core: 0.25,
    constellation: 0.25,
    milky_way: 0.15,
    gravity: 0.2,
    impulse: 0.15,
  };

  let totalScore = 0;

  // Core domain
  const core = extracted.core ?? {};
  const coreFields = Object.values(core);
  const corePopulated = coreFields.filter((v) => v !== null && v !== '').length;
  totalScore += weights.core * (corePopulated / Math.max(coreFields.length, 1));

  // Constellation domain
  const constellation = extracted.constellation ?? {};
  const constellationFields = Object.keys(constellation);
  const constellationPopulated = constellationFields.filter((k) => {
    const val = constellation[k];
    return val !== null && val !== '';
  }).length;
  totalScore += weights.constellation * (constellationPopulated / Math.max(constellationFields.length, 1));

  // MilkyWay domain
  const milkyWay = extracted.milky_way ?? {};
  const milkyWayPopulated = Object.values(milkyWay).filter(
    (v) => v !== null && v !== '' && (Array.isArray(v) ? v.length > 0 : true)
  ).length;
  totalScore += weights.milky_way * (milkyWayPopulated / Math.max(Object.keys(milkyWay).length, 1));

  // Gravity domain
  const gravity = extracted.gravity ?? {};
  const gravityPopulated = Object.values(gravity).filter(
    (v) => v !== null && v !== '' && (Array.isArray(v) ? v.length > 0 : true)
  ).length;
  totalScore += weights.gravity * (gravityPopulated / Math.max(Object.keys(gravity).length, 1));

  // Impulse domain
  const impulse = extracted.impulse ?? {};
  const impulsePopulated = Object.values(impulse).filter((v) => v !== null && v !== '').length;
  totalScore += weights.impulse * (impulsePopulated / Math.max(Object.keys(impulse).length, 1));

  return Math.round(totalScore * 100) / 100;
}

/**
 * Create an Anthropic client
 */
export function createAnthropicClient(apiKey?: string): Anthropic {
  return new Anthropic({
    apiKey: apiKey ?? process.env['ANTHROPIC_API_KEY'],
  });
}
