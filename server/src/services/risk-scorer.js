// MCP Warden — risk scoring engine (Security Feature E).
//
// Calculates a deterministic, evidence-based security risk score (0-100)
// from actual findings, metadata drift, and tool-set discrepancies.
//
// Maximum category contributions:
//   - Suspicious descriptions: 25 points
//   - Risky source patterns:   20 points
//   - Metadata drift:          30 points
//   - Tool-set mismatch:       25 points
//   ------------------------------------
//   Total maximum:             100 points
//
// Display bands:
//   - 0-24:   Low
//   - 25-49:  Moderate
//   - 50-74:  High
//   - 75-100: Critical
//
// DESIGN PRINCIPLES:
//   1. Deterministic: the same findings always yield the exact same score.
//   2. Capped: no single category can push the score beyond its maximum.
//   3. Deduplicated: repeated identical findings do not inflate the score.
//   4. Missing baseline is distinct: an unavailable baseline is reported as
//      "Baseline unavailable", not as a verified zero-risk comparison.
//   5. Heuristic disclaimer: the score is a prioritization signal, not a
//      calibrated probability of maliciousness.

export const CATEGORY_CAPS = {
  descriptions: 25,
  sourcePatterns: 20,
  metadataDrift: 30,
  toolSetMismatch: 25,
};

// Weight assigned to individual findings by severity.
const SEVERITY_WEIGHT = {
  low: 5,
  medium: 10,
  high: 15,
  critical: 25,
};

/**
 * Map numeric score to human-readable risk level.
 * @param {number} score
 * @returns {"Low" | "Moderate" | "High" | "Critical"}
 */
export function getRiskLevel(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Moderate";
  return "Low";
}

/**
 * Deduplicate findings by (ruleId, toolName/file, line).
 * @param {object[]} findings
 * @returns {object[]}
 */
export function deduplicateFindings(findings) {
  if (!Array.isArray(findings)) return [];
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    if (!f || typeof f !== "object") continue;
    const loc = f.file ? `${f.file}:${f.line ?? 0}` : (f.toolName ?? "*");
    const key = `${f.category ?? "unknown"}::${f.ruleId ?? f.id ?? "none"}::${loc}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

/**
 * Compute the score breakdown and total risk score.
 *
 * @param {object} input
 * @param {object[]} [input.descriptionFindings]
 * @param {object[]} [input.sourceFindings]
 * @param {object} [input.drift] result from drift-detector (or null if no baseline)
 * @param {boolean} [input.hasBaseline] whether a baseline was compared against
 * @returns {object}
 */
export function calculateRiskScore({
  descriptionFindings = [],
  sourceFindings = [],
  drift = null,
  hasBaseline = false,
} = {}) {
  // Deduplicate before summing so repeated matches don't run up the score.
  const dedupDesc = deduplicateFindings(descriptionFindings);
  const dedupSrc = deduplicateFindings(sourceFindings);

  // 1. Description category (max 25).
  let rawDesc = 0;
  for (const f of dedupDesc) {
    rawDesc += SEVERITY_WEIGHT[f.severity] ?? 5;
  }
  const descriptionsScore = Math.min(CATEGORY_CAPS.descriptions, rawDesc);

  // 2. Source category (max 20).
  let rawSrc = 0;
  for (const f of dedupSrc) {
    rawSrc += SEVERITY_WEIGHT[f.severity] ?? 5;
  }
  const sourceScore = Math.min(CATEGORY_CAPS.sourcePatterns, rawSrc);

  // 3. Metadata drift category (max 30): modified tools (e.g. description changed).
  let rawDrift = 0;
  let rawMismatch = 0;

  if (hasBaseline && drift) {
    const modifiedCount = drift.modified?.length ?? 0;
    // Each modified tool adds 15 points up to the 30-point cap.
    rawDrift = modifiedCount * 15;

    // 4. Tool-set mismatch category (max 25): added or removed tools.
    const addedCount = drift.added?.length ?? 0;
    const removedCount = drift.removed?.length ?? 0;
    // Added tool is 20 points (high risk of rogue capability); removed is 10.
    rawMismatch = addedCount * 20 + removedCount * 10;
  }

  const driftScore = Math.min(CATEGORY_CAPS.metadataDrift, rawDrift);
  const mismatchScore = Math.min(CATEGORY_CAPS.toolSetMismatch, rawMismatch);

  const totalScore = Math.min(
    100,
    descriptionsScore + sourceScore + driftScore + mismatchScore
  );

  const baselineStatus = !hasBaseline
    ? "unavailable"
    : drift && drift.hasDrift
    ? "drift_detected"
    : "matches_baseline";

  return {
    score: totalScore,
    riskLevel: getRiskLevel(totalScore),
    baselineStatus,
    scoreBreakdown: {
      descriptions: descriptionsScore,
      sourcePatterns: sourceScore,
      metadataDrift: driftScore,
      toolSetMismatch: mismatchScore,
    },
    caps: { ...CATEGORY_CAPS },
    explanation: buildExplanation({
      totalScore,
      descriptionsScore,
      sourceScore,
      driftScore,
      mismatchScore,
      hasBaseline,
      baselineStatus,
    }),
    disclaimer:
      "Risk score is a heuristic prioritization signal, not a calibrated probability of maliciousness. High scores require manual inspection.",
  };
}

function buildExplanation({
  totalScore,
  descriptionsScore,
  sourceScore,
  driftScore,
  mismatchScore,
  hasBaseline,
  baselineStatus,
}) {
  const parts = [];
  if (descriptionsScore > 0) {
    parts.push(`descriptions: ${descriptionsScore}/${CATEGORY_CAPS.descriptions}`);
  }
  if (sourceScore > 0) {
    parts.push(`source patterns: ${sourceScore}/${CATEGORY_CAPS.sourcePatterns}`);
  }
  if (hasBaseline) {
    if (driftScore > 0) {
      parts.push(`metadata drift: ${driftScore}/${CATEGORY_CAPS.metadataDrift}`);
    }
    if (mismatchScore > 0) {
      parts.push(`tool mismatch: ${mismatchScore}/${CATEGORY_CAPS.toolSetMismatch}`);
    }
  } else {
    parts.push("baseline: unavailable (comparison skipped)");
  }

  if (parts.length === 0) return "No suspicious indicators detected across inspected surfaces.";
  return `Score ${totalScore}/100 based on ${parts.join("; ")}.`;
}
