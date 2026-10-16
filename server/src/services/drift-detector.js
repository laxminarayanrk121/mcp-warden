// MCP Warden — metadata drift detection (Security Feature D).
//
// Compares current MCP tool metadata against an approved baseline.
// Identifies:
//   - Added tools (tools present now that were not in the baseline)
//   - Removed tools (tools present in the baseline that are gone now)
//   - Modified tools (tools present in both whose metadata changed)
//
// For modified tools, drift-detector isolates the exact fields that changed
// (`description`, `inputSchema`) so the user can see what shifted without
// having to diff the raw JSON themselves.
//
// IMPORTANT: A changed description or added tool is evidence of metadata
// drift, NOT proof of an attack. Legitimate updates change metadata all the
// time. The drift report explains *what* changed so human review can make
// the security decision.

import {
  canonicalize,
  fingerprintMetadata,
  normalizeMetadata,
} from "./metadata-normalizer.js";

/**
 * Deep equality for normalized JSON values.
 */
function deepEqual(a, b) {
  return JSON.stringify(canonicalize(a)) === JSON.stringify(canonicalize(b));
}

/**
 * Compare two manifests and report all differences.
 *
 * @param {object} baselineManifest
 * @param {object} currentManifest
 * @returns {object} drift summary and detailed changes
 */
export function detectDrift(baselineManifest, currentManifest) {
  const normBaseline = normalizeMetadata(baselineManifest);
  const normCurrent = normalizeMetadata(currentManifest);

  const baselineFingerprint = fingerprintMetadata(normBaseline);
  const currentFingerprint = fingerprintMetadata(normCurrent);

  const baselineMap = new Map();
  for (const tool of normBaseline.tools) baselineMap.set(tool.name, tool);

  const currentMap = new Map();
  for (const tool of normCurrent.tools) currentMap.set(tool.name, tool);

  const added = [];
  const removed = [];
  const modified = [];

  // 1. Detect added and modified tools.
  for (const [name, currentTool] of currentMap.entries()) {
    if (!baselineMap.has(name)) {
      added.push({
        name,
        description: currentTool.description,
        inputSchema: currentTool.inputSchema,
      });
      continue;
    }

    const baselineTool = baselineMap.get(name);
    const fieldChanges = [];

    if (baselineTool.description !== currentTool.description) {
      fieldChanges.push({
        field: "description",
        before: baselineTool.description,
        after: currentTool.description,
      });
    }

    if (!deepEqual(baselineTool.inputSchema, currentTool.inputSchema)) {
      fieldChanges.push({
        field: "inputSchema",
        before: baselineTool.inputSchema,
        after: currentTool.inputSchema,
      });
    }

    if (fieldChanges.length > 0) {
      modified.push({
        name,
        changes: fieldChanges,
      });
    }
  }

  // 2. Detect removed tools.
  for (const [name, baselineTool] of baselineMap.entries()) {
    if (!currentMap.has(name)) {
      removed.push({
        name,
        description: baselineTool.description,
      });
    }
  }

  const hasDrift = added.length > 0 || removed.length > 0 || modified.length > 0;

  return {
    hasDrift,
    match: !hasDrift,
    baselineFingerprint,
    currentFingerprint,
    summary: {
      addedCount: added.length,
      removedCount: removed.length,
      modifiedCount: modified.length,
    },
    added,
    removed,
    modified,
    caveat:
      "Metadata drift indicates that declared tools have changed since the baseline was approved. Review each modification to confirm it is an intended update rather than a rug-pull attempt.",
  };
}
