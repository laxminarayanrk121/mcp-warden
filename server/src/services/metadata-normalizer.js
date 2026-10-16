// MCP Warden — canonical metadata normalizer.
//
// Produces a deterministic, byte-for-byte identical representation of MCP
// tool metadata so that two logically-equivalent manifests always hash the
// same, and any meaningful change always hashes differently.
//
// Normalization rules:
//   - Object keys are sorted recursively (deeply), so key order never matters.
//   - Arrays are preserved in declaration order. This is deliberate: schema
//     arrays (e.g. `required`, enum lists) often have meaningful order, and
//     re-sorting them would hide real changes.
//   - Tools are sorted by name for a stable manifest-wide order.
//   - Only tool name, description, and input schema contribute to the
//     canonical form. Timestamps, random IDs, and server metadata are
//     excluded so a baseline taken at a different time still matches.
//   - Primitives are serialized with JSON.stringify (no whitespace), which is
//     fully deterministic for the supported value types.

import { createHash } from "node:crypto";

const SUPPORTED_FIELDS = new Set(["name", "description", "inputSchema"]);

/**
 * Deeply sort object keys; leave arrays in their original order.
 * @param {*} value
 * @returns {*}
 */
export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = canonicalize(value[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Reduce a tool object to the fields that participate in fingerprinting.
 * @param {object} tool
 * @returns {object}
 */
function normalizeTool(tool) {
  const out = {};
  for (const key of Object.keys(tool).sort()) {
    if (!SUPPORTED_FIELDS.has(key)) continue;
    const value = tool[key];
    if (key === "name") {
      if (typeof value !== "string") {
        throw new Error(`Tool name must be a string, got ${typeof value}.`);
      }
      out.name = value;
    } else if (key === "description") {
      if (typeof value !== "string") {
        throw new Error(`Tool "${tool.name ?? "(unnamed)"}" description must be a string.`);
      }
      out.description = value;
    } else if (key === "inputSchema") {
      out.inputSchema = canonicalize(value);
    }
  }
  return out;
}

/**
 * Normalize a manifest into the canonical tool list used for fingerprinting
 * and drift comparison.
 *
 * Accepts either a full manifest (`{ schemaVersion, server, tools }`) or a
 * bare tool list. Throws a descriptive error for malformed input.
 *
 * @param {object} manifest
 * @returns {{ tools: object[] }}
 */
export function normalizeMetadata(manifest) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("Manifest must be a JSON object.");
  }

  const rawTools = manifest.tools;
  if (!Array.isArray(rawTools)) {
    throw new Error("Manifest must contain a `tools` array.");
  }

  if (rawTools.length > 500) {
    throw new Error(`Manifest exceeds the limit of 500 tools (got ${rawTools.length}).`);
  }

  const tools = [];
  for (let i = 0; i < rawTools.length; i++) {
    const tool = rawTools[i];
    if (tool === null || typeof tool !== "object" || Array.isArray(tool)) {
      throw new Error(`Tool at index ${i} must be an object.`);
    }
    if (typeof tool.name !== "string" || !tool.name.trim()) {
      throw new Error(`Tool at index ${i} must have a non-empty string \`name\`.`);
    }
    if (typeof tool.description !== "string") {
      throw new Error(`Tool "${tool.name}" must have a string \`description\`.`);
    }
    tools.push(normalizeTool(tool));
  }

  // Deterministic order by name. Names must be unique within a manifest.
  const seen = new Set();
  for (const tool of tools) {
    if (seen.has(tool.name)) {
      throw new Error(`Duplicate tool name "${tool.name}" in manifest.`);
    }
    seen.add(tool.name);
  }

  tools.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  return { tools };
}

/**
 * Serialize the normalized manifest to a canonical JSON string.
 * @param {{ tools: object[] }} normalized
 * @returns {string}
 */
export function canonicalJson(normalized) {
  return JSON.stringify(canonicalize(normalized));
}

/**
 * Compute a SHA-256 fingerprint of the canonical manifest.
 * @param {object} manifest
 * @returns {string} `sha256:<hex>`
 */
export function fingerprintMetadata(manifest) {
  const normalized = normalizeMetadata(manifest);
  const digest = createHash("sha256").update(canonicalJson(normalized)).digest("hex");
  return `sha256:${digest}`;
}

/**
 * Validate that a manifest is well-formed without computing a fingerprint.
 * @param {object} manifest
 * @returns {{ ok: true }} | { ok: false, error: string }
 */
export function validateManifest(manifest) {
  try {
    normalizeMetadata(manifest);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}
