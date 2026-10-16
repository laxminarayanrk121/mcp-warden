// MCP Warden — canonical metadata fingerprinting (Security Feature C).
//
// Wraps the normalizer in a small service surface so scan, baseline, and
// comparison operations all share one implementation. The same function is
// used everywhere: a fingerprint is only meaningful if it was computed the
// same way it is being compared against.

import {
  canonicalize,
  canonicalJson,
  fingerprintMetadata,
  normalizeMetadata,
  validateManifest,
} from "./metadata-normalizer.js";

/**
 * Compute a SHA-256 fingerprint for a manifest.
 * @param {object} manifest
 * @returns {{ fingerprint: string, normalized: object, canonicalJson: string }}
 */
export function computeFingerprint(manifest) {
  const normalized = normalizeMetadata(manifest);
  const canonical = canonicalJson(normalized);
  const digest = canonicalize(normalized);
  const fingerprint = fingerprintMetadata(manifest);
  return { fingerprint, normalized: digest, canonicalJson: canonical };
}

/**
 * Compare two fingerprints.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function fingerprintsMatch(a, b) {
  return typeof a === "string" && typeof b === "string" && a === b;
}

export {
  canonicalize,
  canonicalJson,
  fingerprintMetadata,
  normalizeMetadata,
  validateManifest,
};
