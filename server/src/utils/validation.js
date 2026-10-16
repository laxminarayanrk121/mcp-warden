// MCP Warden — shared validation utilities.
//
// Provides fixture allowlists, manifest validation, and safe request-body
// parsing. Used across all routes to keep input validation centralized.

const FIXTURE_IDS = ["benign", "suspicious", "rug-pull"];

/**
 * Validate that a fixture id is on the fixed allowlist.
 * @param {unknown} id
 * @returns {string} the validated id
 */
export function validateFixtureId(id) {
  if (typeof id !== "string" || !id.trim()) {
    throw Object.assign(new Error("fixtureId must be a non-empty string."), {
      status: 400,
      code: "INVALID_REQUEST",
    });
  }
  if (!FIXTURE_IDS.includes(id)) {
    throw Object.assign(new Error(`Unknown fixture id "${id}".`), {
      status: 400,
      code: "INVALID_FIXTURE_ID",
    });
  }
  return id;
}

export { FIXTURE_IDS };
