// MCP Warden — compare controller (Security Feature D).
//
// POST /api/compare
// Compares current tool metadata (from fixture or manifest) against a
// previously stored baseline to detect metadata drift (added/removed/modified
// tools). The comparison is deterministic and based on canonical fingerprints.
//
// Returns:
//   - baseline fingerprint and current fingerprint
//   - lists of added, removed, and modified tools
//   - a clear status when no baseline exists
//
// IMPORTANT: A changed description indicates metadata drift, not proof of
// malicious activity. The report explains what changed for human review.

import { loadBaseline } from "../services/baseline.service.js";
import { detectDrift } from "../services/drift-detector.js";
import { validateManifest } from "../services/fingerprint.service.js";
import { validateFixtureId } from "../utils/validation.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const FIXTURE_DIR = join(process.cwd(), "..", "fixtures");

/**
 * POST /api/compare
 * Body: { baselineId: string, fixtureId?: string, manifest?: object }
 * Returns drift report comparing current metadata against the baseline.
 */
export async function postCompare(req, res) {
  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({
        success: false,
        error: { code: "INVALID_JSON", message: "Request body is not valid JSON." },
      });
    }
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({
      success: false,
      error: { code: "INVALID_REQUEST", message: "Request body must be a JSON object." },
    });
  }

  const { baselineId, fixtureId, manifest } = body;
  if (typeof baselineId !== "string" || !/^[a-f0-9]{12}$/i.test(baselineId)) {
    return res.status(400).json({
      success: false,
      error: { code: "INVALID_REQUEST", message: "baselineId format is invalid." },
    });
  }

  const hasFixture = typeof fixtureId === "string" && Boolean(fixtureId.trim());
  const hasManifest = manifest && typeof manifest === "object" && !Array.isArray(manifest);
  if (hasFixture === Boolean(hasManifest)) {
    return res.status(400).json({
      success: false,
      error: { code: "INVALID_REQUEST", message: "Provide exactly one of fixtureId or manifest." },
    });
  }

  if (hasManifest) {
    const validation = validateManifest(manifest);
    if (!validation.ok) {
      return res.status(400).json({
        success: false,
        error: { code: "INVALID_REQUEST", message: `Invalid manifest: ${validation.error}` },
      });
    }
  }

  try {
    const baselineRecord = await loadBaseline(baselineId);
    if (!baselineRecord) {
      return res.status(404).json({
        success: false,
        error: { code: "NOT_FOUND", message: `Baseline "${baselineId}" not found.` },
      });
    }

    let currentManifest = manifest;
    if (hasFixture) {
      let validatedFixtureId;
      try {
        validatedFixtureId = validateFixtureId(fixtureId);
      } catch (err) {
        return res.status(err.status || 400).json({
          success: false,
          error: { code: err.code || "INVALID_REQUEST", message: err.message },
        });
      }

      const fixturePath = join(FIXTURE_DIR, validatedFixtureId, "tools.json");
      let raw;
      try {
        raw = await readFile(fixturePath, "utf8");
      } catch (err) {
        if (err.code === "ENOENT") {
          return res.status(404).json({
            success: false,
            error: { code: "NOT_FOUND", message: `Fixture "${validatedFixtureId}" not found.` },
          });
        }
        throw err;
      }
      try {
        currentManifest = JSON.parse(raw);
      } catch {
        return res.status(500).json({
          success: false,
          error: { code: "INTERNAL_ERROR", message: `Fixture "${validatedFixtureId}" is corrupted.` },
        });
      }
    }

    const drift = detectDrift(baselineRecord.manifest, currentManifest);
    return res.status(200).json({
      success: true,
      baselineId,
      baselineFingerprint: baselineRecord.fingerprint,
      currentFingerprint: drift.currentFingerprint,
      drift,
    });
  } catch (err) {
    console.error("[compare.controller] error:", err);
    return res.status(500).json({
      success: false,
      error: { code: "INTERNAL_ERROR", message: "Unable to compare against baseline." },
    });
  }
}
