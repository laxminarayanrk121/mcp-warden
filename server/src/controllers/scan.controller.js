// MCP Warden — scan controller (Security Feature F).
//
// Orchestrates the complete security audit workflow:
//   1. Validate input (fixtureId or raw manifest, includeSourceScan flag, baselineId)
//   2. Load permitted fixture or validate supplied manifest
//   3. Run description analysis
//   4. Run source scanning when source input is explicitly supplied and allowed
//   5. Generate canonical fingerprint
//   6. Compare against a baseline when a valid baselineId is supplied
//   7. Calculate the final risk score
//   8. Return a consistent structured result
//   9. Store enough sanitized report data for later retrieval
//
// SAFETY: this controller never executes untrusted code, never touches the host
// filesystem with client-supplied paths, and never includes secrets in logs or
// responses.

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { validateFixtureId } from "../utils/validation.js";
import { analyzeDescriptions } from "../services/description-analyzer.js";
import { analyzeCapabilities } from "../services/capability-analyzer.js";
import { scanSourceFiles, validateFiles } from "../services/source-scanner.js";
import {
  computeFingerprint,
  validateManifest,
} from "../services/fingerprint.service.js";
import { loadBaseline } from "../services/baseline.service.js";
import { detectDrift } from "../services/drift-detector.js";
import { calculateRiskScore } from "../services/risk-scorer.js";
import { saveReport } from "../services/report.service.js";

// FIXTURE_DIR should point to the repository root fixtures directory.
// When the server is started from the repo root, process.cwd() is the repo root.
const FIXTURE_DIR = join(process.cwd(), "..", "fixtures");
const MAX_TOOLS = 200;
const MAX_DESCRIPTION_LENGTH = 4096;
const MAX_SOURCE_FILES = 50;
const MAX_SOURCE_CHARS = 100_000;

/**
 * Validate the request body for POST /api/scan.
 * Supports three modes for backward compatibility:
 *   1. fixture-based: { fixtureId: "benign|suspicious|rug-pull", includeSourceScan?: boolean, baselineId?: string }
 *   2. manifest-based: { manifest: object, includeSourceScan?: boolean, sourceFiles?: Array, baselineId?: string }
 *   3. legacy-manifest: { tools: Array, includeSourceScan?: boolean, ... } (treated as manifest)
 *
 * The body may be a string (raw JSON) or an already-parsed object.
 * @param {object|string} body
 * @returns {{ ok: true, mode: "fixture"|"manifest", fixtureId?: string, manifest?: object, includeSourceScan: boolean, sourceFiles?: Array, baselineId?: string }}
 *          | { ok: false, code: string, message: string, status: number }
 */
function validateScanRequest(body) {
  // If body is a string, try to parse it as JSON.
  let parsed;
  if (typeof body === "string") {
    try {
      parsed = JSON.parse(body);
    } catch {
      return {
        ok: false,
        status: 400,
        code: "INVALID_JSON",
        message: "Request body is not valid JSON.",
      };
    }
  } else if (body === undefined || body === null || typeof body !== "object") {
    return {
      ok: false,
      status: 400,
      code: "INVALID_REQUEST",
      message: "Request body must be a JSON object.",
    };
  } else {
    parsed = body;
  }

  const { fixtureId, manifest, includeSourceScan = false, sourceFiles, baselineId, tools } = parsed;

  // Determine which mode we're in.
  let mode = null;
  let manifestObject = null;

  if (fixtureId && typeof fixtureId === "string" && fixtureId.trim()) {
    // Mode 1: fixture-based
    mode = "fixture";
  } else if (manifest && typeof manifest === "object" && !Array.isArray(manifest)) {
    // Mode 2: manifest-based (wrapped)
    mode = "manifest";
    manifestObject = manifest;
  } else if (tools && Array.isArray(tools)) {
    // Mode 3: legacy-manifest (backward compatibility with existing tests)
    mode = "manifest";
    manifestObject = parsed; // treat the whole object as the manifest
  } else {
    return {
      ok: false,
      status: 400,
      code: "INVALID_REQUEST",
      message: "Provide exactly one of fixtureId, manifest, or tools array.",
    };
  }

  // Validate baselineId if present (format only; existence checked later).
  if (baselineId !== undefined) {
    if (typeof baselineId !== "string" || !baselineId.trim()) {
      return {
        ok: false,
        status: 400,
        code: "INVALID_REQUEST",
        message: "baselineId must be a non-empty string.",
      };
    }
    // Basic UUID-like sanity check; service will confirm existence.
    if (!/^[a-f0-9]{12}$/i.test(baselineId)) {
      return {
        ok: false,
        status: 400,
        code: "INVALID_REQUEST",
        message: "baselineId format is invalid.",
      };
    }
  }

  let validatedSourceFiles;
  if (includeSourceScan) {
    if (!Array.isArray(sourceFiles)) {
      return {
        ok: false,
        status: 400,
        code: "INVALID_REQUEST",
        message: "includeSourceScan is true but sourceFiles is not an array.",
      };
    }
    try {
      validateFiles(sourceFiles);
      validatedSourceFiles = sourceFiles;
    } catch (err) {
      return {
        ok: false,
        status: err instanceof RangeError ? 413 : 400,
        code: err instanceof RangeError ? "PAYLOAD_TOO_LARGE" : "INVALID_REQUEST",
        message: `sourceFiles validation failed: ${err.message}`,
      };
    }
  }

  if (mode === "fixture") {
    try {
      const fid = validateFixtureId(fixtureId);
      return {
        ok: true,
        mode: "fixture",
        fixtureId: fid,
        includeSourceScan: Boolean(includeSourceScan),
        sourceFiles: validatedSourceFiles,
        baselineId: baselineId || undefined,
      };
    } catch (err) {
      return {
        ok: false,
        status: err.status || 400,
        code: err.code || "INVALID_REQUEST",
        message: err.message,
      };
    }
  }

  // manifest-based mode (including legacy)
  // 1. Validate manifest shape.
  const manifestValidation = validateManifest(manifestObject);
  if (!manifestValidation.ok) {
    return {
      ok: false,
      status: 400,
      code: "INVALID_REQUEST",
      message: `Invalid manifest: ${manifestValidation.error}`,
    };
  }

  // 1b. Validate description length for legacy mode (tools array directly)
  if (tools && Array.isArray(tools)) {
    for (let i = 0; i < tools.length; i++) {
      const tool = tools[i];
      if (tool && typeof tool.description === "string" && tool.description.length > MAX_DESCRIPTION_LENGTH) {
        return {
          ok: false,
          status: 413,
          code: "PAYLOAD_TOO_LARGE",
          message: `Tool at index ${i} description exceeds ${MAX_DESCRIPTION_LENGTH} characters.`,
        };
      }
    }
  }

  return {
    ok: true,
    mode: "manifest",
    manifest: manifestObject,
    includeSourceScan: Boolean(includeSourceScan),
    sourceFiles: validatedSourceFiles,
    baselineId: baselineId || undefined,
  };
}

/**
 * Load fixture manifest from disk.
 * @param {string} fixtureId
 * @returns {Promise<object>}
 */
async function loadFixtureManifest(fixtureId) {
  const manifestPath = join(FIXTURE_DIR, fixtureId, "tools.json");
  const raw = await readFile(manifestPath, "utf8");
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Fixture "${fixtureId}" is corrupted.`);
  }
}

/**
 * Generate a scanId that is unique but readable.
 * @returns {string}
 */
function generateScanId() {
  const uuid = randomUUID();
  const timestamp = Date.now().toString(36);
  const random = uuid.replace(/-/g, "").slice(0, 8);
  return `scan_${timestamp}_${random}`;
}

/**
 * Build the standardized success response shape.
 * @param {object} inputs
 * @param {object} analysisResults
 * @returns {object}
 */
function buildScanResponse(inputs, analysisResults) {
  const {
    scanId,
    mode,
    fixtureId,
    manifest,
    includeSourceScan,
    sourceFiles,
    baselineId,
  } = inputs;

  const {
    descriptionFindings,
    sourceFindings,
    fingerprintObj,
    drift,
    riskResult,
    capabilityAnalysis,
  } = analysisResults;

  const toolsInspected =
    mode === "fixture"
      ? manifest.tools.length
      : Array.isArray(manifest.tools)
      ? manifest.tools.length
      : 0;
  const findings = [...(descriptionFindings ?? []), ...(sourceFindings ?? [])];
  const severityCounts = Object.fromEntries(
    ["critical", "high", "medium", "low"].map((severity) => [
      severity,
      findings.filter((finding) => finding.severity === severity).length,
    ])
  );
  const recommendations = [
    ...new Set(findings.map((finding) => finding.remediation).filter(Boolean)),
  ];

  return {
    success: true,
    scanId,
    timestamp: new Date().toISOString(),
    score: riskResult.score,
    riskLevel: riskResult.riskLevel,
    fingerprint: fingerprintObj.fingerprint,
    baselineStatus: riskResult.baselineStatus,
    // Legacy field for fixture-based scans
    ...(mode === "fixture" && fixtureId ? { fixtureId } : {}),
    // Backward compatibility fields
    toolsScanned: toolsInspected,
    fixtureId,
    // New structured fields
    summary: {
      toolsInspected,
      findingsCount: findings.length,
      filesScanned: includeSourceScan ? (sourceFiles?.length ?? 0) : 0,
    },
    severityCounts,
    scoreBreakdown: riskResult.scoreBreakdown,
    findings,
    capabilityAnalysis,
    recommendations,
    metadataChanges: drift
      ? {
          added: drift.added ?? [],
          removed: drift.removed ?? [],
          modified: drift.modified ?? [],
        }
      : undefined,
    limitations: [
      "Description analysis uses heuristic regexes; natural-language variation can cause false positives or false negatives.",
      "Source scanning is pattern-based and bounded; it identifies risk indicators, not proof of exploitable vulnerabilities.",
      "A changed description indicates drift, not necessarily malicious activity.",
      "The risk score is a heuristic prioritization signal, not a formal security certification.",
    ],
  };
}

export async function postScan(req, res) {
  // 1. Validate and normalize inputs.
  const validation = validateScanRequest(req.body);
  if (!validation.ok) {
    return res.status(validation.status).json({
      success: false,
      error: { code: validation.code, message: validation.message },
    });
  }

  try {
    // 2. Load manifest (from fixture or manifest).
    let manifest;
    let fixtureId = undefined;
    if (validation.mode === "fixture") {
      manifest = await loadFixtureManifest(validation.fixtureId);
      fixtureId = validation.fixtureId;
    } else {
      manifest = validation.manifest;
    }

    // 3. Description analysis (always runs).
    const descriptionFindings = analyzeDescriptions(manifest.tools);

    // 4. Source scanning (only if flagged and sourceFiles provided).
    let sourceFindings = [];
    if (validation.includeSourceScan && validation.sourceFiles) {
      const sourceResult = await scanSourceFiles(validation.sourceFiles);
      sourceFindings = sourceResult.findings;
    }

    // 5. Canonical fingerprint.
    const fingerprintObj = computeFingerprint(manifest);

    // 6. Baseline comparison (if baselineId supplied).
    let drift = null;
    let hasBaseline = false;
    if (validation.baselineId) {
      hasBaseline = true;
      const baselineRecord = await loadBaseline(validation.baselineId);
      if (baselineRecord) {
        drift = detectDrift(baselineRecord.manifest, manifest);
      }
      // If baseline not found, drift stays null and hasBaseline remains true
      // so the risk scorer knows a baseline was requested but missing.
    }

    // 7. Risk scoring.
    const riskResult = calculateRiskScore({
      descriptionFindings,
      sourceFindings,
      drift,
      hasBaseline,
    });

    // 8. Generate scanId and build response.
    const scanId = generateScanId();
    const analysisResults = {
      descriptionFindings,
      sourceFindings,
      fingerprintObj,
      drift,
      riskResult,
      capabilityAnalysis: analyzeCapabilities(manifest.tools, sourceFindings),
    };
    const response = buildScanResponse(
      {
        scanId,
        mode: validation.mode,
        fixtureId,
        manifest,
        includeSourceScan: validation.includeSourceScan,
        sourceFiles: validation.sourceFiles,
        baselineId: validation.baselineId,
      },
      analysisResults
    );

    // 9. Persist a sanitized report for later retrieval.
    const reportToSave = {
      ...response,
      scanId,
      fixtureId: validation.mode === "fixture" ? validation.fixtureId : undefined,
      includeSourceScan: validation.includeSourceScan,
      createdAt: new Date().toISOString(),
      // Strip fields that are too large or internal for reports storage.
      limitations: undefined,
    };
    await saveReport(reportToSave);

    // 10. Return the response.
    res.status(200).json(response);
  } catch (err) {
    console.error("[scan.controller] unexpected error:", err);
    return res.status(500).json({
      success: false,
      error: { code: "INTERNAL_ERROR", message: err.message },
    });
  }
}
