// MCP Warden — baselines controller (Security Feature D).
//
// POST /api/baselines   -> create a new baseline from fixture or manifest
// GET  /api/baselines   -> list all stored baselines
//
// Baselines are persisted as JSON files under `data/baselines`. Each file
// contains the metadata needed to compare a current manifest against the
// approved snapshot.

import { createBaseline, listBaselines, deleteBaseline } from "../services/baseline.service.js";
import { validateFixtureId } from "../utils/validation.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const FIXTURE_DIR = join(process.cwd(), "..", "fixtures");

/**
 * POST /api/baselines
 * Body: { fixtureId?: string, manifest?: object, name?: string }
 * Creates a baseline from either a fixture (by id) or a raw manifest.
 */
export function postBaselines(req, res) {
  // Support both fixture-based and manifest-based baseline creation.
  let manifest;
  let name;

  // Parse body if it's a string.
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

  try {
    if (body.fixtureId) {
      const fixtureId = validateFixtureId(body.fixtureId);
      const fixturePath = join(FIXTURE_DIR, fixtureId, "tools.json");
      return readFile(fixturePath, "utf8")
        .then((raw) => {
          try {
            manifest = JSON.parse(raw);
          } catch {
            return res.status(500).json({
              success: false,
              error: { code: "INTERNAL_ERROR", message: `Fixture "${fixtureId}" is corrupted.` },
            });
          }
          name = body.name || `baseline-${fixtureId}`;
          return createBaseline(manifest, { name });
        })
        .then((record) => {
          res.status(201).json({
            success: true,
            baseline: record,
          });
        })
        .catch((err) => {
          if (err.code === "ENOENT") {
            return res.status(404).json({
              success: false,
              error: { code: "NOT_FOUND", message: `Fixture "${fixtureId}" not found.` },
            });
          }
          console.error("[baselines.controller] fixture load error:", err);
          return res.status(500).json({
            success: false,
            error: { code: "INTERNAL_ERROR", message: err.message },
          });
        });
    } else if (body.manifest) {
      manifest = body.manifest;
      name = body.name || "manual-baseline";
      return createBaseline(manifest, { name })
        .then((record) => {
          res.status(201).json({
            success: true,
            baseline: record,
          });
        })
        .catch((err) => {
          console.error("[baselines.controller] manifest validation error:", err);
          return res.status(400).json({
            success: false,
            error: { code: "INVALID_REQUEST", message: err.message },
          });
        });
    } else {
      return res.status(400).json({
        success: false,
        error: {
          code: "INVALID_REQUEST",
          message: "Request body must include either `fixtureId` or `manifest`.",
        },
      });
    }
  } catch (err) {
    return res.status(err.status || 400).json({
      success: false,
      error: { code: err.code || "INVALID_REQUEST", message: err.message },
    });
  }
}

/**
 * GET /api/baselines
 * Returns a list of all stored baselines (metadata only).
 */
export function getBaselines(_req, res) {
  listBaselines()
    .then((baselines) => {
      res.status(200).json({
        success: true,
        baselines,
      });
    })
    .catch((err) => {
      console.error("[baselines.controller] list error:", err);
      res.status(500).json({
        success: false,
        error: { code: "INTERNAL_ERROR", message: err.message },
      });
    });
}

/**
 * DELETE /api/baselines/:id
 * Removes a baseline by its server-generated ID.
 */
export function deleteBaselineById(req, res) {
  try {
    const { id } = req.params;
    if (typeof id !== "string" || !id.trim()) {
      return res.status(400).json({
        success: false,
        error: { code: "INVALID_REQUEST", message: "baselineId must be a non-empty string." },
      });
    }
    deleteBaseline(id)
      .then((deleted) => {
        if (!deleted) {
          return res.status(404).json({
            success: false,
            error: { code: "NOT_FOUND", message: `Baseline "${id}" not found.` },
          });
        }
        res.status(200).json({
          success: true,
          message: `Baseline "${id}" deleted.`,
        });
      })
      .catch((err) => {
        console.error("[baselines.controller] delete error:", err);
        res.status(500).json({
          success: false,
          error: { code: "INTERNAL_ERROR", message: err.message },
        });
      });
  } catch (err) {
    return res.status(err.status || 400).json({
      success: false,
      error: { code: err.code || "INVALID_REQUEST", message: err.message },
    });
  }
}
