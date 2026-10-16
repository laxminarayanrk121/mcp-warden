// MCP Warden — fixtures controller (Security Feature F).
//
// Provides access to the built-in demo fixture scenarios so the frontend
// can load known-good and known-bad examples without requiring a live MCP
// server.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { validateFixtureId } from "../utils/validation.js";

const FIXTURE_DIR = join(process.cwd(), "fixtures");

/**
 * GET /api/fixtures
 * Returns the list of available fixture IDs.
 */
export function getFixtures(_req, res) {
  res.status(200).json({
    success: true,
    fixtures: ["benign", "suspicious", "rug-pull"],
  });
}

/**
 * GET /api/fixtures/:id
 * Returns the full fixture manifest for the given id.
 */
export function getFixtureById(req, res) {
  try {
    const fixtureId = validateFixtureId(req.params.id);
    const manifestPath = join(FIXTURE_DIR, fixtureId, "tools.json");
    return readFile(manifestPath, "utf8")
      .then((raw) => {
        let manifest;
        try {
          manifest = JSON.parse(raw);
        } catch {
          return res.status(500).json({
            success: false,
            error: { code: "INTERNAL_ERROR", message: `Fixture ${fixtureId} is corrupted.` },
          });
        }
        res.status(200).json({
          success: true,
          fixtureId,
          manifest,
        });
      })
      .catch((err) => {
        if (err.code === "ENOENT") {
          return res.status(404).json({
            success: false,
            error: { code: "NOT_FOUND", message: `Fixture "${fixtureId}" not found.` },
          });
        }
        console.error("[fixtures.controller] error reading fixture:", err);
        return res.status(500).json({
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
