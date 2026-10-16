// MCP Warden — baseline persistence (Security Feature D).
//
// A baseline is an approved snapshot of MCP tool metadata, identified by a
// server-generated ID and stored as JSON under a designated directory.
//
// Persistence notes (MVP):
//   - Local JSON files only. Suitable for a demo; not hardened for production
//     where an attacker could read or tamper with the storage directory.
//   - Baseline IDs are generated on the server and are URL-safe.
//   - Filenames are derived from the ID only; no client-supplied paths are
//     accepted, so path traversal is not possible.
//   - Existing baselines are never silently overwritten.
//   - Fingerprints are always computed on the server from the submitted
//     metadata; a client-supplied fingerprint is ignored.

import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, readdir, rm } from "node:fs/promises";
import { join, basename } from "node:path";
import { normalize as normalizePath } from "node:path";

import { fingerprintMetadata, validateManifest } from "./fingerprint.service.js";

// Resolved at module load from env; falls back to the repo-relative path so
// the demo works out of the box. The directory is always created on demand.
const BASELINE_DIR = process.env.MCP_WARDEN_BASELINES_DIR
  ? process.env.MCP_WARDEN_BASELINES_DIR
  : join(process.cwd(), "data", "baselines");

const BASELINE_ID_RE = /^[a-z0-9_-]{6,64}$/i;

function safeBaselineName(id) {
  if (typeof id !== "string" || !BASELINE_ID_RE.test(id)) {
    throw new Error(`Invalid baseline id: ${JSON.stringify(id)}.`);
  }
  return `${id}.json`;
}

function baselinePath(id) {
  return join(BASELINE_DIR, safeBaselineName(id));
}

/**
 * Ensure the baseline directory exists.
 */
export async function ensureBaselineDir() {
  await mkdir(BASELINE_DIR, { recursive: true });
}

/**
 * Load a baseline file, returning null if it does not exist.
 * @param {string} id
 * @returns {object|null}
 */
export async function loadBaseline(id) {
  let raw;
  try {
    raw = await readFile(baselinePath(id), "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Baseline ${id} is not valid JSON.`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Baseline ${id} is not a JSON object.`);
  }

  return parsed;
}

/**
 * Create a new baseline from validated tool metadata.
 *
 * @param {object} manifest
 * @param {{ name?: string, source?: string }} [meta]
 * @returns {object} created baseline record
 */
export async function createBaseline(manifest, meta = {}) {
  const validation = validateManifest(manifest);
  if (!validation.ok) {
    throw new Error(`Cannot create baseline: ${validation.error}`);
  }

  // Fingerprints are always computed on the server.
  const fingerprint = fingerprintMetadata(manifest);

  const id = randomUUID().replace(/-/g, "").slice(0, 12);
  const createdAt = new Date().toISOString();

  const record = {
    id,
    fingerprint,
    createdAt,
    source: typeof meta.source === "string" ? meta.source : "manual",
    name: typeof meta.name === "string" ? meta.name : undefined,
    toolCount: manifest.tools.length,
    manifest,
  };

  await ensureBaselineDir();

  // Never silently overwrite an existing baseline.
  try {
    await writeFile(baselinePath(id), "", { flag: "wx" });
  } catch (err) {
    if (err.code === "EEXIST") {
      // Extremely unlikely with a random id; retry once with a fresh id.
      return createBaseline(manifest, meta);
    }
    throw err;
  }

  await writeFile(baselinePath(id), JSON.stringify(record, null, 2), "utf8");

  return sanitizeBaseline(record);
}

/**
 * List all stored baselines (metadata only, no embedded manifest).
 * @returns {object[]}
 */
export async function listBaselines() {
  await ensureBaselineDir();
  let names;
  try {
    names = await readdir(BASELINE_DIR);
  } catch {
    return [];
  }

  const out = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const id = basename(name, ".json");
    if (!BASELINE_ID_RE.test(id)) continue;
    try {
      const record = await loadBaseline(id);
      if (record) out.push(sanitizeBaseline(record));
    } catch (err) {
      // Skip unreadable/malformed files rather than failing the whole list.
      console.error(`[baseline] skipping unreadable baseline ${id}:`, err.message);
    }
  }

  out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return out;
}

/**
 * Delete a baseline by id. Returns true if it existed.
 * @param {string} id
 * @returns {boolean}
 */
export async function deleteBaseline(id) {
  try {
    await rm(baselinePath(id));
    return true;
  } catch (err) {
    if (err.code === "ENOENT") return false;
    throw err;
  }
}

/**
 * Return a sanitized copy of a baseline record (no internal paths).
 * @param {object} record
 * @returns {object}
 */
export function sanitizeBaseline(record) {
  if (!record) return record;
  const { manifest, ...rest } = record;
  return rest;
}
