// MCP Warden — scan controller.
//
// Orchestrates a description-security scan over submitted MCP tool metadata.
//
// SAFETY: this controller is read-only over tool metadata. It inspects only
// `name` and `description` strings. It never executes, spawns, imports, or
// evals submitted tools, scripts, or MCP servers — the request body is treated
// as untrusted data and passed only to the pure regex-based scanner.

import { createHash } from "node:crypto";
import { scanDescriptions } from "../security/descriptionRules.js";

const MAX_TOOLS = 200;
const MAX_DESCRIPTION_LENGTH = 4096;

const SEVERITY_WEIGHT = { low: 5, medium: 15, high: 40, critical: 60 };

function riskLevel(score) {
  if (score >= 70) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function computeScore(findings) {
  let score = 0;
  for (const f of findings) {
    score += SEVERITY_WEIGHT[f.severity] ?? 10;
  }
  return Math.min(100, score);
}

/**
 * Build a deterministic fingerprint over normalized tool metadata.
 * Only `name` and `description` contribute — never command/args/scripts.
 */
function fingerprint(tools) {
  const parts = [];
  for (const tool of tools) {
    const name = typeof tool.name === "string" ? tool.name.trim().toLowerCase() : "";
    const description =
      typeof tool.description === "string"
        ? tool.description.trim().toLowerCase().replace(/\s+/g, " ")
        : "";
    parts.push(`${name}\u0000${description}`);
  }
  const digest = createHash("sha256").update(parts.join("\u0001")).digest("hex");
  return `sha256:${digest}`;
}

/**
 * Validate the request body for POST /api/scan.
 *
 * The HTTP shim stores the raw request body as a string on `req.body`, so the
 * JSON is parsed here. Malformed JSON is rejected as a 400 rather than
 * crashing the server.
 *
 * @returns {{ ok: true, tools: object[] }} | { ok: false, code: string, message: string, status: number }
 */
function validateScanRequest(body) {
  if (body === undefined || body === null || body === "") {
    return {
      ok: false,
      status: 400,
      code: "INVALID_REQUEST",
      message: "Request body must be a JSON object with a `tools` array.",
    };
  }

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
  } else {
    parsed = body;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      ok: false,
      status: 400,
      code: "INVALID_REQUEST",
      message: "Request body must be a JSON object with a `tools` array.",
    };
  }

  const { tools } = parsed;
  if (!Array.isArray(tools)) {
    return {
      ok: false,
      status: 400,
      code: "INVALID_REQUEST",
      message: "`tools` must be an array of MCP tool objects.",
    };
  }

  if (tools.length === 0) {
    return { ok: true, tools: [] };
  }

  if (tools.length > MAX_TOOLS) {
    return {
      ok: false,
      status: 413,
      code: "PAYLOAD_TOO_LARGE",
      message: `Request exceeds the limit of ${MAX_TOOLS} tools.`,
    };
  }

  const normalized = [];
  for (let i = 0; i < tools.length; i++) {
    const tool = tools[i];
    if (tool === null || typeof tool !== "object" || Array.isArray(tool)) {
      return {
        ok: false,
        status: 400,
        code: "INVALID_TOOL",
        message: `Tool at index ${i} must be an object with a string \`description\`.`,
      };
    }

    const { name, description } = tool;
    if (typeof description !== "string") {
      return {
        ok: false,
        status: 400,
        code: "INVALID_TOOL",
        message: `Tool at index ${i} must have a string \`description\` field.`,
      };
    }

    if (description.length > MAX_DESCRIPTION_LENGTH) {
      return {
        ok: false,
        status: 413,
        code: "PAYLOAD_TOO_LARGE",
        message: `Tool at index ${i} description exceeds ${MAX_DESCRIPTION_LENGTH} characters.`,
      };
    }

    normalized.push({
      name: typeof name === "string" ? name : undefined,
      description,
    });
  }

  return { ok: true, tools: normalized };
}

export function postScan(req, res) {
  const validation = validateScanRequest(req.body);
  if (!validation.ok) {
    return res.status(validation.status).json({
      success: false,
      error: { code: validation.code, message: validation.message },
    });
  }

  const { tools } = validation;
  const findings = scanDescriptions(tools);
  const score = computeScore(findings);

  res.status(200).json({
    success: true,
    scanId: `scan_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    toolsScanned: tools.length,
    score,
    riskLevel: riskLevel(score),
    fingerprint: fingerprint(tools),
    findings,
  });
}