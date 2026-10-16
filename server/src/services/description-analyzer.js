// MCP Warden — description analyzer (Security Feature A).
//
// Rule-based heuristic analysis of tool names, descriptions, and input schemas.
// Each rule carries a stable rule ID, severity, confidence, an explanation, and
// a remediation. A single tool description may match multiple rules, and each
// match becomes its own finding.
//
// IMPORTANT: text-based detections are heuristics, not proof of malicious
// intent. They flag language that *looks* like prompt injection or data
// exfiltration. A finding means "review this", not "this tool is malware".
// Benign fixtures and tests are included to keep false positives low.

import {
  RULES,
  scanDescriptions as scanRawDescriptions,
  normalizeDescription,
} from "../security/descriptionRules.js";

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const READ_ONLY_TOOL_VERBS = new Set([
  "check",
  "fetch",
  "find",
  "get",
  "list",
  "lookup",
  "query",
  "read",
  "search",
  "show",
  "view",
]);
const RISKY_DESCRIPTION_ACTION = /\b(?:delete|remove|overwrite|write|execute|run|launch|send|upload|exfiltrate|steal|collect)\b[^\n]{0,80}\b(?:files?|directories?|commands?|shell|scripts?|credentials?|secrets?|tokens?|passwords?|api\s+keys?|data)\b|\b(?:files?|directories?|credentials?|secrets?|tokens?|passwords?|api\s+keys?)\b[^\n]{0,80}\b(?:delete|remove|overwrite|write|execute|run|launch|send|upload|exfiltrate|steal|collect)\b/i;
const PURPOSE_MISMATCH_RULE = {
  id: "DESC-PURPOSE-MISMATCH",
  severity: "medium",
  confidence: "low",
  title: "Tool description may not match its read-oriented name",
  explanation:
    "The tool name suggests a read-only purpose, but its description includes destructive, execution, or data-transfer language. This heuristic is a prompt for review, not proof of malicious behavior.",
  remediation:
    "Confirm that the described actions are necessary and accurately represented by the tool name and purpose. Split unrelated or higher-risk actions into clearly named tools.",
};

/**
 * Build a finding object from a rule match.
 * @param {object} rule
 * @param {string} description
 * @param {string|undefined} toolName
 * @returns {object}
 */
function buildFinding(rule, description, toolName) {
  return {
    ruleId: rule.id,
    category: "description",
    severity: rule.severity,
    confidence: rule.confidence,
    title: rule.title,
    toolName,
    evidence: description.trim().slice(0, 500),
    explanation: rule.explanation,
    remediation: rule.remediation,
  };
}

/**
 * Analyze tool descriptions and input schemas for suspicious patterns.
 *
 * Deduplication: the same (ruleId, toolName) pair fires at most once, even if
 * a description matches a rule in several places. This prevents one long
 * malicious description from inflating the risk score.
 *
 * @param {Array<{name?: string, description?: string, inputSchema?: object}>} tools
 * @returns {object[]} findings
 */
export function analyzeDescriptions(tools) {
  if (!Array.isArray(tools)) return [];
  const findings = [];
  const seen = new Set();

  for (const tool of tools) {
    if (!tool || typeof tool !== "object") continue;
    const toolName = typeof tool.name === "string" ? tool.name : undefined;

    // 1. Description text.
    const description = tool.description;
    if (typeof description === "string" && description.length > 0) {
      for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(description)) {
          const key = `${rule.id}::${toolName ?? "*"}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push(buildFinding(rule, description, toolName));
        }
      }

      const nameVerb = toolName
        ?.replace(/([a-z])([A-Z])/g, "$1_$2")
        .toLowerCase()
        .split(/[_-]/, 1)[0];
      const mismatchKey = `${PURPOSE_MISMATCH_RULE.id}::${toolName ?? "*"}`;
      if (
        nameVerb &&
        READ_ONLY_TOOL_VERBS.has(nameVerb) &&
        RISKY_DESCRIPTION_ACTION.test(description) &&
        !seen.has(mismatchKey)
      ) {
        seen.add(mismatchKey);
        findings.push(buildFinding(PURPOSE_MISMATCH_RULE, description, toolName));
      }
    }

    // 2. Input schema text (e.g. a hidden `endpoint` parameter that asks where
    //    to send collected secrets). Schemas are serialized to text and scanned
    //    with the same rules so the schema surface is covered too.
    if (tool.inputSchema && typeof tool.inputSchema === "object") {
      let schemaText;
      try {
        schemaText = JSON.stringify(tool.inputSchema);
      } catch {
        schemaText = String(tool.inputSchema);
      }
      if (schemaText) {
        for (const rule of RULES) {
          rule.pattern.lastIndex = 0;
          if (rule.pattern.test(schemaText)) {
            const key = `${rule.id}::${toolName ?? "*"}::schema`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              ...buildFinding(rule, schemaText.slice(0, 500), toolName),
              evidence: `inputSchema: ${schemaText.trim().slice(0, 500)}`,
            });
          }
        }
      }
    }
  }

  findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0) ||
      (a.toolName ?? "").localeCompare(b.toolName ?? "")
  );

  return findings;
}

// Re-export for tests and documentation.
export { RULES, scanRawDescriptions, normalizeDescription };
