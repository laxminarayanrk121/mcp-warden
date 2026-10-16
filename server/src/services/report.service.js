// MCP Warden — report persistence and Markdown export (Security Feature G).
//
// Manages completed scan reports. Each scan produces a persistent report
// that can be fetched later via GET /api/reports/:id in both structured JSON
// and human-readable Markdown format.
//
// Security considerations:
//   - Reports are stored in a dedicated directory under `data/reports`.
//   - Report IDs are strictly alphanumeric/hyphens/underscores to prevent
//     path traversal.
//   - Untrusted strings (tool names, descriptions, evidence) are sanitized
//     when generating Markdown so injection cannot break markdown formatting.
//   - Secrets and absolute filesystem paths are never written into reports.

import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, readdir, rm } from "node:fs/promises";
import { join, basename } from "node:path";

const REPORT_DIR = process.env.MCP_WARDEN_REPORTS_DIR
  ? process.env.MCP_WARDEN_REPORTS_DIR
  : join(process.cwd(), "data", "reports");

const REPORT_ID_RE = /^[a-z0-9_-]{6,64}$/i;

function safeReportName(id) {
  if (typeof id !== "string" || !REPORT_ID_RE.test(id)) {
    throw new Error(`Invalid report id: ${JSON.stringify(id)}.`);
  }
  return `${id}.json`;
}

function reportPath(id) {
  return join(REPORT_DIR, safeReportName(id));
}

export async function ensureReportDir() {
  await mkdir(REPORT_DIR, { recursive: true });
}

/**
 * Escape markdown control characters in untrusted text.
 * @param {string} text
 * @returns {string}
 */
export function escapeMarkdown(text) {
  if (typeof text !== "string") return "";
  return text
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/\*/g, "\\*")
    .replace(/_/g, "\\_")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]");
}

/**
 * Format a scan report as clean, self-contained Markdown.
 * @param {object} report
 * @returns {string}
 */
export function formatReportMarkdown(report) {
  const lines = [];

  lines.push(`# MCP Warden Security Audit Report`);
  lines.push("");
  lines.push(`**Scan ID:** \`${report.scanId}\`  `);
  lines.push(`**Generated At:** ${report.createdAt}  `);
  lines.push(`**Risk Level:** **${report.riskLevel?.toUpperCase()}** (Score: ${report.score}/100)  `);
  lines.push(`**Baseline Status:** \`${report.baselineStatus}\`  `);
  lines.push(`**Canonical Fingerprint:** \`${report.fingerprint}\`  `);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  lines.push(`- **Tools Inspected:** ${report.summary?.toolsInspected ?? 0}`);
  lines.push(`- **Total Findings:** ${report.summary?.findingsCount ?? 0}`);
  lines.push(`- **Source Files Scanned:** ${report.summary?.filesScanned ?? 0}`);
  lines.push("");

  lines.push(`## Score Breakdown`);
  lines.push("");
  lines.push(`| Category | Score | Cap |`);
  lines.push(`|---|---|---|`);
  const b = report.scoreBreakdown ?? {};
  lines.push(`| Suspicious Descriptions | ${b.descriptions ?? 0} | 25 |`);
  lines.push(`| Risky Source Patterns | ${b.sourcePatterns ?? 0} | 20 |`);
  lines.push(`| Metadata Drift | ${b.metadataDrift ?? 0} | 30 |`);
  lines.push(`| Tool Set Mismatch | ${b.toolSetMismatch ?? 0} | 25 |`);
  lines.push(`| **Total** | **${report.score}** | **100** |`);
  lines.push("");

  if (report.drift && report.drift.hasDrift) {
    lines.push(`## Metadata Drift`);
    lines.push("");
    if (report.drift.added?.length) {
      lines.push(`### Added Tools (${report.drift.added.length})`);
      for (const t of report.drift.added) {
        lines.push(`- **\`${escapeMarkdown(t.name)}\`**: ${escapeMarkdown(t.description)}`);
      }
      lines.push("");
    }
    if (report.drift.removed?.length) {
      lines.push(`### Removed Tools (${report.drift.removed.length})`);
      for (const t of report.drift.removed) {
        lines.push(`- **\`${escapeMarkdown(t.name)}\`**`);
      }
      lines.push("");
    }
    if (report.drift.modified?.length) {
      lines.push(`### Modified Tools (${report.drift.modified.length})`);
      for (const m of report.drift.modified) {
        lines.push(`- **\`${escapeMarkdown(m.name)}\`**:`);
        for (const c of m.changes) {
          lines.push(`  - Field \`${c.field}\` changed`);
        }
      }
      lines.push("");
    }
  }

  lines.push(`## Findings (${report.findings?.length ?? 0})`);
  lines.push("");

  if (!report.findings || report.findings.length === 0) {
    lines.push(`_No findings detected._`);
    lines.push("");
  } else {
    for (let i = 0; i < report.findings.length; i++) {
      const f = report.findings[i];
      lines.push(`### ${i + 1}. [${f.severity?.toUpperCase()}] ${escapeMarkdown(f.title ?? "Finding")}`);
      lines.push("");
      lines.push(`- **Rule ID:** \`${f.ruleId ?? "N/A"}\``);
      lines.push(`- **Category:** \`${f.category ?? "N/A"}\``);
      if (f.toolName) lines.push(`- **Tool:** \`${escapeMarkdown(f.toolName)}\``);
      if (f.file) lines.push(`- **Location:** \`${escapeMarkdown(f.file)}:${f.line ?? 0}\``);
      lines.push(`- **Confidence:** \`${f.confidence ?? "medium"}\``);
      lines.push("");
      lines.push(`**Evidence:**`);
      lines.push("```");
      lines.push(f.evidence ?? "(no evidence provided)");
      lines.push("```");
      lines.push("");
      if (f.explanation) {
        lines.push(`**Explanation:** ${escapeMarkdown(f.explanation)}`);
        lines.push("");
      }
      if (f.remediation) {
        lines.push(`**Remediation:** ${escapeMarkdown(f.remediation)}`);
        lines.push("");
      }
    }
  }

  lines.push(`## Limitations & Caveats`);
  lines.push("");
  lines.push(`- Description analysis uses heuristic regexes; natural-language variation can cause false positives or false negatives.`);
  lines.push(`- Source scanning is pattern-based and bounded; it identifies risk indicators, not proof of exploitable vulnerabilities.`);
  lines.push(`- A changed description indicates drift, not necessarily malicious activity.`);
  lines.push(`- The risk score is a heuristic prioritization signal, not a formal security certification.`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Save a report record.
 * @param {object} reportData
 * @returns {object}
 */
export async function saveReport(reportData) {
  const scanId = reportData.scanId || `scan_${randomUUID().replace(/-/g, "").slice(0, 10)}`;
  const createdAt = reportData.createdAt || new Date().toISOString();

  const record = {
    ...reportData,
    scanId,
    createdAt,
  };

  await ensureReportDir();
  await writeFile(reportPath(scanId), JSON.stringify(record, null, 2), "utf8");

  return record;
}

/**
 * Load a report record by scanId.
 * @param {string} scanId
 * @returns {object|null}
 */
export async function loadReport(scanId) {
  let raw;
  try {
    raw = await readFile(reportPath(scanId), "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Report ${scanId} is corrupted.`);
  }
}

/**
 * List all saved reports.
 * @returns {object[]}
 */
export async function listReports() {
  await ensureReportDir();
  let names;
  try {
    names = await readdir(REPORT_DIR);
  } catch {
    return [];
  }

  const out = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const id = basename(name, ".json");
    if (!REPORT_ID_RE.test(id)) continue;
    try {
      const rep = await loadReport(id);
      if (rep) {
        out.push({
          scanId: rep.scanId,
          createdAt: rep.createdAt,
          score: rep.score,
          riskLevel: rep.riskLevel,
          findingsCount: rep.findings?.length ?? 0,
          toolsInspected: rep.summary?.toolsInspected ?? 0,
        });
      }
    } catch (err) {
      console.error(`[report] skipping ${id}:`, err.message);
    }
  }

  out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return out;
}
