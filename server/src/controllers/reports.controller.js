// MCP Warden — reports controller (Security Feature G).
//
// GET /api/reports/        -> list all saved reports
// GET /api/reports/:id     -> get a specific report (JSON)
// GET /api/reports/:id/md  -> get a specific report as Markdown
//
// Reports contain the complete scan result: findings, fingerprint, score,
// baseline comparison, and remediation advice. They are stored as JSON and
// can be rendered as Markdown for easy human consumption.

import { loadReport, listReports, formatReportMarkdown } from "../services/report.service.js";

/**
 * GET /api/reports/
 * Returns a list of all saved reports (metadata only).
 */
export function getReports(_req, res) {
  listReports()
    .then((reports) => {
      res.status(200).json({
        success: true,
        reports,
      });
    })
    .catch((err) => {
      console.error("[reports.controller] list error:", err);
      res.status(500).json({
        success: false,
        error: { code: "INTERNAL_ERROR", message: err.message },
      });
    });
}

/**
 * GET /api/reports/:id
 * Returns the full report JSON for the given scanId.
 */
export function getReportById(req, res) {
  const { id } = req.params;
  if (typeof id !== "string" || !id.trim()) {
    return res.status(400).json({
      success: false,
      error: { code: "INVALID_REQUEST", message: "scanId must be a non-empty string." },
    });
  }

  loadReport(id)
    .then((report) => {
      if (!report) {
        return res.status(404).json({
          success: false,
          error: { code: "NOT_FOUND", message: `Report "${id}" not found.` },
        });
      }
      res.status(200).json({
        success: true,
        report,
      });
    })
    .catch((err) => {
      console.error("[reports.controller] load error:", err);
      res.status(500).json({
        success: false,
        error: { code: "INTERNAL_ERROR", message: err.message },
      });
    });
}

/**
 * GET /api/reports/:id/md
 * Returns the report formatted as Markdown.
 */
export function getReportMarkdown(req, res) {
  const { id } = req.params;
  if (typeof id !== "string" || !id.trim()) {
    return res.status(400).json({
      success: false,
      error: { code: "INVALID_REQUEST", message: "scanId must be a non-empty string." },
    });
  }

  loadReport(id)
    .then((report) => {
      if (!report) {
        return res.status(404).json({
          success: false,
          error: { code: "NOT_FOUND", message: `Report "${id}" not found.` },
        });
      }
      const markdown = formatReportMarkdown(report);
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.status(200).send(markdown);
    })
    .catch((err) => {
      console.error("[reports.controller] markdown error:", err);
      res.status(500).json({
        success: false,
        error: { code: "INTERNAL_ERROR", message: err.message },
      });
    });
}
