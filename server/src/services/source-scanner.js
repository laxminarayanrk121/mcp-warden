// MCP Warden — static source scanner (Security Feature B).
//
// Bounded, pattern-based analysis of JavaScript/TypeScript source text.
// The scanner never executes the code it inspects and never touches the host
// filesystem: callers pass file contents in memory, and the `path` field is a
// caller-supplied relative label used only for reporting.
//
// Bounds:
//   - at most 50 files per scan
//   - at most 100,000 characters per file
//   - only .js/.cjs/.mjs/.ts/.tsx/.jsx extensions accepted
//   - no absolute paths, no drive letters, no `..` segments
//
// Findings are potential risk indicators, not confirmed vulnerabilities.

import { extname } from "node:path";
import {
  SOURCE_RULES,
  NETWORK_PATTERN,
  SECRET_ACCESS_PATTERN,
} from "../security/sourceRules.js";

const ALLOWED_EXTENSIONS = new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".tsx",
  ".jsx",
]);

const MAX_FILES = 50;
const MAX_FILE_CHARS = 100_000;

/**
 * Validate the shape and safety of a file list.
 * @param {Array<{path: string, content: string}>} files
 */
export function validateFiles(files) {
  if (!Array.isArray(files)) {
    throw new TypeError("'files' must be an array.");
  }

  if (files.length > MAX_FILES) {
    throw new RangeError(`At most ${MAX_FILES} files are allowed.`);
  }

  for (const file of files) {
    if (!file || typeof file !== "object" || Array.isArray(file)) {
      throw new TypeError("Each file must be an object.");
    }

    if (typeof file.path !== "string" || !file.path.trim()) {
      throw new TypeError("Each file needs a relative path.");
    }

    const normalizedPath = file.path.replace(/\\/g, "/");
    const segments = normalizedPath.split("/");

    if (
      normalizedPath.startsWith("/") ||
      /^[a-z]:/i.test(normalizedPath) ||
      segments.includes("..") ||
      segments.includes("")
    ) {
      throw new TypeError(`Unsafe relative path: ${file.path}`);
    }

    if (!ALLOWED_EXTENSIONS.has(extname(normalizedPath).toLowerCase())) {
      throw new TypeError(`Unsupported source extension: ${file.path}`);
    }

    if (typeof file.content !== "string") {
      throw new TypeError(`Source content must be a string: ${file.path}`);
    }

    if (file.content.length > MAX_FILE_CHARS) {
      throw new RangeError(`Source file is too large: ${file.path}`);
    }
  }
}

/**
 * Redact any credential-like literal from an evidence line before reporting.
 * Never include actual secret values in findings or logs.
 * @param {string} line
 * @returns {string}
 */
export function sanitizeEvidence(line) {
  return line
    .replace(
      /((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*["'`])[^"'`\r\n]*(["'`])/gi,
      "$1[REDACTED]$2"
    )
    .replace(
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi,
      "[REDACTED PRIVATE KEY]"
    )
    .trim()
    .slice(0, 300);
}

function makeFinding(rule, file, lineNumber, sourceLine) {
  return {
    ruleId: rule.id,
    category: "source",
    severity: rule.severity,
    confidence: rule.confidence,
    title: rule.title,
    file,
    line: lineNumber,
    evidence: sanitizeEvidence(sourceLine),
    explanation: rule.description,
    remediation: rule.recommendation,
  };
}

/**
 * Scan in-memory source files for risky patterns.
 * @param {Array<{path: string, content: string}>} files
 * @returns {object}
 */
export function scanSourceFiles(files) {
  validateFiles(files);

  const findings = [];

  for (const file of files) {
    const lines = file.content.split(/\r\n|\n|\r/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];

      for (const rule of SOURCE_RULES) {
        if (rule.pattern.test(line)) {
          findings.push(makeFinding(rule, file.path, index + 1, line));
        }
      }
    }

    // Combination detection: outbound network activity alongside credential or
    // environment-variable access is a stronger indicator than either alone.
    const hasNetwork = NETWORK_PATTERN.test(file.content);
    const hasSecretAccess = SECRET_ACCESS_PATTERN.test(file.content);

    if (hasNetwork && hasSecretAccess) {
      const networkLineIndex = lines.findIndex((line) =>
        NETWORK_PATTERN.test(line)
      );

      if (networkLineIndex !== -1) {
        findings.push({
          ruleId: "SRC006",
          category: "source",
          severity: "high",
          confidence: "low",
          title: "Review possible secret exfiltration",
          file: file.path,
          line: networkLineIndex + 1,
          evidence: sanitizeEvidence(lines[networkLineIndex]),
          explanation:
            "This file contains both outbound network activity and credential or environment-variable references. Review whether sensitive data can leave the server.",
          remediation:
            "Do not transmit secrets to untrusted destinations. Restrict outbound requests and review how credentials are handled.",
        });
      }
    }
  }

  findings.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId)
  );

  const summary = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };

  return {
    filesScanned: files.length,
    findings,
    summary,
  };
}
