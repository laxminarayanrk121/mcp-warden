// MCP Warden — static source-scanner rules.
//
// Bounded, pattern-based heuristics over JavaScript/TypeScript source text.
// Rules are intentionally conservative: they flag *potential* risk indicators,
// not confirmed vulnerabilities. Every finding carries an explanation and a
// remediation so the result is actionable rather than noisy.
//
// The scanner never executes the source it inspects. It never touches the
// host filesystem: callers pass file contents in memory, and the path field
// is a caller-supplied relative label used only for reporting.

export const SOURCE_RULES = [
  {
    id: "SRC001",
    title: "Dynamic code execution",
    severity: "high",
    confidence: "high",
    description: "Dynamic code evaluation can execute untrusted input as code.",
    recommendation: "Avoid eval() and new Function() with untrusted input.",
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/i,
  },
  {
    id: "SRC002",
    title: "Process execution",
    severity: "high",
    confidence: "medium",
    description: "Process execution can launch commands with server privileges.",
    recommendation: "Avoid shell execution with untrusted input. Prefer fixed executables and validated arguments.",
    pattern: /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/i,
  },
  {
    id: "SRC003",
    title: "Potential hardcoded secret",
    severity: "high",
    confidence: "medium",
    description: "A credential-like variable may expose a hardcoded secret.",
    recommendation: "Remove hardcoded credentials, rotate exposed secrets, and use environment configuration or a secret manager.",
    pattern: /(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*["'`][^"'`\r\n]{8,}["'`]/i,
  },
  {
    id: "SRC004",
    title: "Private key material",
    severity: "critical",
    confidence: "high",
    description: "A private-key header appears in source code.",
    recommendation: "Remove the key from source control and rotate or revoke it if real.",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  },
  {
    id: "SRC005",
    title: "Risky filesystem operation",
    severity: "medium",
    confidence: "low",
    description: "Filesystem access can expose or modify data when paths or inputs are not appropriately constrained.",
    recommendation: "Validate paths, restrict operations to approved directories, and validate user-controlled inputs.",
    pattern: /\b(?:readFile(?:Sync)?|writeFile(?:Sync)?|appendFile(?:Sync)?|createReadStream|createWriteStream|open(?:Sync)?|readdir(?:Sync)?|access(?:Sync)?|stat(?:Sync)?|lstat(?:Sync)?|mkdir(?:Sync)?|rename(?:Sync)?|copyFile(?:Sync)?|rmdir(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?)\s*\(/i,
  },
  {
    id: "SRC007",
    title: "Network operation",
    severity: "medium",
    confidence: "low",
    description: "Outbound network operations can transmit data to remote systems.",
    recommendation: "Review destinations and data sent over the network, and restrict outbound access where practical.",
    pattern: /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete|request))?|https?\.request|https?\.get|request)\s*\(/i,
  },
  {
    id: "SRC008",
    title: "Potential path traversal",
    severity: "medium",
    confidence: "low",
    description: "A relative traversal sequence or user-controlled path may escape an intended directory.",
    recommendation: "Resolve paths against an approved root, normalize them, and reject paths that escape that root.",
    pattern: /(?:\.\.[\\/]|%2e%2e(?:%2f|%5c)|\bpath\s*\.\s*(?:join|resolve)\s*\([^\n)]*(?:req\.(?:params|query|body)|user(?:Input|Path)|fileName|filename))/i,
  },
  {
    id: "SRC009",
    title: "Environment-variable access",
    severity: "low",
    confidence: "high",
    description: "Environment variables may contain credentials or other sensitive configuration.",
    recommendation: "Avoid logging or transmitting environment values, and expose only the specific variables the application needs.",
    pattern: /\bprocess\s*\.\s*env\b/i,
  },
];

export const NETWORK_PATTERN =
  /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete|request))?|https?\.request|https?\.get|request)\s*\(/i;

export const SECRET_ACCESS_PATTERN =
  /\bprocess\.env\b|\b(?:api[_-]?key|access[_-]?token|password|secret|credential)s?\b/i;
