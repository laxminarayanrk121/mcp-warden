// MCP Warden — static source scanning rules (Security Feature B).
//
// Bounded, pattern-based heuristics over JavaScript/TypeScript source text.
// Findings are potential risk indicators, not confirmed vulnerabilities.
// The scanner never executes source and never touches the host filesystem.

export const SOURCE_RULES = [
  {
    id: "SRC-001",
    title: "Dynamic code execution",
    severity: "high",
    confidence: "high",
    description: "Dynamic code evaluation (eval, new Function) can execute untrusted input as code.",
    recommendation: "Avoid eval() and new Function() with any untrusted input.",
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/i,
  },
  {
    id: "SRC-002",
    title: "Process execution",
    severity: "high",
    confidence: "medium",
    description: "Process execution APIs can launch commands with server privileges.",
    recommendation: "Avoid shell execution with untrusted input.",
    pattern: /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/i,
  },
  {
    id: "SRC-003",
    title: "Potential hardcoded secret",
    severity: "high",
    confidence: "medium",
    description: "A credential-like variable assignment may expose a hardcoded secret.",
    recommendation: "Remove hardcoded credentials; use a secret manager or environment configuration.",
    pattern: /(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*["'`][^"'`\r\n]{8,}["'`]/i,
  },
  {
    id: "SRC-004",
    title: "Private key material",
    severity: "critical",
    confidence: "high",
    description: "A private-key header appears in source code.",
    recommendation: "Remove the key from source control and rotate or revoke it.",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  },
  {
    id: "SRC-005",
    title: "Risky filesystem operation",
    severity: "medium",
    confidence: "low",
    description: "File write or deletion operations can damage data.",
    recommendation: "Validate paths and restrict operations to approved directories.",
    pattern: /\b(?:writeFileSync|writeFile|rmSync|rm|unlinkSync|unlink)\s*\(/i,
  },
];

export const NETWORK_PATTERN =
  /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete|request))?|https?\.request|https?\.get|request)\s*\(/i;

export const SECRET_ACCESS_PATTERN =
  /\bprocess\.env\b|\b(?:api[_-]?key|access[_-]?token|password|secret|credential)s?\b/i;
